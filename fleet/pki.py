#!/usr/bin/env python3
"""Manage the offline certificate authority used by the PRL fleet relay."""
from __future__ import annotations

import argparse
import getpass
from functools import wraps
import ipaddress
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


CLIENT_ID = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
STATE_FILES = ("index.txt", "index.txt.attr", "serial", "crlnumber")


def _exclusive_authority_operation(operation):
    """Serialize authority changes across processes using an atomic mkdir."""
    @wraps(operation)
    def guarded(path, *args, **kwargs):
        authority = Path(path).absolute()
        lock = authority / '.operation-lock'
        try:
            lock.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise RuntimeError('another PKI operation holds .operation-lock; see docs/PKI.md') from exc
        try:
            return operation(path, *args, **kwargs)
        finally:
            lock.rmdir()
    return guarded


def _validate_password(password: str) -> None:
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("CA passphrase must contain at least 12 characters")


def _validate_client_id(client_id: str) -> None:
    if not isinstance(client_id, str) or not CLIENT_ID.fullmatch(client_id):
        raise ValueError("client ID must match [a-z][a-z0-9_-]{0,31}")


def _validate_relay_ip(relay_ip: str | None) -> str | None:
    if relay_ip is None:
        return None
    try:
        return str(ipaddress.IPv4Address(relay_ip))
    except ipaddress.AddressValueError as exc:
        raise ValueError("relay IP must be an IPv4 address") from exc


def _openssl_command(directory: Path, arguments: tuple[str, ...]) -> tuple[list[str], Path | None]:
    executable = shutil.which("openssl")
    if executable:
        return [executable, *arguments], directory
    wsl = shutil.which("wsl")
    if os.name == "nt" and wsl:
        converted = subprocess.run(
            [wsl, "-e", "wslpath", "-a", str(directory)], capture_output=True,
            text=True, check=True,
        ).stdout.strip()
        return [wsl, "--cd", converted, "-e", "openssl", *arguments], None
    raise RuntimeError("OpenSSL was not found in PATH")


def _run_openssl(directory: Path, password: str, *arguments: str) -> None:
    command, cwd = _openssl_command(directory, arguments)
    result = subprocess.run(
        command, cwd=cwd, input=password + "\n", capture_output=True, text=True,
    )
    if result.returncode:
        detail = result.stderr.strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise RuntimeError(f"OpenSSL operation failed{suffix}")


def _config(relay_ip: str | None = None) -> str:
    san = "DNS:relay.prl.internal"
    if relay_ip is not None:
        san += f",IP:{relay_ip}"
    return f"""\
[ ca ]
default_ca = CA_default

[ CA_default ]
database = ./index.txt
new_certs_dir = ./newcerts
certificate = ./ca.crt
private_key = ./ca.key
serial = ./serial
crlnumber = ./crlnumber
default_md = sha256
default_days = 825
default_crl_days = 30
policy = policy_cn
unique_subject = yes
copy_extensions = none

[ policy_cn ]
commonName = supplied

[ server_cert ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = {san}

[ client_cert ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
"""


def _write_text(path: Path, content: str, mode: int = 0o600) -> None:
    path.write_text(content, encoding="ascii", newline="\n")
    path.chmod(mode)


def _combine_pem(key: Path, certificate: Path, output: Path) -> None:
    output.write_bytes(key.read_bytes() + certificate.read_bytes())
    output.chmod(0o600)


def _stage(parent: Path) -> Path:
    parent.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=".prl-pki-", dir=parent))


def _copy_authority(path: Path, stage: Path) -> None:
    required = ("ca.key", "ca.crt", *STATE_FILES)
    missing = [name for name in required if not (path / name).is_file()]
    if missing:
        raise ValueError(f"invalid PKI directory; missing {missing[0]}")
    for name in required:
        shutil.copyfile(path / name, stage / name)
    (stage / "newcerts").mkdir()
    _write_text(stage / "openssl.cnf", _config())


def _replace_files(path: Path, stage: Path, names: tuple[str, ...]) -> None:
    """Replace a small file set and restore all originals on an OS error."""
    originals = {name: (path / name).read_bytes() for name in names
                 if (path / name).exists()}
    created = [name for name in names if name not in originals]
    try:
        for name in names:
            os.replace(stage / name, path / name)
    except OSError:
        for name, content in originals.items():
            (path / name).write_bytes(content)
        for name in created:
            try:
                (path / name).unlink()
            except FileNotFoundError:
                pass
        raise


def init_pki(path: str | os.PathLike[str], password: str,
             relay_ip: str | None = None) -> Path:
    """Create a new encrypted offline CA and relay server certificate."""
    _validate_password(password)
    relay_ip = _validate_relay_ip(relay_ip)
    destination = Path(path).absolute()
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"PKI path already exists: {destination}")

    stage = _stage(destination.parent)
    try:
        (stage / "newcerts").mkdir()
        (stage / "clients").mkdir(mode=0o700)
        _write_text(stage / "index.txt", "")
        _write_text(stage / "index.txt.attr", "unique_subject = yes\n")
        _write_text(stage / "serial", "1000\n")
        _write_text(stage / "crlnumber", "1000\n")
        _write_text(stage / "openssl.cnf", _config(relay_ip))

        _run_openssl(
            stage, password, "genpkey", "-algorithm", "EC", "-pkeyopt",
            "ec_paramgen_curve:P-256", "-aes-256-cbc", "-pass", "stdin",
            "-out", "ca.key",
        )
        (stage / "ca.key").chmod(0o600)
        _run_openssl(
            stage, password, "req", "-new", "-x509", "-sha256", "-days", "3650",
            "-key", "ca.key", "-passin", "stdin",
            "-subj", "/CN=PRL Fleet Offline CA", "-addext",
            "basicConstraints=critical,CA:true,pathlen:0", "-addext",
            "keyUsage=critical,keyCertSign,cRLSign", "-addext",
            "subjectKeyIdentifier=hash", "-out", "ca.crt",
        )
        _run_openssl(
            stage, password, "genpkey", "-algorithm", "EC", "-pkeyopt",
            "ec_paramgen_curve:P-256", "-out", "server.key",
        )
        _run_openssl(
            stage, password, "req", "-new", "-sha256", "-key", "server.key",
            "-subj", "/CN=relay.prl.internal", "-out", "server.csr",
        )
        _run_openssl(
            stage, password, "ca", "-batch", "-config", "openssl.cnf",
            "-extensions", "server_cert", "-in", "server.csr", "-out",
            "server.crt", "-passin", "stdin", "-notext",
        )
        _combine_pem(stage / "server.key", stage / "server.crt",
                     stage / "server.pem")
        _run_openssl(
            stage, password, "ca", "-batch", "-config", "openssl.cnf",
            "-gencrl", "-out", "crl.pem", "-passin", "stdin",
        )

        for temporary in ("server.key", "server.csr", "server.crt", "openssl.cnf"):
            (stage / temporary).unlink()
        shutil.rmtree(stage / "newcerts")
        (stage / "ca.crt").chmod(0o644)
        (stage / "crl.pem").chmod(0o644)
        stage.rename(destination)
        return destination
    finally:
        if stage.exists():
            shutil.rmtree(stage)


@_exclusive_authority_operation
def issue_client(path: str | os.PathLike[str], client_id: str,
                 password: str) -> Path:
    """Issue one unencrypted P-256 client key and certificate PEM."""
    _validate_password(password)
    _validate_client_id(client_id)
    authority = Path(path).absolute()
    target = authority / "clients" / f"{client_id}.pem"
    if target.exists() or target.is_symlink():
        raise FileExistsError(f"client certificate already exists: {client_id}")

    stage = _stage(authority.parent)
    try:
        _copy_authority(authority, stage)
        _run_openssl(
            stage, password, "genpkey", "-algorithm", "EC", "-pkeyopt",
            "ec_paramgen_curve:P-256", "-out", "client.key",
        )
        _run_openssl(
            stage, password, "req", "-new", "-sha256", "-key", "client.key",
            "-subj", f"/CN={client_id}", "-out", "client.csr",
        )
        _run_openssl(
            stage, password, "ca", "-batch", "-config", "openssl.cnf",
            "-extensions", "client_cert", "-in", "client.csr", "-out",
            "client.crt", "-passin", "stdin", "-notext",
        )
        _combine_pem(stage / "client.key", stage / "client.crt",
                     stage / "client.pem")
        target.parent.mkdir(mode=0o700, exist_ok=True)
        os.replace(stage / "client.pem", target)
        try:
            _replace_files(authority, stage, ("index.txt", "index.txt.attr", "serial"))
        except OSError:
            target.unlink(missing_ok=True)
            raise
        target.chmod(0o600)
        return target
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def _certificate_status(index: Path, client_id: str) -> str | None:
    suffix = f"/CN={client_id}"
    for line in index.read_text(encoding="ascii").splitlines():
        fields = line.split("\t")
        if len(fields) >= 6 and fields[5].endswith(suffix):
            return fields[0]
    return None


@_exclusive_authority_operation
def revoke_client(path: str | os.PathLike[str], client_id: str,
                  password: str) -> Path:
    """Revoke an issued client certificate and atomically publish a new CRL."""
    _validate_password(password)
    _validate_client_id(client_id)
    authority = Path(path).absolute()
    certificate = authority / "clients" / f"{client_id}.pem"
    if not certificate.is_file():
        raise FileNotFoundError(f"client certificate does not exist: {client_id}")
    status = _certificate_status(authority / "index.txt", client_id)
    if status == "R":
        raise ValueError(f"client certificate is already revoked: {client_id}")
    if status != "V":
        raise ValueError(f"client certificate is not active: {client_id}")

    stage = _stage(authority.parent)
    try:
        _copy_authority(authority, stage)
        shutil.copyfile(certificate, stage / "client.pem")
        _run_openssl(
            stage, password, "ca", "-batch", "-config", "openssl.cnf",
            "-revoke", "client.pem", "-passin", "stdin",
        )
        _run_openssl(
            stage, password, "ca", "-batch", "-config", "openssl.cnf",
            "-gencrl", "-out", "crl.pem", "-passin", "stdin",
        )
        (stage / "crl.pem").chmod(0o644)
        _replace_files(
            authority, stage,
            ("index.txt", "index.txt.attr", "serial", "crlnumber", "crl.pem"),
        )
        return authority / "crl.pem"
    finally:
        if stage.exists():
            shutil.rmtree(stage)


@_exclusive_authority_operation
def refresh_crl(path: str | os.PathLike[str], password: str) -> Path:
    """Renew the signed CRL without changing any certificate's status."""
    _validate_password(password)
    authority = Path(path).absolute()
    stage = _stage(authority.parent)
    try:
        _copy_authority(authority, stage)
        _run_openssl(
            stage, password, "ca", "-batch", "-config", "openssl.cnf",
            "-gencrl", "-out", "crl.pem", "-passin", "stdin",
        )
        (stage / "crl.pem").chmod(0o644)
        _replace_files(authority, stage, ("crlnumber", "crl.pem"))
        return authority / "crl.pem"
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def _passphrase() -> str:
    value = os.environ.get("PRL_CA_PASSPHRASE")
    if value is not None:
        return value
    return getpass.getpass("CA passphrase: ")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("init", help="create a new offline PKI")
    initialize.add_argument("path", type=Path)
    initialize.add_argument("--relay-ip", help="add an IPv4 SAN to the relay cert")
    issue = commands.add_parser("issue", help="issue a client certificate")
    issue.add_argument("path", type=Path)
    issue.add_argument("client_id")
    revoke = commands.add_parser("revoke", help="revoke a client certificate")
    revoke.add_argument("path", type=Path)
    revoke.add_argument("client_id")
    refresh = commands.add_parser("refresh-crl", help="renew CRL before its 30-day expiry")
    refresh.add_argument("path", type=Path)
    args = parser.parse_args(argv)

    try:
        password = _passphrase()
        if args.command == "init":
            result = init_pki(args.path, password, relay_ip=args.relay_ip)
            print(f"PKI created: {result}")
        elif args.command == "issue":
            result = issue_client(args.path, args.client_id, password)
            print(f"Client certificate created: {result}")
        elif args.command == "revoke":
            result = revoke_client(args.path, args.client_id, password)
            print(f"CRL updated: {result}")
        else:
            result = refresh_crl(args.path, password)
            print(f"CRL renewed: {result}")
    except (ValueError, FileExistsError, FileNotFoundError, RuntimeError, OSError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
