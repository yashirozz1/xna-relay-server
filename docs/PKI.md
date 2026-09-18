# Offline fleet PKI

The fleet PKI gives every relay client its own mTLS identity. Run all CA
operations on an offline Linux machine in a private directory. The implementation
uses the system `openssl` command and Python's standard library; it has no Python
package dependency.

## Create the authority

Run the CLI without a password argument so the passphrase is hidden by `getpass`:

```sh
python3 -m fleet.pki init /secure/prl-pki --relay-ip 203.0.113.10
```

`--relay-ip` is optional. The relay certificate always contains the DNS SAN
`relay.prl.internal`; when supplied, the validated IPv4 address is added as an IP
SAN. CA, relay, and client keys use ECDSA P-256. The CA certificate is valid for
ten years, while issued relay and client certificates are valid for 825 days.

For non-interactive operation, set `PRL_CA_PASSPHRASE` in the process environment
and remove it immediately afterwards. The passphrase must contain at least 12
characters. It is never printed or passed to OpenSSL as a command-line argument.

```sh
read -r -s PRL_CA_PASSPHRASE
export PRL_CA_PASSPHRASE
python3 -m fleet.pki init /secure/prl-pki --relay-ip 203.0.113.10
unset PRL_CA_PASSPHRASE
```

Initialization refuses an existing path and builds in a sibling temporary
directory, so a failed OpenSSL operation does not replace existing data.

## Issue and revoke clients

Client IDs must match `[a-z][a-z0-9_-]{0,31}`. Issuing an existing ID is refused.
There is no built-in 256-client limit; the CA workflow supports the deployment's
planned 1,024 identities.

```sh
python3 -m fleet.pki issue /secure/prl-pki gpu01
python3 -m fleet.pki issue /secure/prl-pki monitor-panel
python3 -m fleet.pki revoke /secure/prl-pki gpu01
```

`monitor-panel` is a valid management certificate identity. The fleet manifest
and relay generator must keep that reserved ID out of mining backends.

Revocation keeps the client's PEM for audit and recovery purposes, marks its
certificate revoked in the OpenSSL index, and publishes a newly signed `crl.pem`.
Copy the updated CRL to the relay after every revocation. A second revocation of
the same certificate is refused.

CRLs expire after 30 days. Renew before expiry even if no clients were revoked:

```sh
python3 -m fleet.pki refresh-crl /secure/prl-pki
```

This preserves revocations, signs a new CRL and advances its serial number. Copy
the renewed file to `/etc/prl-fleet/crl.pem` (root:prl-fleet, 0640), validate the
HAProxy configuration and restart `prl-fleet`. Restarting disconnects established
sessions too; clients reconnect briefly. Without the automatic enrollment setup,
schedule this offline renewal in your operational calendar. The setup described
in [AUTOMATIC-MINING.md](AUTOMATIC-MINING.md) installs a daily renewal timer.

Issuance, revocation and CRL renewal use the same authority lock. A concurrent
operation is refused before reading or changing authority state. On Linux, the
kernel releases the directory lock if the process exits or is killed. Use the
current tooling for all concurrent operations; older releases use a different
locking mechanism. On Windows or with old tooling, `.operation-lock` can remain
after forced termination. Confirm no PKI process is active before removing that
empty legacy directory with `rmdir`. Never remove an active operation's lock.

The Python API exposes the same operations:

```python
from fleet.pki import init_pki, issue_client, revoke_client, refresh_crl

init_pki("/secure/prl-pki", password, relay_ip="203.0.113.10")
issue_client("/secure/prl-pki", "gpu01", password)
revoke_client("/secure/prl-pki", "gpu01", password)
refresh_crl("/secure/prl-pki", password)
```

## Files and deployment boundary

Keep the complete PKI directory offline and back it up securely. Its files are:

| File | Purpose | Deployment |
|---|---|---|
| `ca.key` | Encrypted CA private key | Never deploy |
| `ca.crt` | Public trust anchor | Relay and clients |
| `server.pem` | Relay private key and server certificate | Relay only |
| `clients/ID.pem` | Unencrypted client key and client certificate | That client only |
| `crl.pem` | Signed certificate revocation list | Relay |
| `index.txt`, `serial`, `crlnumber` and attributes | OpenSSL issuance/revocation state | Never deploy |

The relay bundle may contain only `ca.crt`, `crl.pem`, and `server.pem`. A client
bundle may contain only its own `clients/ID.pem` and the public CA certificate.
Never copy `ca.key` or the OpenSSL state files into a relay or client bundle.

Private PEM files are requested as mode `0600`, and private directories as
`0700`. Windows filesystems and WSL mounts may not enforce POSIX modes even when
`chmod` succeeds. Perform production CA operations on Linux in a directory owned
by the PKI operator, with a restrictive umask, full-disk protection, and backups
whose access is equally restricted.

## Verification

These commands verify the intended certificate purposes and revocation state:

```sh
openssl verify -CAfile /secure/prl-pki/ca.crt \
  -purpose sslserver /secure/prl-pki/server.pem
openssl verify -CAfile /secure/prl-pki/ca.crt \
  -purpose sslclient /secure/prl-pki/clients/gpu01.pem
openssl verify -CAfile /secure/prl-pki/ca.crt \
  -CRLfile /secure/prl-pki/crl.pem -crl_check \
  /secure/prl-pki/clients/gpu01.pem
```

The last command fails with `certificate revoked` after `gpu01` is revoked.
