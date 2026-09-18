# Azure PRL + XMR bootstrap implementation plan

**Goal:** Generate a private cloud-init file per existing client certificate, usable with Azure CLI, that starts GPU PRL and CPU XMR through the authenticated Contabo relay.

**Architecture:** A Python stdlib generator packages one client identity with a pinned, resumable Ubuntu installer. cloud-init installs a bootstrap service with retry on failure; the installer verifies hardware and artifacts, creates clearly named systemd services, and configures scoped PRL forwarding and XMR TLS-over-mTLS. No CA private key or SSH password is distributed. The relay gains an opt-in XMR destination within each existing per-client backend, retaining aggregated traffic counters.

**Platform:** Ubuntu 24.04 x86_64, systemd, NVIDIA driver already installed (same image as the working H100 VM). KRig 1.5.1 and Alfa 6.26.0 zero-fee artifacts are pinned by URL and SHA256. Azure machines are created by the user's automation; this task does not create billable resources.

## Task 1: Installer and repeatable startup
- [ ] Implement `dual/install.py` with strict manifest/certificate/hardware validation, download checksum checks, safe extraction, service ownership tracking, resumability after interruption, dedicated non-root accounts, local metrics and explicit CPU/GPU mining service names.
- [ ] Reserve CPU capacity per NUMA node, configure huge pages without reducing existing reservations, and leave GPU tuning unchanged.
- [ ] Create local PRL mTLS listener 8048 and XMR listeners 17029/17429; scope TCP redirection to the PRL account only and retain real pool DNS/TLS validation.
- [ ] Test CPU selection, input rejection, archive path validation, checksum mismatch and resume identity guards in `tests/test_dual_install.py`.

## Task 2: Per-VM package and Azure CLI integration
- [ ] Write failing tests in `tests/test_dual_bundle.py` for recipient isolation, cloud-config decoding, 64 KiB size ceiling, invalid IDs and refusal to overwrite output.
- [ ] Implement `dual_bundle.py --fleet-dir ... --instance-id ... --account ... --output ...` and `--all`; verify certificates and key pairing before copying only the chosen identity.
- [ ] Emit private JSON-form cloud-config with compressed write_files and a restartable bootstrap unit; no public credential hosting.
- [ ] Document `az vm create --custom-data FILE`, one identity per VM, boot status, retries, stop/start and driver requirements in `docs/AZURE-DUAL.md` and link from README.

## Task 3: Relay routing, validation and delivery
- [ ] Add optional `xmr_pool_host`/`xmr_pool_port` manifest fields and opt-in `use-server xmr` with weight zero in each client backend; ensure existing PRL-only manifests remain unchanged.
- [ ] Test routing isolation and generated HAProxy configuration using existing Linux tooling, plus generated cloud-init schema and shell/systemd validation where available.
- [ ] Obtain independent code review; fix important findings.
- [ ] Generate cloud-init for available IDs on the private Contabo storage; enable XMR routing for those IDs with backup and config validation, then confirm existing PRL/XMR mining resumes.
- [ ] Publish only source/docs/tests to the existing relay repository, keeping private outputs ignored. Report verification limits: no fresh Azure VM was created.
