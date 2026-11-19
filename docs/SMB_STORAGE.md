# OMEGA STORAGE — SMB2/SMB3 v1.0 development

The storage track is a permanent peer of the OMEGA-X compute track.
This release introduces an opt-in native Samba service for a rootful Linux
Docker VPS. It does not impersonate a Samba implementation in Python.
The existing FTPS, SFTP, WebDAV, CAS and Rclone services remain independent.

## Shares and trust boundaries

| Share | Account | Host directory | Dialect and protection |
| --- | --- | --- | --- |
| omega-compat | omega-compat | vps/smb-data/compat | SMB 2.0.2–3.1.1, mandatory signing; encryption not required |
| omega-secure | omega-secure | vps/smb-data/secure | SMB3, mandatory encryption |
| omega-models | omega-secure | vps/smb-models | SMB3, mandatory encryption, read-only |

SMB1, NetBIOS transport, guest access, weak NTLMv1 and symlink following
are disabled. SMB2 signing protects integrity but does not provide content
confidentiality: use the compatibility share only in an isolated private
network/VPN. Prefer the encrypted share for nonpublic assets. The two
accounts have separate random 256-bit passwords and UNIX IDs 10002/10003.
The model share is mounted read-only in Docker as well as in Samba.
The server does not expose the project's internal CAS, DBs or credentials.
Only explicitly staged data belongs on a network share. Do not bind an
existing private CAS root or a secrets directory into this service.

## VPS setup

Use a trusted checkout on a local Linux filesystem, with rootful Docker
and Compose supporting bind.create_host_path=false, and install smbclient
from the host distribution for acceptance testing. The image uses the
Debian trixie-slim distribution's Samba packages; the base image and
packages are not digest-pinned. Build/update using a trusted registry
and patched packages. The container uses Docker's default capabilities
with no-new-privileges, PID/memory limits and bounded logs.

From the repository root on the VPS, not Android:

    sudo python3 tools/smbctl.py prepare
    sudo python3 tools/smbctl.py up
    sudo python3 tools/smbctl.py probe

The default bind is 127.0.0.1:445, forwarded to container port 1445.
The probe requires smbclient with --client-protection and --use-kerberos.
It creates only small random disposable files, reads them back and removes
them. It tests signed SMB2.1 and encrypted SMB3.1.1, encrypted model listing,
and rejection of SMB2 on the secure share, a wrong account, model writing
and an SMB1 request. Failure or inconclusive evidence is never a pass.
A client-side SMB1 rejection may also occur; packet capture and server
dialect logs are required to independently prove server negotiation.
If the probe is interrupted, inspect any omega-probe-* files before cleanup.

For remote access, set SMB_PRIVATE_IP to an actual assigned RFC1918 or
CGNAT/VPN address, not a public address, and configure the firewall/VPN
to allow only enrolled clients. Never forward TCP 445 from the Internet.

    sudo python3 tools/smbctl.py up --bind "$SMB_PRIVATE_IP" --allow-network
    sudo python3 tools/smbctl.py probe --bind "$SMB_PRIVATE_IP" --allow-network

Use --port 1445 for a nonstandard-port lab if 445 is occupied; many native
SMB clients assume 445. Stop only the SMB service with smbctl.py stop.
Use the wrapper rather than raw Compose: it rejects public/wildcard binds.
Direct modification of Compose or root-level configuration bypasses that
guard; this is not a security boundary against the host operator.

Preparation never silently overwrites passwords or chmods/chowns existing
directories; it refuses unsafe ownership, modes or symlinks. The passwords
are generated under vps/smb-secrets, root-only 0600. Retrieve them locally
as administrator for client enrollment; do not paste them in chat, commit
them, or use command-line password arguments. The two credential files are
the persistent source of account passwords; Samba rebuilds its accounts
on container start. Rotation is manual: stop service, securely replace the
appropriate file with a new random 64-hex-character line, restart and
re-enroll clients. Back up credentials separately, encrypted.

## Android / Termux network drives

On S24 Ultra no root or kernel CIFS mount is assumed. Use Samsung My Files
network storage or an SMB client that negotiates the required protocol and
connects to the VPS private address. Prefer SMB3 or VPN. The client must use
the share's corresponding user; a client lacking SMB3 encryption must not
be granted the secure share. Rclone provides a user-space file interface,
not a kernel drive mount. The Android device remains capable of using its
existing local GGUF directory and existing SFTP/WebDAV server.

    pkg install rclone
    rclone config

Create a named remote omega-smb with storage type smb, the actual VPS private
IP, port 445 (or configured port), user omega-secure and its password entered
interactively. Keep the Rclone config private. Do not assume every Rclone
build supports the encryption policy: verify access, otherwise use a proven
SMB3 client or another private transport, never disable server encryption.

    rclone lsf omega-smb:omega-secure
    rclone lsf omega-smb:omega-models

The existing CAS replication client accepts configured Rclone remote paths,
including omega-smb:omega-secure/replicas. Follow docs/REPLICATION.md for
explicit export authorization and pinned SHA-256 manifests. The existing
ATLAS remote staging commands support configured Rclone sources; do not
point inference mmap directly at a network path. Verify model bytes locally.
SMB transport encryption is not encryption at rest; use independently
configured encrypted backups where required. No automatic replication of
local_only data is authorized.

## Development evidence

11 focused host unit tests passed on Linux/Python 3.13. They covered actual
local directory and credential preparation, symlink refusal, bind policy,
static share/Compose layout, and the acceptance probe with a controlled
smbclient process substitute. Shell syntax, Python compilation, and YAML
parse passed. Samba, Docker and smbclient are absent from the test runner;
image build, real dialect negotiation, real encrypted transfer, Windows
and Android interoperability, throughput and hardware deployment are NOT_RUN.
Full upstream repository regression and packaging remain unverified here.

## Parallel storage roadmap

- STORAGE-01: native SMB2/SMB3 service, separate accounts and shares,
  explicit private bind and live acceptance probe — implemented, runtime gate open.
- STORAGE-02: mobile client integration, local verified model cache and
  signed storage inventory; test actual S24/Windows/Linux clients.
- STORAGE-03: versioned snapshots, encrypted replication with CAS and
  existing Rclone mirrors, bounded resume, retention and restore drills.
- STORAGE-04: per-user ACLs, quotas, audit, credential lifecycle, throughput
  benchmarks, SMB3 multichannel/leases/durable handles qualification.
- STORAGE-05: independent storage failure-domain failover, backup verification,
  resource coordination with AI workers; no claims of transparent HA or
  distributed locking until tested.

Compute scheduler v5.1, adaptive failover and HA remain separate active
work items; none is marked closed by this storage increment.
