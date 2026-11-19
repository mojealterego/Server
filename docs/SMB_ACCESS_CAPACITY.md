# STORAGE-04 — SMB access, auditing and volume capacity guard

## Model-only identity

Run the updated preparation command before rebuilding the existing service:

    sudo python3 tools/smbctl.py prepare
    sudo python3 tools/smbctl.py up
    sudo python3 tools/smbctl.py probe

The original compat and secure credentials are preserved. A third independent
256-bit password is generated for omega-model-reader in
vps/smb-secrets/models_password (0600). This account can access only the
encrypted omega-models share and cannot write to it. The original secure
account retains backward-compatible model access. The model share is
read-only at both Samba and container mount layers, and maps admitted model
users to the existing filesystem owner for read access. The worker no
longer needs a credential for the writable secure share to stage models.
SMB1 remains disabled; SMB2 signing and SMB3 encryption policies remain.

The native SMB probe now includes successful model-only listing and negative
access/write tests. Live probe execution is required on a provisioned VPS.
This is share-level authorization with fixed accounts; arbitrary user CRUD,
per-file NT ACL management and ACL backup/restore are not implemented.

## Dedicated filesystem capacity mode

Existing deployment without capacity mode still works on a shared filesystem.
For a hard per-share capacity boundary, provision three separate local ext4
or XFS filesystems on the VPS at the existing share directories:

- vps/smb-data/compat
- vps/smb-data/secure
- vps/smb-models

Do not format or remount a live data disk blindly. Preserve and verify a
backup, stop the SMB service and all other writers, and migrate contents and
ownership in a planned operation. Each share must be the root of its own
filesystem, without nested mounts, and retain the ownership/modes described
in SMB_STORAGE.md. The operator owns filesystem provisioning and the actual
volume sizes. The software does not create, resize or format volumes.

Example caps (MiB; choose values for the actual provisioned disks):

    sudo python3 tools/smbctl.py volume-check --volume-limits 10240,51200,102400
    sudo python3 tools/smbctl.py up --volume-limits 10240,51200,102400

The validation uses mountinfo, distinct filesystem device IDs and statvfs
total filesystem capacity. A plain directory, oversized capacity, nested
mount, non-root bind, unexpected filesystem or shared device fails closed.
Configured limits are stored in a private 0600 policy file under smb-secrets.
A later smbctl up without a limit argument reads the stored policy. An
inconsistent requested policy is refused. The host validates before the
Compose up and the container repeats the volume validation on startup.
For status use sudo python3 tools/smbctl.py volume-check. On storage changes
stop the service and use a planned root-admin offline reconfiguration;
never delete the policy just to bypass capacity checks. Use the wrapper
rather than raw Docker Compose. Root-controlled mounts and configuration
are trusted. This is a per-volume capacity boundary (kernel filesystem
capacity), not a per-user byte quota or continuous online resizing guard.
No physical mount or full-volume write test has been run here.

## Audit

Samba's native full_audit module is configured for authentication logs and
selected connection, open, write, truncate, rename and delete events, plus
VFS failures. Logging includes original client username, IP and share;
the full_audit debug class is enabled at level 1 with syslog disabled so
records go to the Samba log stream. The Docker json-file rotation remains
bounded (three 10 MiB files). Audit logs may contain sensitive filenames
and IP addresses; restrict operator access and arrange secure external
collection if long retention or tamper evidence is required.

    sudo docker compose -f vps/compose.yaml -f vps/compose.smb.yaml \
      --profile smb logs --tail 200 smb

After a live smbctl probe, inspect the disposable omega-probe file events
and compare negotiated dialect and authorization outcomes. No log format,
emission, end-to-end SMB handshake, filesystem ENOSPC behavior or container
build has been validated on a physical server in this increment. SMB3
multichannel and durable handles require a separate network qualification.
References: Samba smb.conf(5), Debian trixie vfs_full_audit(8).

## Evidence

6 new storage tests and 11 existing SMB tests passed locally. They check
the account/config policy, independent secret provisioning, stored limit
rejection, volume capacity checks with simulated mount/device values, plain
directory rejection and the expanded client probe with a controlled
smbclient substitute. Python compilation, shell syntax and YAML parsing
passed. Samba/Docker and real client/volume qualification remain NOT_RUN.
