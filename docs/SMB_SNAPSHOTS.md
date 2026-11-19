# STORAGE-03 — versioned SMB content snapshots

This is a logical quiesced snapshot of share contents into a dedicated
private on-disk CAS, not a live Samba filesystem snapshot or a backup of
ACLs, timestamps, ownership, Samba passdb or open handles. Original
SMB2/SMB3 service configuration and model cache are unchanged.

## Create a snapshot on the VPS

Choose a private local filesystem supporting fsync, hard links and (for
restore) Linux renameat2 RENAME_NOREPLACE. Keep the snapshot vault separate
from both live shares and compute CAS. Stop SMB using smbctl and stop
all other writers, including model-publisher jobs, before capture.
The operator is responsible for actual quiescence; the module does not
stop or start services automatically.

    sudo python3 tools/smbctl.py stop
    sudo install -d -m 0700 /var/lib/omega-storage
    sudo python3 -m atlas.storage_snapshot --vault /var/lib/omega-storage/cas \
      create --share omega-secure --confirm-quiesced

The CLI supports precisely omega-compat, omega-secure and omega-models,
maps them to their fixed VPS paths, and does not back up smb-secrets or
internal database paths. Never put sensitive service internals into a
share. The result contains snapshot sha256 and manifest_sha256. Save both
in a trusted independent, access-controlled receipt store. The SHA pin is
the version identity; identical content has the same version, changed
contents produce a different hash. There is no automatic retention or GC.

The snapshot preserves directory structure, empty directories, zero-length
files and all file bytes. It rejects symlinks, hardlinks, special files,
path traversal and oversized entries; verifies inventory and hashes again
before index publication. This does not provide a consistent capture
against a malicious or continually changing local writer. Limits:
16 GiB per file, 256 GiB aggregate, 4096 entries (including directories),
1 MiB canonical JSON index. Files larger than 16 GiB require a future
chunked-object extension or separate backup route. Insufficient disk space
causes failure; failed captures may leave unreachable CAS objects.

## Replicate and retrieve

Configure independent Rclone crypt remotes (not ordinary SMB remotes).
For CLI export/retrieval the configuration is checked for type=crypt and
distinct aliases; the operator must ensure each has real encryption,
trusted credentials and separate failure domains. The CLI reads the
configuration internally and does not output its contents. An alias
does not establish physical independence. Export is explicit.

    sudo python3 -m atlas.storage_snapshot --vault /var/lib/omega-storage/cas \
      push "$SNAPSHOT_SHA" --remote backup1:omega-smb-snapshots \
      --remote backup2:omega-smb-snapshots --allow-export

The existing CAS replication implementation reuses blocks and verifies
each uploaded object. On each replica the version index is published
only after its referenced objects. The index pins every object's Merkle
manifest hash and full content digest. Failed pushes may leave blocks
or complete previous replicas. Run the command again to verify and resume.
Remote providers are not inherently immutable. A snapshot receipt is
content integrity, not an independent signature; trust the expected
pins through the operator's authenticated channel.

Retrieve on a separate trusted Linux host:

    sudo python3 -m atlas.storage_snapshot --vault /var/lib/omega-storage/cas \
      pull "$SNAPSHOT_SHA" --manifest-sha256 "$SNAPSHOT_MANIFEST_SHA" \
      --remote backup1:omega-smb-snapshots --remote backup2:omega-smb-snapshots

Remote blocks are checked by length and SHA; the first available valid
replica supplies each block. An incomplete pull may leave a locally
cached index or partial objects but does not claim verified retrieval.

## Restore drill

    sudo python3 -m atlas.storage_snapshot --vault /var/lib/omega-storage/cas \
      restore "$SNAPSHOT_SHA" --dest /var/lib/omega-storage/recovered

The destination must not exist; its parent must be private. Restore creates
an isolated temporary tree, validates each restored object and publishes the
completed directory using atomic no-overwrite rename. Contents are not
automatically swapped into a live share. Apply the intended share ownership
and ACLs separately, verify permissions and restore into the intended
operational location during planned downtime. Start Samba only after
inspection. Restoration is file-content level; metadata/ACL/NTFS
semantics, online snapshots, previous-versions integration, scheduled
retention and RTO/RPO benchmarks remain open.

## Evidence

9 new snapshot tests passed using real ArtifactStore, Merkle replication
logic and atomic Linux directory publication with in-memory replica
substitutes. Coverage: versions, deduplication, empty directories,
corrupt object rejection, traversal, remote loss/failover, hash pins,
encrypted remote config and credential error redaction. Earlier SMB
service qualification is still NOT_RUN on real clients. No Rclone,
Samba or provider integration test in this increment.
