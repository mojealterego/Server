# STORAGE-05 — pinned three-share recovery sets

The existing SMB2 signed and SMB3 encrypted shares retain their distinct
access policies. This module coordinates recovery of omega-compat,
omega-secure and omega-models as one pinned generation. It reuses
the existing snapshot CAS and authenticated operator-configured
crypt replicas, without treating a version on a surviving replica as
the latest merely because that replica is online.

## Capture and export

Stop SMB and all other writers to all three shares before capture.
Use a private dedicated snapshot vault outside the live shares and
compute CAS. Capture invokes the existing checked snapshot builder
for each fixed share. It only emits a recovery-set receipt after all
three snapshots are created.

    umask 077
    python3 -m atlas.storage_recovery --vault /private/storage-cas \
      capture --confirm-quiesced > recovery-set.json

Retain the returned set SHA-256 separately, as an authenticated
operator-controlled version pin. The receipt can be passed directly
to later commands. All three index digests and Merkle pins must match.
Use the same pinned receipt on a standby. Quiescence across all shares
is an operator requirement, not a distributed write freeze.

    python3 -m atlas.storage_recovery --vault /private/storage-cas \
      push --set recovery-set.json --sha256 "$TRUSTED_SET_PIN" \
      --remote backup1:omega --remote backup2:omega --allow-export

Export verifies share identity and local index pins first, and uses the
existing read-back checked replication on each remote. Remotes must
be configured as Rclone crypt. Distinct alias names do not establish
physical independence. A failed export may leave verified reusable
blocks or individual share versions; there is no remote atomic commit
of the set. Retain the receipt independently even when a remote fails.

## Restore

    python3 -m atlas.storage_recovery --vault /private/recovery-cas \
      restore --set recovery-set.json --sha256 "$TRUSTED_SET_PIN" \
      --remote backup1:omega --remote backup2:omega --dest /private/recovered

The restore path authenticates the set pin before accessing replicas,
retrieves each matching snapshot using block-level verified replica
failover, and checks that the snapshot belongs to the expected share.
A missing current generation does not trigger silent fallback to an
older version. All three directories are constructed in private staging
and atomically published together in a new destination. Failures can
leave verified CAS entries for retry, but no partial final share tree.
The files and empty directories are restored; no ACL, timestamps,
ownership, passdb, durable handles or active SMB sessions are cloned.

The recovered directory is not a live SMB endpoint. To promote a
standby, fence the previous SMB writer, confirm the chosen generation
and RPO, provision the standby's dedicated filesystem volumes,
credentials, ownership, ACLs and read-only model policy using the
existing SMB setup, and copy the verified tree into the intended
offline share locations. Verify the copy and smbctl probe before
allowing clients to reconnect. This module does not format volumes,
swap mounted filesystems or automatically redirect clients.

## Evidence

9 focused storage recovery tests passed, including actual upstream
snapshot/CAS/Merkle/replication code, a simulated failure of one and
both replicas, actual file publication, and a capture/push/restore CLI
test using subprocess Rclone emulation. Independent replica endpoints
are emulated; no actual Rclone provider, Samba negotiation, SMB
transparent failover, physical mount or cross-host test was performed.
