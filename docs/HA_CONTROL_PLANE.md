# v5.4a — coordinator availability and recovery

## Same-host active/standby

The production dispatch CLI now acquires a private, persistent flock on
the local lease database's authority-lock file before creating its coordinator.
A second process with the same database fails closed by default. With
--standby-wait 1..3600 it waits for the authority to become available.
Use the existing dispatch serve invocation and add --standby-wait 3600
to a separately supervised standby. Both processes must use identical
database, replay database, staging, CAS, plan, enrollment and network
configuration. Do not delete or rename the lock or database while in use.
The new CLI's graceful shutdown drains handler threads before releasing
the authority. After process death the kernel releases the lock. In-flight
worker leases remain governed by the existing lease epochs and expiry.

All DB paths and locks must be on a private local Linux filesystem that
supports flock. This is same-host process exclusion, not cross-host
coordination. Do not place SQLite or its lock on SMB/NFS or replicate it
as an active shared database. Direct library callers, legacy binaries
and independent databases do not participate in this CLI lock. Update
all coordinator entry points together and stop external writers.

## Quiesced coordinator checkpoint

Stop all coordinator and worker processes and any direct DB writers.
Capture also acquires the authority lock and refuses live leases. It
uses SQLite backup for both lease and CAPCTL replay DBs, not copying
an active WAL file. The databases must exist and have their initialized
schema (including accepted CAPCTL declarations). All completed outputs
referenced by the lease DB are copied from the compute CAS and checked
against SHA-256. The checkpoint includes retired plans, attempt
ceilings and replay state. It excludes unreferenced CAS objects,
partial uploads, configs, credentials and logs. Provision those separately.

    umask 077
    python3 -m atlas.ha_checkpoint capture --db /private/leases.db \
      --replay /private/replay.db --cas /private/compute-cas \
      --dest /private/checkpoint --confirm-quiesced

Use a new destination in an existing private parent. Limits:
256 MiB per SQLite DB, 16 GiB per referenced artifact, 256 GiB total
referenced object bytes, 4096 objects. Preserve the returned SHA-256
pin independently from the checkpoint. Secure the checkpoint separately;
its manifest is not a digital signature and it is not encrypted.
Copy it using a trusted encrypted transport or store it on a private
backup filesystem, never a writable SMB public share.

## Offline recovery

First physically or administratively fence the old authority and all
old processes. Only restore if the captured state is known to be the
latest acknowledged state, with no later accepted leases, outputs or
CAPCTL declarations. Otherwise rollback can reaccept old operations
or lose completed work; do not activate this checkpoint automatically.

    python3 -m atlas.ha_checkpoint recover --bundle /private/checkpoint \
      --sha256 "$TRUSTED_CHECKPOINT_PIN" --dest /private/rebuilt \
      --confirm-fenced --confirm-no-newer-state

Recovery independently verifies each database and completed CAS object,
preserves epochs, attempt and replay records, and converts expired
LEASED records to FAILED without resetting their epochs. Publication is
atomic and no-overwrite. Start the existing coordinator with the recovered
leases.db, replay.db and cas paths under rebuilt, a new private staging
directory, and the matching trusted configuration. The old authority
must remain fenced. No automatic restore to a live DB is provided.

## Evidence and limits

12 focused HA cases passed: 3 authority tests (including real SIGKILL
and standby process acquisition) and 9 checkpoint tests (actual SQLite
WAL, CAS verification and real Ed25519 CAPCTL replay rejection after
restore). SQL lease test fixtures match the current table layout; the
complete LeaseStore/dispatch service was not run in this increment.
New modules compile; CLI entry integration was applied to the exact
upstream source but full dispatch regression could not run because
the full checkout is unavailable. This is controlled local recovery
and same-host availability preparation, not quorum, automatic physical
fencing, network partition resilience or cross-host zero-RPO HA.
