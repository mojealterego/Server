# OMEGA-X v4.6 — local recovery contract

## Execution

Every SupervisedExecutor invocation (phaseexec and phasechat) now acquires a nonblocking per-node flock next to the operator's existing lease SQLite database before claiming the job. The directory is private, the file is owner-only, and symlinks/nonregular files/hardlink aliases are rejected. Separate plans using the same database and node ID serialize their actual subprocess lifetimes. Different node IDs can still run independently. Do not delete, replace or rename the database or lock directory while executing. Use a local filesystem with reliable flock support, not Android shared storage or a network mount.

The guardian runs in a new process session and owns an inherited copy of the lock. A pipe is held open only by the supervisor. EOF (including supervisor SIGKILL) causes the guardian to send SIGKILL to its own current process group, never to a PID obtained from stale persisted state. The guardian passes the lock to the trusted foreground command as an extra defense; if the guardian is killed, a child retaining that descriptor keeps the node busy. On normal exit the guardian preserves the child exit code. The supervisor waits for bounded stdout drainage before publishing, refusing publication if stdout stays open.

A busy node is rejected with RECOVERY_BUSY before lease claim. The lock is not explicitly unlocked: it is released only when the last holder of the shared open file description closes it. The durable SQLite lease and epoch remain the source of truth for result publication. RUNTIME_GUARD now uses the same immediate fenced FAILED transition as other supported failures, rather than waiting for TTL because of an unsupported reason.

## Recovery checklist

1. Check the node lock using your actual DB path and node ID:

       python3 -m atlas.recovery --db "$HOME/.omega-cap/leases.sqlite" --node s24

   BUSY means do not retry. IDLE only means no holder of this particular execution lock. It is not proof that the node has no other processes.
2. Use existing phasectl status for the same workflow/plan/task. COMPLETED must not be rerun. LEASED may remain until TTL after an abrupt supervisor death; wait until expiry or use an existing fenced failure authorization.
3. Retry with phaseexec or phasechat and fresh runtime credentials after expiry or FAILED. The existing LeaseStore assigns a new epoch. Do not forge or manually update fencing tokens. Existing CAS receipts are authoritative only when lease state confirms completion.
4. Old temporary outputs/logs from a crash can remain in the work directory; never publish them by filename or remove them while a relevant execution is active.

## Boundaries

This is one-host, one-local-database cooperative exclusion. One simultaneous supervised command per node is an intentional conservative tradeoff. Do not use arbitrary commands that daemonize, call setsid, close/unlock the inherited lock or escape the group; this is not a sandbox. A guardian killed independently cannot cancel a child itself, and a child that loses the lock descriptor could be untracked. If that happens, check for leftover processes before retry. A local lock cannot cancel inference already running in an external llama-server after its client dies. Legacy direct lease-only entry points and other servers do not acquire this lock. No distributed exclusion, automatic reattachment, kernel-level resource quota, power-loss durability proof or recovery of a model's in-memory state is claimed.

## Verification

35 focused tests passed on Linux/Python, including real process creation, SIGKILL of supervisor and guardian, lock continuity, contention, exit status, symlink rejection and a SQLite RUNTIME_GUARD regression. The existing selected CAPCTL and runtime tests also passed. Supervisor integration tests use controlled lease/CAS doubles. SQLite failure regression was run against the extracted upstream fail and transaction methods with mocked ownership verification. Full checkout via git fails DNS in this runner; full regression not run. Existing v4.3 verification reports are historical.

       python3 -m unittest discover -s tests -p 'test_recovery*.py' -v
       python3 -m unittest discover -s tests -p 'test_gate_execution.py' -v
       bash tools/verify.sh
