# Compute v5.2b — durable retry policy and bounded failover detection

## Administrator-owned retry budget

The coordinator now accepts --max-attempts 1..10 (default 3). On first
successful initialization it persists the limit for this workflow in the
central SQLite database. The limit is immutable for that lineage; restarting
with a different value fails rather than silently raising/resetting it.
Supply the same value to the successor coordinator after failover. The
worker's --max-attempts and requested max_epoch remain separate, stricter
client-side options. The default worker still does not retry automatically.

Every LeaseStore.claim transaction checks the persisted limit if one exists.
Epochs of all plans registered to the same root lineage are summed per task,
including previous failed/expired attempts. The successor inherits the
policy during the same atomic transaction that retires its predecessor.
If no attempt remains for any task, full-restart cutover is refused.
Legacy unconfigured direct/local plans remain without a ceiling until
configured. Earlier unregistered retired generations are not retroactively
counted. This is a workflow-lineage limit, not a cross-workflow user quota.
Never use old unpatched binaries or copied databases against an active
authority. A new independent workflow is a separate policy scope.

The status RPC exposes remaining_attempts; scheduler treats zero budget as
terminal once the task is pending or retryable. It does not terminate an
already active lease merely because it has spent its last attempt.

## Watch and gated cutover

Run from the coordinator repository root using the existing private plan
inputs and central lease DB:

    python3 -m atlas.failover watch --db /private/leases.db \
      --plan plan.json --tasks tasks.json --nodes nodes.json \
      --catalog catalog.json --failed-node phone --watch-timeout 120 --poll 1

The bounded watcher returns CANDIDATE only when at least one lease on the
specified node has expired, no predecessor lease remains active, no task
has completed, and no configured budget is exhausted. It never modifies
the plan or contacts the node. TIMEOUT returns exit code 2. This is
evidence of lease expiry, not proof of device death, actual quiescence or
network partition. SQLite lock waits can extend the nominal watch deadline.

For a controlled cutover use the existing prepare command documented in
FAILOVER.md, with --require-expired as an additional guard. It rechecks
expiry in the atomic retirement transaction, requires the operator's
--confirm-quiesced and fresh signed survivor declarations, and honors
--restart-completed only when explicitly set and budget permits.
A watcher result alone is not authorization. Stop/unregister the old
coordinator and verify old worker/inference processes before proceeding.
Automatic physical fencing, coordinator HA and unattended cross-host
redeployment remain open. No live migration or completed artifact reuse
is claimed.

## Evidence

7 new retry/watch unit and SQLite integration cases passed; 1 additional
scheduler case and 1 additional real mTLS dispatch case passed, including
a manual client trying to omit or enlarge its retry limit. Existing 11
scheduler, 13 dispatch, 9 failover and 9 recovery cases also passed.
Tests used the existing local recovered source subset; physical nodes and
the full repository verification remain open.
