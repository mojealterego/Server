# Compute v5.2a — fenced failover restart

This is operator-confirmed full workflow restart after node loss, not
transparent active-job migration or automatic failure detection. It uses
the existing PHASESHIFT compiler, independent verifier, CAPCTL and central
SQLite LeaseStore. It is designed for the current single-authority system.

## Cutover contract

Before cutover, upgrade all services using the same lease database, stop
the predecessor coordinator and workers, verify that no untracked model/job
process is still active, and retain the exact predecessor plan and inputs.
Legacy processes do not know the retirement table and must not run.
The operator supplies fresh signed declarations from the surviving already
enrolled nodes. No new trust identity is introduced. The planner uses the
intersection of live and enrolled capabilities/models, conservative RAM,
headroom, free disk and temperature, and recompiles with the failed node
excluded. The successor certificate is independently verified against
the original enrolled capacity records of the selected subset so the
existing node_registry contract of the same database is preserved.
Runtime claim still rechecks fresh telemetry.

Local-only workflows are rejected in this network restart path. The original
require_n_minus_one condition is preserved unless --allow-degraded is
explicitly supplied. The plan may be blocked if remaining nodes cannot
cover the DAG under the live limits.

Cutover is atomic: BEGIN IMMEDIATE checks no unexpired predecessor leases;
completed tasks are refused by default. If the operator authorizes a full
restart including completed work with --restart-completed, all tasks start
fresh in the new plan, including already completed ones. The old results
remain in CAS but are not imported or reused automatically. Be aware of
external side effects; do not restart non-idempotent jobs without a separate
reconciliation. The transaction records the exact successor payload in
retired_plans. The modified LeaseStore checks predecessor retirement in
every guarded transaction, preventing stale claims, renewals and final
completion. Expired jobs may still have external side effects, so the
quiescence requirement is not optional. Old raw read-only status remains
available locally. Use the same central database on local storage; a copied
or older database or unpatched program is not covered by this fence.

## CLI

With actual private file paths, existing enrolled policy and fresh
declarations from surviving nodes:

    umask 077
    python3 -m atlas.failover prepare \
      --db /private/leases.db --plan plan.json --tasks tasks.json \
      --nodes nodes.json --catalog catalog.json --failed-node phone \
      --envelope /private/gpu-live.json --policy /private/policy.json \
      --replay /private/restart-replay.db --confirm-quiesced > successor.json

Repeat --envelope for other surviving nodes. Use a private replay database
separate from the lease database and other admission domains.
An unsuccessful planning attempt can consume a declaration; sign a fresh
one. If the process crashes or stdout is lost after commitment, recover
the same successor rather than making another:

    python3 -m atlas.failover recover --db /private/leases.db \
      --plan plan.json --tasks tasks.json --nodes nodes.json \
      --catalog catalog.json > successor.json

Extract the successor plan and node inventory into *new* private files:

    python3 -c 'import json; x=json.load(open("successor.json")); [(open(p,"x").write(json.dumps(x[k],indent=2))) for k,p in [("plan","successor-plan.json"),("nodes","successor-nodes.json")]]'

Configure the coordinator and surviving workers with the successor files,
matching original tasks/catalog, appropriate enrolled certificate pins,
and the SAME coordinator lease database. Follow HYBRID_DISPATCH.md and
SCHEDULER.md. Retired plans cannot be reactivated through the updated
LeaseStore. Preserve the DB during backups and upgrades. This feature is
not a consensus protocol or HA for the coordinator.

## Evidence

9 new cases passed, including real SQLite concurrent cutovers (one
successor), active lease denial, explicit restart of completed tasks,
expired credential fencing, insufficient resources, privacy and identity
rejection, and separate CLI subprocesses with real signed CAPCTL telemetry
and successor recovery. 13 dispatch, 11 scheduler and 9 recovery
regression cases also passed. Python compilation passed for the available
source subset. Full repo checkout remains blocked by DNS; no real hardware,
network partition or distributed failover deployment is claimed.
