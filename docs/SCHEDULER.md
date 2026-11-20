# Autonomous node scheduler (v5.1 development)

Use the same provisioned worker arguments as docs/HYBRID_DISPATCH.md, but
replace --task ID with --schedule. Each worker processes its own certified
network assignments sequentially, without requiring the operator to invoke
each stage. Start a scheduler on every participating node. Local-only tasks
are excluded; no local-only data is exported by this scheduler.

Defaults: one attempt per task, one-second polling, 300-second idle budget.
To authorize a bounded retry policy explicitly, add
--retry-failed --max-attempts 3 (range 1..10 inclusive, including initial
epoch). --poll-interval accepts 0.1..30 seconds; --idle-timeout accepts
1..86400 seconds. Existing --timeout remains the per-stage execution
budget. An active lease is never retried. The server reports a readiness
boolean derived from upstream completion and retry eligibility using its
own clock. Claim still validates CAS dependencies and attestation.

The scheduler orders runnable stages by certified start slot, end slot,
and task ID. It polls only assignments for that node and skips local-only
stages. A local NodeLock excludes a second scheduler using the same work
directory and node; worker execution has its separate existing lock.
Persisted task state and epoch come from the coordinator's durable lease
database, so restart does not repeat completed stages. A lost completion
response is resolved by re-reading status. RPC failures back off and stop
after a bounded number; three consecutive stage failures without epoch
progress block that task for the current invocation. The process returns
0 for completion, 2 for blocked, 1 for configuration/other worker errors,
and 130 for keyboard interruption. Completion applies to node network
assignments, not global completion of an entire workflow.

When supplied on a network claim, max_epoch is checked by the coordinator
under its per-task lock before admission. This is a requested bound, not
a mandatory global administrator policy: legacy/manual claim callers may
omit or choose it; direct LeaseStore operators must not bypass coordinator
ownership. Preclaim failure counts and idle deadlines are process-local
and reset on scheduler restart. No automatic migration, dynamic cluster
replanning, background service installation or exactly-once inference is
provided. Polling uses bounded sequential RPCs, so idle timeout is checked
between polls rather than a hard wall-clock bound on in-flight RPCs.

Verification: 11 scheduler unit cases passed using deterministic clock and
controlled callbacks. All 13 dispatch cases passed (20.284 s in the Linux
runner); two new cases exercise real mTLS, readiness and epoch caps, plus
two concurrent schedulers reaching actual worker processes, SQLite and
CAS over a synthetic HTTP LLM endpoint. Compilation and CLI help passed.
No full repository regression, real model inference, hardware or VPS
deployment was performed in this increment.

## v5.5a — opt-in idle polling adaptation

Add `--max-poll-interval 8` to the existing worker `--schedule`
invocation (with `--poll-interval 1`, for example). Without the option
or if its value equals the base interval, previous fixed idle polling
is retained. The cap must be between the base interval and 30 seconds.
Single-task mode rejects this option.

When no work is ready, the delay doubles to the cap, clipped to the
idle deadline and existing eligible retry due-time. A changed valid
snapshot or stage execution resets the delay to the base interval.
RPC failure backoff and error limits are unchanged; the new cap applies
only to idle polling. No change to the lease heartbeat, plan, resource
or retry policy. A larger cap trades fewer queries for a greater
readiness detection latency (in-flight RPC times are additional).

Deterministic single-task example: over 20 simulated idle seconds,
fixed one-second polling issues 21 status calls; base 1 s/cap 8 s
issues 6. These are fixture counts, not hardware power or speed results.
