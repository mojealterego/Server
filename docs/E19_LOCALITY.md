# E19a: offline locality advice for workloads and verified data references

**Implemented** an advisory scoring layer for the existing PHASESHIFT/ATLAS
compute and E14/E15 data fabric. No runtime placement is activated and no
PHASESHIFT certificate is forged or bypassed. The result contains **ranked
advice only**; the actual task scheduler and existing admission/lease guards
remain unchanged.

Operator input `omega.locality.v1` contains:

- `task_inputs`: exact SHA-256 of a dataset and its byte size, bound to task ID.
- `replicas`: observation of a content digest being available at a node.
- `links`: measured directional bytes/second and RTT for source-to-target.
- `runtime`: 10..100 profiled stage-latency samples (ms) per task/node.

The complete document is bound to an external SHA-256 pin. Records with
future timestamps or older than the `max_age` window are ignored, not
interpolated. Invalid or duplicate declarations are rejected. Per-stage runtime
uses nearest-rank p95. Estimated transfer time is
`ceil(bytes * 1000 / measured_bytes_per_second) + rtt_ms`; if the digest is
already observed locally, network transfer estimate is zero. If there is no
measured feasible path, the candidate is excluded instead of inventing a
bandwidth. Candidates must satisfy declared trust/privacy, model, engine,
RAM/headroom and thermal constraints. Scores are deterministic and represent
*sum of measured stage p95 and estimated transfer*, not an end-to-end p95.

Example (operator inputs must be actual independently measured observations):

```bash
python -m atlas.locality_advisor \
  --tasks /private/tasks.json --nodes /private/nodes.json \
  --profile /private/locality.json --profile-sha256 "$TRUSTED_LOCALITY_PIN" \
  --max-age 300 > /private/recommendations.json
```

Privacy rules are advisory guardrails, **not** authorization to read a remote
dataset or permission to send sensitive files. A content digest declaration
is not proof the node physically possesses bytes. A SHA-256 profile pin is not
an authenticity signature. Verification of real profiles, E15 restore identity,
network authorization and source-to-target ACL must happen separately. An
actual proposed schedule must go through the existing PHASESHIFT verifier and
lease authority before activation. No speculative prefetch or paid cloud write.

**Evidence:** 10 focused deterministic cases + 1 real subprocess CLI test,
including tampered profile pins, missing/expired measurements, trust
restrictions, capacity failures and no network-route fallback. No real network
benchmark; no throughput, cost, S24 latency or energy advantage claimed.

Next E19b: signed measurements + actual transfer receipts, multi-task resource
contention, rollback and performance-regression gate; followed by E20 quorum
fencing and E21 immutable restore. GATE-09 remains OPEN.
