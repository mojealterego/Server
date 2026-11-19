# OMEGA-X v5.0 development — authenticated hybrid execution

## Scope and trust model

The coordinator is the single durable authority for the exact admitted
PHASESHIFT certificate. It holds a private local SQLite database and CAS.
Multiple enrolled workers may execute assigned stages on separate hosts. The
worker validates its own copy of the certificate, recipes, model catalog,
node inventory and deployment before claiming a stage. No generated shell
commands, remote executable paths, arbitrary filesystem reads or arbitrary
CAS hashes are accepted. Network operations reject local_only, including
privacy propagated transitively by PHASESHIFT. The operator must install and
trust the coordinator and its storage: trusted_only and any data handled by
this distributed transport are visible to that coordinator. Private local
stages should use the existing local pipeline instead.

TLS 1.3, CA, SAN and both leaf certificate pins reuse the infrastructure of
MTLS_MESH.md. The client certificate selects a node; task assignment and
plan hash must match. Claim and renewal require a newly signed CAPCTL
declaration of the enrolled node, including live RAM, temperature and
capacity. A separate replay database protects this dispatch domain. Keep
all configuration, lease state, replay state, worker keys and CAS private.
Do not reuse replay databases from a separate admission domain without
coordinating declaration issuance. Choose one durable coordinator and a
stable state directory, never two independent authorities for the same plan.

## Protocol and recovery

- One framed request/reply per mTLS connection: status, claim, renew, fail,
  upload, offset, download, complete. Requests identify task and exact plan.
- Claim returns a fenced epoch and bearer secret, a typed recipe, enrolled
  catalog entries, output budget and SHA-256-pinned dependency receipts.
  Dependencies must already be COMPLETED and verified in CAS.
- Claims on failed or expired attempts require explicit retry. No takeover
  of a live lease. The fixed primary assignment is not dynamically changed.
- Upload is limited to contiguous 64 KiB blocks, encoded in bounded frames.
  Identical retransmission of a committed block is idempotent. Gap, conflict
  and output-budget violations fail closed. Part files are isolated by task
  and epoch; the coordinator uses fsync and a local flock to serialize
  transfer and publication.
- Download exposes only dependencies of the active authorized lease.
  The file client validates total size and SHA-256 before publishing a local
  input. Interrupted file-client transfers can resume using the same active
  lease and private partial files; a bad final digest discards the local
  partial. Resumption does not restore in-memory inference state.
- Before completion the coordinator independently hashes the staged file
  and checks its declared modality and media attributes, including FFmpeg
  validation for image/video. LeaseStore fences the final transaction after
  CAS ingestion. Repeated completion with the same token/epoch/digest is
  idempotent; stale credentials and different hashes are refused.
- A worker uses the existing trusted multimodal subprocess adapter and
  guardian. It collects and signs live telemetry, renews in a separate
  thread, checks local RAM/temperature, and kills the supervised process
  if renewal fails or the deadline/resource policy is violated. Its local
  working directory is private. The worker runs one named stage per CLI
  invocation; orchestration of repeated polling is not yet implemented.
- If a response is lost, claim may be committed without the worker receiving
  its token. Inspect status and wait for expiration before explicit retry.
  A lost completion reply may follow successful publication; status is
  authoritative. Old epochs cannot publish; failed/expired attempts may
  have performed external side effects. Do not assume exactly-once inference.

## Deployment

Use the same exact certified tasks, nodes, catalog and plan JSON on all
hosts, and operator-provisioned CA/enrollment material per docs/MTLS_MESH.md.
Use a private filesystem for all DBs, staging, CAS and worker directories.
The coordinator's media-tools JSON contains absolute ffprobe and ffmpeg
paths for media jobs (empty object is sufficient for text-only workflows).
The worker deployment follows docs/MULTIMODAL.md. If a worker consumes
image/video dependencies, it also needs local FFmpeg and ffprobe. The
node template contains exactly id, capabilities, models, ram_headroom_mb.
Set the correct readable millidegree sensor and optional cgroup directory.
The worker signing key is distinct from its TLS key and both are owner-only.
Set a policy consistent with actual host capacities; unknown readings fail
closed. The plan's declared capacity is not a hardware attestation.

Start the coordinator in the repository root (replace paths with actual
operator-provisioned paths; default loopback port 8444):

    python3 -m atlas.dispatch serve --plan plan.json --tasks tasks.json \
      --nodes nodes.json --catalog catalog.json --db /private/leases.db \
      --cas /private/cas --staging /private/staging --policy /private/policy.json \
      --replay /private/dispatch-replay.db --pins /private/pins.json \
      --media-tools /private/media-tools.json --ca /private/ca.pem \
      --cert /private/server.pem --key /private/server.key

For a private LAN/VPN use an explicit assigned IPv4 bind plus --allow-network
and firewall restrictions. Do not expose the service publicly.

Execute a single assigned stage on its host after dependencies complete:

    python3 -m atlas.dispatch_worker --plan plan.json --tasks tasks.json \
      --nodes nodes.json --catalog catalog.json --deployment deployment.json \
      --work /private/worker --template /private/node-template.json \
      --sign-key /private/cap.pem --thermal-file "$THERMAL_SENSOR" \
      --ca /private/ca.pem --cert /private/node.pem --key /private/node.key \
      --host "$COORDINATOR_HOST" --server-pin "$SERVER_CERT_SHA256" \
      --node "$NODE_ID" --task "$TASK_ID"

Set --retry-failed explicitly only after investigating prior failures.
The low-level atlas.dispatch request CLI also exposes --upload-file or
--download-dir for operator-controlled resumable file transfers. Credential
files and stdout containing raw claim tokens are sensitive; use umask 077.
The worker CLI does not return a token in its completion receipt.

## Evidence and remaining gates

11 new dispatch tests passed (15.413 seconds in a Linux host run).
They exercise real TLS sockets and two independently enrolled client
certificates, real SQLite lease transactions, CAS, file transfer/resumption,
restart of the coordinator object on persisted data, replay rejection,
privacy, expiry, stale epoch, invalid and conflicting chunks, wrong node,
and typed output rejection. The automatic two-worker test uses actual
subprocesses/guardian, a controlled localhost Qwen-compatible HTTP server,
synthetic telemetry, and simulates temperature violation while inference is
in progress. It confirms fenced failure, retry, renewal on both nodes and
cross-node prompt transfer. It does not run AI weights or physical devices.
68 selected existing regression tests passed in groups (16 mesh, 10 CAPCTL,
17 multimodal unit, 12 runtime gate, 9 recovery, 4 supervisor gate).
Python compilation passed on the available source subset. Git cloning is
still blocked by runner DNS, so full repository verification is not claimed.

This is a single-coordinator implementation, not a replicated consensus
cluster. No automatic reassignment to a different physical node, scheduler
polling daemon, quorum or HA, automatic cloud replication, global storage
quota/GC, adversarial worker sandbox, independent execution attestation,
or physical S24/VPS evidence is provided. The 64 KiB one-connection-per-RPC
transport prioritizes correctness rather than high-throughput bulk transfer.
For large assets the existing Merkle/Rclone layer remains a separate
operator-controlled option; it is not yet automated by this coordinator.
Expensive server-side hashing/media verification may finish after a socket
deadline or lost response; fencing and idempotent completion handle this
uncertainty. Keep regular lease renewals active during validation. Worker
locking uses a private stable anchor separate from legacy local executors;
do not run legacy independent supervisors against the same hardware
concurrently. It does not guarantee cancellation of work inside an external
llama-server after client termination. Server capacity and remote live
metrics are not kernel enforcement. Model profiles and binaries still
require qualification with actual weights. Automatic multi-host failover
and production deployment remain open.

    python3 -m unittest discover -s tests -p test_dispatch.py -v
