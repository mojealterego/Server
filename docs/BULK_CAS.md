# Compute v5.3 — bounded parallel CAS replication

The existing Rclone CAS replication protocol now supports parallel transfers
of distinct 4 MiB blocks, with a maximum of eight concurrent operations
per replica and per invocation. The library remains serial by default
(workers=1); the replicactl CLI defaults to four. Existing manifests,
object hashes, remote layout and partial download files are compatible.
The fixed block size, 16 GiB object limit and replica count are unchanged.

    python3 tools/replicactl.py --vault /private/cas \
      --remote backup1:omega-cas --workers 4 push "$ARTIFACT_SHA" --allow-export

    python3 tools/replicactl.py --vault /private/cas \
      --remote backup1:omega-cas --remote backup2:omega-cas \
      --workers 4 pull "$ARTIFACT_SHA" --manifest-sha256 "$MANIFEST_SHA"

Use --workers 1 to preserve serial behavior when memory, thermal limits
or provider throttling make concurrency undesirable. Eight 4 MiB blocks
represent a 32 MiB nominal payload window, not a measured bound on total
process RSS; Rclone, hashing, subprocess pipes, read-back buffers and Python
overhead add to memory consumption. Separate replication invocations do not
share a global concurrency budget. Each remote operation retains the timeout
and size guards; there is no hard whole-transfer deadline.

Push hashes local bytes before upload, avoids duplicate uploads of identical
blocks in a single object, waits for verified read-back of all blocks on a
replica, then publishes its existing canonical manifest last. It never treats
an authentication/network error as permission to overwrite. Failed transfers
can leave reusable remote blocks; a previous manifest may already exist.

Pull checks the independently pinned manifest, rehashes existing partial
ranges before scheduling downloads, fetches missing blocks concurrently
in bounded windows, verifies each result, writes in deterministic order,
and fsyncs before publication. Individual block readers try replicas in
order. A failed window need not retain results after the first failed block;
retry still reuses verified persisted ranges. The final complete file
is SHA-256/Merkle verified before no-overwrite publication. Custom Merkle
readers must be thread-safe if explicitly enabling more than one worker.
Legacy serial callers keep their calling-thread semantics.

Evidence: 5 new deterministic concurrency/failure tests passed with
in-memory replica substitutes; the barrier tests establish simultaneous
block operations without relying on wall-clock speed. All 12 existing
replication cases passed in split invocations with subprocess Rclone
substitutes. 9 snapshot and 8 storage cache regressions passed. Actual
Rclone/cloud throughput and hardware RSS are not measured. This does not
accelerate the separate 64 KiB mTLS dispatch RPC protocol. It is not a
distributed quota or consensus layer.
