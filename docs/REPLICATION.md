# OMEGA-X v4.7 — replicated CAS

The operator can replicate local verified CAS artifacts to 1–8 configured Rclone
vault paths and restore from independent replicas. Existing ArtifactStore and
Merkle staging are reused. This is a content-addressed replication layer, not
distributed consensus, remote execution or a distributed lease.

## Protocol

- Fixed 4 MiB blocks (final block may be shorter), named blocks/<SHA256>.
- Artifact manifests use the existing omega.atlas.merkle.v1 schema, with the
  artifact digest as filename. Canonical JSON is published to
  manifests/<artifact SHA256>.json only after every referenced block is read
  back and verified on that replica. Identical blocks across artifacts are
  reused; checking their bytes still consumes download traffic.
- Push checks existing bytes; only Rclone not-found exit codes 3/4 allow
  upload. It uses --immutable and reads back each write. Rclone is not a
  transactional conditional-write primitive; require operator-controlled
  remotes with trusted writers and compatible exit codes. Do not delete or
  mutate referenced blocks.
- Pull requires both the expected artifact SHA256 and the expected manifest
  SHA256 from a trusted out-of-band receipt. Each block tries replicas in
  order until hash and length match. Corruption, unavailable sources, and
  hash mismatch never authorize publication.
- Local partial data persists across failed attempts and is rehashed before
  reuse. Merkle and full file digest are validated before atomic same-filesystem
  hardlink publication into the existing CAS. The staging directory is private;
  do not remove lock files while active. Corrupt preexisting local objects are
  rejected, not overwritten. The local bound is 16 GiB per artifact, 512 KiB
  per manifest and 4 MiB per remote read, plus bounded per-command timeout.
  There is no aggregate transfer deadline or storage quota.

## Usage

Configure actual independent Rclone remotes, preferably separately encrypted
crypt remotes (verify SSH host keys where applicable). Keep credentials out of
Git. Choose an authorized artifact SHA256 returned by casctl put or an
execution receipt. The CLI requires explicit --allow-export; this is an
operator decision, not automated workflow privacy enforcement. Never export
local_only or other restricted data. Use private paths for receipts and CAS.

    python3 tools/replicactl.py --vault "$HOME/.omega-x/cas" \
      --remote crypt1:omega-cas --remote crypt2:omega-cas \
      push "$ARTIFACT_SHA" --allow-export

Retain the resulting manifest_sha256 independently of the replicas. Restore
on another host (with configured remotes and an existing private vault parent):

    python3 tools/replicactl.py --vault "$HOME/.omega-x/cas" \
      --remote crypt1:omega-cas --remote crypt2:omega-cas \
      pull "$ARTIFACT_SHA" --manifest-sha256 "$MANIFEST_SHA"

    python3 tools/casctl.py --vault "$HOME/.omega-x/cas" verify "$ARTIFACT_SHA"

Use casctl restore to materialize a new destination if needed. A failed push
may already have deposited blocks or a completed manifest on an earlier
replica; rerun the same command to verify and continue. The status
VERIFIED_READBACK is a point-in-time read verification, not a claim of future
availability, immutability, or physical separation. A manifest published in
an earlier successful transfer may remain visible if the remote later loses
blocks; pull still verifies every byte.

No encryption is implemented by the replication module itself; encryption
depends on trusted Rclone configuration. Cross-replica deduplication may expose
equality to a party seeing plaintext names, and this does not authorize
cross-tenant sharing. No automatic GC, remote repair/overwrite, background
replication, quorum protocol or automatic privacy admission is implemented.

## Evidence

12 new tests passed in groups on Linux/Python 3.13 with real
ArtifactStore/Merkle source matched to upstream SHA-256 and Rclone emulated
by a subprocess. Round trip, interruption/resume, deduplication, corrupted
replica failover, oversized responses, manifest pin mismatch and fail-closed
publication were tested. A separate actual CLI invocation proved explicit
export authorization and push/pull round trip with the same emulator.
Python compilation passed. Full repository clone is blocked by DNS in this
runner; full regression, mobile, actual Rclone binary, real network/cloud and
VPS remain untested. Earlier verification reports are historical.

    python3 -m unittest discover -s tests -p test_replication.py -v
