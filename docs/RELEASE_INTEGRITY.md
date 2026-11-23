# RELEASE-01 — pinned source verification and deterministic packaging

The previous `--skip-verify` implementation trusted a historical JSON PASS even after sources changed, allowing stale test evidence in a release package.

## Contract

1. `python3 tools/verify.py` executes the full local suite, shell checks, compileall and the synthetic benchmark. After all other evidence files are written, it computes `local.verified_sources={sha256,files}` and saves it to `reports/verification.json`. The digest includes explicitly allowlisted source, documentation and evidence reports, excluding verification.json and generated SHA256SUMS to avoid self-reference.
2. `python3 tools/package.py` requires PASS, nonzero tests, zero failures/errors/skips and an exact match of the verified source fingerprint before ZIP creation **and again after creation**. A missing pin, modified/added/deleted allowed file, hardlinked file, or file mutation fails closed.
3. `python3 tools/package.py --skip-verify` only repacks the unchanged previously verified checkout; old reports without a pin are intentionally rejected. Run the full verification again after changing any allowlisted input.
4. Recent E16–E22 evidence reports are included through an explicit allowlist, while unknown report filenames, keys, .env and model weights are not packaged.

The fingerprint streams files in bounded chunks with no-follow and before/after inode/size/mtime/ctime checks. Maximum input size: 128 MiB per source file, 2 GiB total, 10,000 files.

## Local test evidence and limitations

`PYTHONWARNINGS=error::ResourceWarning python3 -m unittest discover -s tests -p 'test_release_fingerprint.py' -v`: 9 PASS.

`PYTHONWARNINGS=error::ResourceWarning python3 -m unittest discover -s tests -p 'test_package_release_pin.py' -v`: 4 PASS.

Three package assertions were RED against the previous package builder (stale PASS accepted, missing pin accepted, evidence report omitted); all GREEN after the fix. Combined 42 focused tests passed with E21/E22 on a local Linux/Python 3.13.5 source subset. The full GitHub checkout and full verify.py integration are NOT_RUN. See reports/release-pin-verification.txt.

**A local hash is not an independent trusted signature.** An adversary able to rewrite both source and the verification JSON can forge a consistent pin. Production acceptance needs an external signed manifest, pinned Git SHA, independent clean build, physical SMB/etcd/cloud/Android tests and GATE-09 evidence.
