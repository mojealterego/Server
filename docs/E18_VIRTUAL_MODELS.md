# E18a: pinned, source-backed public model hydration

**Implemented scope:** re-fetch an independently SHA-256-pinned, publicly
licensed model artifact from a reproducible HTTPS source on demand. This
eliminates the need to keep every copy of public weights locally; it does
**not create free physical disk space**. Unique/private data are not
reconstructible this way. Licenses must be reviewed by the operator.

Reference fields: `schema=omega.virtual-model.v1`, `url`, `revision` (exact
40-character lowercase Git commit), `sha256` (64-character lowercase hex),
`size_bytes` (1..64 GiB), `license` (operator asserted SPDX-style ID).
Origin is pinned to `huggingface.co/<owner>/<repo>/resolve/<commit>/<file>`;
only HTTPS and platform CDN redirects (`*.hf.co`, `*.xethub.hf.co`) are
admitted, maximum three redirects. Environmental proxy settings are not
inherited. IP literal URLs, credentials, custom ports, unpinned branches,
unsafe path segments and fragments are rejected.

`rehydrate` reads a bounded stream (1 MiB chunks), verifies exact byte count
and SHA-256, fsyncs private staged data and atomically hard-links it to a new
immutable-style cache object, never overwriting a destination. Existing
cached files undergo a fresh full SHA-256 check and require no network.
Transport failures and mismatches discard partial files. The file is marked
read-only to reduce accidental modification. The caller must keep the
independent digest pin and ensure sufficient free disk before hydration.

CLI:

```bash
umask 077
python -m atlas.virtual_model --reference /private/pinned-public-model.json \
    --destination /private/model-cache/model.gguf --max-seconds 3600
```

**Acceptance:** 8 library tests and one real subprocess offline-cache CLI
roundtrip. These tests use controlled streams, not live Hugging Face network
transfer, TLS/CDN validation, huge model weights, Android mmap or throughput
benchmarks. Manifest integrity is a SHA pin, not an origin signature.

Future E18b needs resumable range transfer with authenticated chunk hashes,
real provider and license qualification, storage pressure/eviction arbitration,
recovery evidence and end-to-end llama-server inference on pinned weights.
