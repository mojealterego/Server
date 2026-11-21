# OMEGA-X — evidence-gated audit of the supplied v1.0.0 report

Baseline: `aec4640b476fc097738639d2d5dba5fb019f2799` on `main`. The supplied v1 report is a requirements/reference document, not a verified device or server release. Do not overwrite the current v5.x modules with the report's historical code.

## Accepted requirements and implementation

- Model directory: `$HOME/storage/shared/1.GGUF-UNCENSORED`; read existing files without copying or renaming them automatically. The current `termux/model_inventory.py` parses bounded GGUF v2/v3 and Safetensors headers and classifies models, but does not claim observed six files without actually listing them.
- `termux/device_model_probe.py` adds a separate read-only operator command that checks file existence, file count (optional), genuine first-page `mmap` access, optional full-file SHA-256, and observed process affinity. It rejects symlinks, malformed headers, non-regular files and mutations observed during the scan. It outputs truthful per-file evidence, never a synthetic `GREEN-MOBILE VERIFIED` certificate.
- The existing Termux arbiter and mobile services remain authoritative. SFTP/WebDAV/LLM are not automatically enabled by this preflight; thermals, LLM inference, TTFT, OpenCL/NPU, media generation and mobile E2E remain `NOT_RUN` until measured on the real device.
- The existing immutable, independently checked, per-remote Rclone snapshot process with authenticated completion receipts remains authoritative. `rclone union create_policy=all` is a convenience mirrored write policy, **not** proof of 3-2-1 independence or a durable transaction. No complete `rclone.conf` overwrite and no placeholder credentials.

## Rejected or unproven claims in the supplied v1 report

1. `verify_test_suite()` generates literal `[PASS]` strings without invoking tests. These are assertions, not evidence. The report's `red.txt` similarly cannot be treated as proof of zero vulnerabilities.
2. The six exact model filenames, 9.83 GB WAN composition, projector compatibility and output engine support are hypotheses until confirmed by the local inventory, model provenance and engine version. Matching projection dimensions does **not** prove weight lineage compatibility.
3. A successful file `mmap` page read does not demonstrate zero-copy execution, resident-RAM size, cold start under 800 ms or TTFT around 340 ms. Android shared storage can involve emulation/FUSE; benchmark on the actual phone.
4. `taskset -c 2-7` and six threads are candidate settings, not validated CPU topology/affinity on every device/Android build. Probe the process cpuset and benchmark.
5. `--size-only` checks sizes, not byte integrity. `sha256sum` is an integrity digest, **not** a digital signature. The historical `rclone.conf` generator destructively rewrites a private configuration, may leak secrets via environment/configuration, and substitutes placeholders.
6. A shell worker that moves `queue/pending/*.json` into `queue/completed/` has not run media inference. Never mark the job completed without an actual verified output.
7. Do not silently change device-global Android `device_config`/Phantom Process Killer parameters; any ADB change needs independent owner approval, compatibility validation and rollback.
8. A production/green-mobile certificate requires on-device reproducible logs and an actual exercised engine. The current repository intentionally keeps `reports/green-mobile.txt` at `NOT_RUN_ON_S24_ULTRA` until the real hardware run.

## Operator read-only preflight (on the phone)

```bash
python3 termux/device_model_probe.py \
  --dir "$HOME/storage/shared/1.GGUF-UNCENSORED" \
  --expect-count 6 --sha256 \
  --json-out "$HOME/.omega-x/model-probe.json"
```

`--expect-count 6` is a *requested expectation*, not a discovery; omit it if the actual file count differs. `--sha256` reads all model bytes and can take considerable time. A successful run only confirms these read-only checks; it does not change `reports/green-mobile.txt` or the release gate.

## Acceptance and open gates

- New local fixture tests for the preflight: 13/13 passed on an x86_64 Linux host (includes actual read-only `mmap` against fixtures, failure cases, SHA-256 and private report publication). Python compilation and CLI help also passed.
- **OPEN**: authentic S24 Ultra run; six real file headers and hashes; mmproj image inference; CPU/GPU/NPU performance and thermal measurements; real Wan/LTX; SFTP/WebDAV device E2E; VPS container and cloud recovery tests. No full-repository regression or production GATE-09 pass claimed.

Sources: [GGUF specification](https://github.com/ggml-org/ggml/blob/master/docs/gguf.md); [llama.cpp loader](https://github.com/ggml-org/llama.cpp/blob/master/src/llama-model-loader.cpp); [Rclone Union](https://rclone.org/union/); [Termux execution environment](https://github.com/termux/termux-packages/wiki/Termux-execution-environment).
