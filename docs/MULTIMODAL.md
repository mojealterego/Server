# OMEGA-X v4.9 — typed multimodal orchestration

## Contract

The operator supplies a PHASESHIFT-certified task DAG, catalog, node inventory,
and trusted local deployment configuration. Multictl verifies the plan through
LeaseStore, checks every typed recipe and runs the local assigned tasks through
SupervisedExecutor and its process guardian. All dependency edges must stay on
one node. The runner does not dispatch to other hosts or export data.

Supported recipes:

| kind | engine | typed output | required model slots |
| --- | --- | --- | --- |
| qwen_text | llama | nonempty UTF-8 | one Qwen llm/vlm, runtime_model_ids binding |
| flux1 | sd-cli | PNG | diffusion_model, clip_l, t5xxl, vae |
| wan_t2v | sd-cli | AVI | diffusion_model, t5xxl, vae |
| wan_i2v | sd-cli | AVI | diffusion_model, t5xxl, vae |
| ltx2 | sd-cli | AVI | diffusion_model, llm, embeddings_connectors, vae; optional audio_vae |

The task recipe accepts exactly one of prompt (literal text) or prompt_from
(ID of a declared text dependency). Wan I2V also requires image_from
(ID of a declared PNG dependency). Dependencies must precisely match inputs.
Media recipes include slots (slot name to catalog model ID), width, height,
steps; video recipes also include frames and fps. Qwen recipes include
runtime_model and optional max_tokens. All tasks declare output_bytes,
ram_mb, privacy, models, engine, id and depends_on under the existing planner
contract. Arbitrary commands and extra recipe fields are refused.

Every media catalog entry must declare family (flux1, wan, or ltx2),
role matching its slot, bundle (operator-verified common bundle ID),
lineage_verified=true, format (gguf, safetensors or sft), bytes and sha256.
The diffusion backbone must explicitly enroll the recipe kind in profiles.
Media weights are read in bounded chunks and checked before invoking sd-cli.
Family, variant and lineage declarations require independent operator evidence;
the orchestrator does not establish lineage from filenames. Existing catalog
entries are not automatically promoted. The Qwen HTTP model ID is a server
claim, not independent verification of the loaded weights.

Deployment JSON contains node, llama_endpoint (literal http://127.0.0.1:PORT),
sd_cli, ffmpeg, ffprobe (absolute executable paths), backend (cpu, cuda0,
vulkan0 or hip0) and model_paths (catalog IDs to absolute local file paths).
Only entries needed by the local tasks are required. Executable and model
files must be non-symlink regular files; keep files and deployment root
operator-controlled and stable. There is no adversarial same-UID isolation.

## Operation

Install Python, FFmpeg/ffprobe, and the actual compatible inference binaries
and verified model bundles separately. Consult the deployed sd-cli --help
and pin a known compatible build before using a profile. For Termux,
FFmpeg is available via pkg install ffmpeg.

    python3 tools/multictl.py --help
    python3 tools/multictl.py --tasks tasks.json --nodes nodes.json \
      --catalog catalog.json --plan plan.json --deployment deployment.json \
      --db /private/workflow.db --cas /private/cas --work /private/work \
      --node phone --timeout 600

Use real operator-provisioned paths. The plan must have been generated for
the exact tasks, catalog and nodes. For signed runtime admission add
--runtime-envelope-dir, --runtime-policy, --runtime-db, --thermal-file,
and optionally --runtime-cgroup and --runtime-ttl. The envelope directory
contains one signed task-ID.json per stage. Runtime gate is optional for
legacy compatibility; expiry may interrupt long jobs, and automatic
renewal is not implemented.

Completed stages are rehashed in CAS and validated again before reuse.
Failures and expired leases are not automatically retried; explicitly add
--retry-failed after inspecting the cause. Live leases remain blocked.
Expected media signature, dimensions, frame count, frame rate and full video
decode are verified with FFmpeg before CAS publication. Text must be valid,
nonempty UTF-8 without NUL. Output budgets apply through the existing lease
and worker contracts. Audio stream content is not verified by this release.

## Verification

24 new cases passed (17 unit and 7 integration cases, run in groups because
the aggregate invocation exceeded the runner time budget). The integration
tests use real upstream PHASESHIFT, lease/fencing, guardian, CAS, HTTP
transport and FFmpeg processes with synthetic model endpoints and synthetic
PNG/AVI generation. 35 selected existing CAPCTL, runtime and recovery cases
also passed. Python compilation passed. Exact recovered upstream dependencies
were compared against repository SHA-256 values. Full checkout/regression,
actual model inference, physical S24/VPS tests, multi-node dispatch and
hardware performance verification remain outstanding.

    python3 -m unittest discover -s tests -p 'test_multimodal.py' -v
    python3 -m unittest discover -s tests -p 'test_multimodal_integration.py' -v

The media adapter is a typed command contract, not a claim that any particular
FLUX.2 or LTX 2.3 checkpoint works. No automatic cloud transfer, mTLS-backed
dispatch or whole-system production certification is implied.
