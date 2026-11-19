# Live runtime gate (v4.5)

The operator must choose a readable sensor containing integer millidegrees Celsius, calibrate its threshold and select the actual cgroup v2 directory if applicable. No fallback temperatures are fabricated. Without cgroup input only /proc/meminfo is used. The cgroup limit is sampled, not created or enforced by this tool. Ancestors are not enumerated. A 43 C threshold is a policy value, not a certified thermal safety limit. Keep all configs and replay state in private directories.

Prepare an operator-enrolled Ed25519 key and policy per CAPCTL.md. Create a node template JSON with exactly id, capabilities (list), models (list), ram_headroom_mb (integer). The collector measures RAM availability, filesystem free space and configured thermal reading rather than accepting supplied readings.

Collector:

    python3 -m atlas.runtime_gate --template "$HOME/.omega-cap/template.json" --key "$HOME/.omega-x/cap-key.pem" --thermal-file "$THERMAL_SENSOR" --disk "$HOME" > "$HOME/.omega-cap/fresh.json"

Optional --cgroup points to the applicable cgroup v2 directory (memory.max, memory.current). Model IDs and capabilities remain operator declarations, not inferred proof of model files.

Append these options to the existing tools/phaseexec.py or tools/phasechat.py invocation (before -- and before the executable in phaseexec):

    --runtime-envelope "$HOME/.omega-cap/fresh.json" --runtime-policy "$HOME/.omega-cap/policy.json" --runtime-db "$HOME/.omega-cap/runtime-replay.sqlite" --thermal-file "$THERMAL_SENSOR"

Optionally add --runtime-cgroup and --runtime-ttl (1..300 seconds, default 120). THERMAL_SENSOR must be set by the operator to the correct readable sensor. Partial config is refused. Use a fresh envelope per task; do not reuse a declaration already consumed by admission. A distinct replay DB for planning vs execution is appropriate only when each has its own security boundary; keep both private. Pin the node key, trust and capacity policy. The existing plan must already pass LeaseStore verification; node/task IDs must match. A different priority or trust class is rejected. Headroom may not be less than the original plan.

Supervisor checks before lease claim, before child spawn, every ~1 s while executing and immediately before publication. Expiration, missing telemetry or pressure causes RUNTIME_GUARD and existing process termination / lease failure paths. During execution, only headroom is required, preventing double-counting the task RAM already allocated. The gate uses an elapsed-time deadline after signature verification; there is currently no renewal, so long tasks exceeding the remaining signed TTL fail closed. The monitored disk is the working filesystem; output size is checked against declared capacity before execution, not a hard quota or a separate CAS filesystem reservation.

This mode is optional for backward compatibility. No mandatory protection of legacy direct entry points is claimed. Killing the PHASECHAT client does not guarantee cancellation of inference already running in llama-server. The gate is not a container sandbox or a distributed lease, and it does not prove physical telemetry. Do not use arbitrary sensor paths or remote supplied configuration as trusted operator inputs.

Verification: 10 CAPCTL and 12 telemetry/gate tests (real OpenSSL and SQLite, controlled telemetry fixtures), 4 subprocess tests (real child process, controlled lease/CAS doubles). Exact tested supervisor/module/test sources matched via Git blob hashes. CLI wiring is reviewed but not executed in full repository in this runner; direct git clone fails DNS. Previous reports remain historical. No mobile, GPU, cloud or production execution claims.

    python3 -m unittest discover -s tests -p 'test_runtime_gate.py' -v
    python3 -m unittest discover -s tests -p 'test_gate_execution.py' -v
    bash tools/verify.sh
