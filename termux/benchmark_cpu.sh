#!/data/data/com.termux/files/usr/bin/bash
# Run actual local CPU throughput tests; no invented tokens/sec.
set -Eeuo pipefail
MODEL_DIR="${OMEGA_MODEL_DIR:-$HOME/storage/shared/1.GGUF-UNCENSORED}"
MODEL="${1:-}"
[[ -f "$MODEL" && "$MODEL" == *.gguf ]] || {
  echo "Usage: $0 /absolute/path/model.gguf" >&2; exit 2;
}
BENCH="${LLAMA_BENCH_BIN:-$HOME/llama.cpp/build/bin/llama-bench}"
[[ -x "$BENCH" ]] || { echo "Missing executable: $BENCH" >&2; exit 1; }
LOGDIR="$HOME/.omega-x/benchmarks"
mkdir -p "$LOGDIR"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
for threads in 2 4 6; do
  echo "[OMEGA] Benchmark CPU threads=$threads; output=$LOGDIR/$stamp-t$threads.txt"
  "$BENCH" -m "$MODEL" -t "$threads" -p 128 -n 64 \
     > "$LOGDIR/$stamp-t$threads.txt" 2>&1
done
printf 'Saved benchmark evidence in %s\n' "$LOGDIR"
