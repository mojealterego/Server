#!/data/data/com.termux/files/usr/bin/bash
# Reproducible build instructions once LLAMA_REF is pinned to a commit/tag.
# GGML_OPENCL=ON only when explicitly requested and dependencies work.
set -Eeuo pipefail
command -v pkg >/dev/null || { echo 'Run inside Termux' >&2; exit 1; }
pkg install -y git cmake ninja clang
DEST="${LLAMA_SOURCE_DIR:-$HOME/llama.cpp}"
if [[ ! -d "$DEST/.git" ]]; then
  git clone https://github.com/ggml-org/llama.cpp.git "$DEST"
fi
if [[ -n "${LLAMA_REF:-}" ]]; then
  git -C "$DEST" fetch origin "$LLAMA_REF"
  git -C "$DEST" checkout --detach FETCH_HEAD
else
  echo 'WARNING: source is not pinned. Set LLAMA_REF to commit/tag for a reproducible build.' >&2
fi
options=(-S "$DEST" -B "$DEST/build" -G Ninja -DCMAKE_BUILD_TYPE=Release)
if [[ "${OMEGA_BUILD_OPENCL:-0}" == '1' ]]; then
  options+=(-DGGML_OPENCL=ON -DGGML_OPENCL_EMBED_KERNELS=ON -DGGML_OPENCL_USE_ADRENO_KERNELS=ON)
  echo 'OpenCL requested: build fails if Android OpenCL dependencies are unavailable.'
else
  options+=(-DGGML_OPENCL=OFF)
fi
cmake "${options[@]}"
cmake --build "$DEST/build" --parallel "${OMEGA_BUILD_JOBS:-4}"
"$DEST/build/bin/llama-server" --help >/dev/null
printf 'Built llama.cpp at source commit: '
git -C "$DEST" rev-parse HEAD
