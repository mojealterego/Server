# STORAGE-02 — signed SMB model cache (development)

A mobile or desktop worker can stage verified weights from the read-only
omega-models share in a local private filesystem. It does not mount SMB as a
kernel filesystem or mmap remote files. Existing SMB compatibility and secure
shares are unchanged.

## Enrollment and trust

Publish only stable, operator-authorized model files on one or more separately
configured SMB remotes. Keep the manifest signing key offline and private
(0600); do not reuse TLS/worker keys. The signing function computes full
SHA-256 and 4 MiB Merkle blocks locally and signs the canonical manifest with
Ed25519. The signer must trust the source bytes and keep the file stable while
hashing; the signature is not evidence of model lineage, format internals,
license or inference compatibility.

From the repository root on the publisher host:

    umask 077
    openssl genpkey -algorithm ED25519 -out model-sign.pem
    chmod 600 model-sign.pem
    python3 -m atlas.storage_cache sign --source /private/model.gguf --key model-sign.pem > model.manifest.json

Generate the key once; the openssl command can overwrite an existing key.
Distribute the public key (base64 DER SPKI) and expected model SHA-256 via a
trusted independent catalog or administrative channel. Do not trust either
pin merely because it arrives alongside the model/manifest. Each manifest
covers one nonempty GGUF, safetensors, SFT or ONNX file, up to 32 GiB.
The catalog pin selects the intended version. The manifest is not a
multi-model transactional bundle and has no independent revocation or expiry.

On Termux install Python, OpenSSL and Rclone. Configure the SMB remotes
interactively as described in SMB_STORAGE.md; use the encrypted SMB3
omega-models share. Never weaken its encryption requirement to fit a client.
The cache module accepts named Rclone aliases, not arbitrary remote paths;
the operator must ensure each alias actually uses the intended authenticated
SMB backend and approved endpoint. Do not place the cache in Android shared
storage. Example:

    mkdir -p "$HOME/.omega-x/model-cache"
    chmod 700 "$HOME/.omega-x/model-cache"
    python3 -m atlas.storage_cache stage --manifest model.manifest.json \
      --public-key "$MODEL_SIGNER_SPKI" --sha256 "$MODEL_SHA256" \
      --cache "$HOME/.omega-x/model-cache" \
      --remote omega-smb --remote omega-smb-backup

Use distinct configured aliases if two replicas actually exist; one alias is
also supported. Use the returned path as the operator-provided local model
path in the deployment configuration or llama-server invocation. This is an
explicit staging step, not automatic worker cache admission. The cache
does not move or delete existing phone files.

## Recovery and limits

The module verifies the signed manifest and independent expected SHA before
reading data. Each block attempts the enrolled replicas in order and accepts
only exact length and hash. The external Rclone process has a size-bounded
stdout and a deadline; failed or corrupt sources are skipped. The existing
Merkle implementation rehashes partial bytes on retry and verifies the entire
file before no-overwrite publication. An already-cached file is reverified
without a network download. Cache locking serializes staging in this private
cache; no cache eviction, quota enforcement, open-file lease, global deadline
or automatic shared-store repair is implemented. Disk admission conservatively
requires full model size plus 512 MiB by default even when a partial file exists.
The operator may lower the reserve explicitly with --reserve-mib. Do not
remove lock/partial files while active. There is no remote model loading,
direct CIFS mount or guarantee that the deployed Rclone negotiates SMB3.
Physical transport qualification remains a separate gate.

Tests: 8 focused host cases with real Ed25519/OpenSSL, local filesystem,
controlled range readers and subprocess stand-ins for Rclone. Tests cover
signature and version pin, corrupt first replica, verified resume, cache hits,
conflicting final files, private path/bad alias rejection, disk reserve,
oversized range, timeout and valid subprocess range read. Python compiled.
No physical Samba, Rclone SMB, Android or AI inference test was performed.
