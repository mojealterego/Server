# STORAGE-06 (increment) — pinned unified storage routing

A single independently pinned JSON catalog binds logical model IDs to an
Ed25519 public key, an exact model SHA-256 and enrolled SMB model replicas;
it also binds the current three-share recovery-set SHA-256 to enrolled
Rclone crypt roots. The schema is `omega.storage.fabric.v1`, with exactly
three top-level fields: `schema`, `models`, `recovery`. `models` is a map
of IDs (1..256 entries), each with `sha256`, `public_key`, `remotes` (1..8
unique SMB Rclone aliases). `recovery` has `sha256` and `remotes` (1..8
distinct crypt aliases with non-traversing paths). Use actual receipts and
keys produced by storage_cache and storage_recovery, not example hashes.

Obtain the catalog digest with `python3 -c 'import json,sys; from
atlas.storage_fabric import digest; print(digest(json.load(open(sys.argv[1]))))'
/private/fabric.json` (single command). Distribute and preserve the pin
independently through a trusted operator channel. Pin rotation is explicit;
there is no fallback to an older generation.

    python3 -m atlas.storage_fabric --catalog /private/fabric.json \
      --catalog-sha256 "$TRUSTED_FABRIC_PIN" stage-model --model qwen \
      --manifest /private/qwen-signed.json --cache /private/model-cache

    python3 -m atlas.storage_fabric --catalog /private/fabric.json \
      --catalog-sha256 "$TRUSTED_FABRIC_PIN" restore \
      --receipt /private/recovery-set.json --vault /private/storage-cas \
      --dest /private/recovered

The first path delegates to the existing signed model stage/cache (signed
manifest verification, pinned SHA-256, bounded block reads, per-block
verified replica failover); the second validates the pinned recovery set,
checks configured crypt remote types, and delegates to the existing
three-share verified offline restore. The catalog rejects unknown IDs,
wrong pins, duplicate aliases and path injection. Receipt identity is
checked on return. Private cache, storage CAS and live shares remain
separate. The service's existing signed SMB2 compatibility share,
encrypted SMB3 secure share and read-only model policy are unchanged.

The operator must maintain trusted Rclone config and independent pins.
A remote alias alone is not proof of its SMB transport, host identity or
independent failure domain. This increment does not automatically mount
storage, promote a live share, manage ACL/quota/GC/retention, provide
transparent SMB failover or qualify physical devices/providers. Local
routing tests used controlled adapter doubles; actual upstream cache and
recovery adapters were inspected but not exercised in this increment.

## SMB backend preflight

On the first attempted range read from each alias, the production Fabric
reader checks `rclone config redacted <alias>`; the command must be supported
by the installed Rclone. It requires a single matching INI section with
type=smb, rejects external remote type environment overrides, caps output
at 64 KiB and uses a 10-second deadline. The output is never logged.
An unsuccessful alias is excluded for the current staging invocation;
retry with a new invocation after repair. Cache hits use no remote config
probe. This is configuration validation, not proof of SMB dialect or
transport security; the Rclone executable, environment and config are
trusted and must not change during staging. See
https://rclone.org/commands/rclone_config_redacted/.

## Model staging qualification increment

The default stage path now inherits the serial verified-replica
preference documented in [STORAGE_CACHE.md](STORAGE_CACHE.md). Two
focused integration cases execute the real Fabric, storage_cache and
Merkle implementations, real OpenSSL Ed25519 operations, private files
and subprocess Rclone fixtures. They verify backend rejection, replica
fallback, verified offline cache reuse and no publication when all
replicas fail. These do not establish actual SMB dialect negotiation,
physical replica independence or real Rclone/provider operation.
Recovery-generation integration and existing external gates stay open.
