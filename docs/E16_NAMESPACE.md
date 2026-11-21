# E16a: transactional, fenced namespace for archive references

**Implemented scope:** a single-host, SQLite WAL + synchronous=FULL index for
logical file paths pointing to immutable E14/E15 manifest pins, not a writable
SMB filesystem or direct archive data plane. It does not mount a filesystem,
provide POSIX/SMB byte-range locks, materialize a share, or authenticate remote
users. Existing Samba `omega-secure` and `omega-models` are unchanged.

- Case-insensitive ASCII names matching a conservative cross-platform subset.
  Relative paths only; rejects traversal, symlinks, control characters,
  reserved Windows DOS device names, trailing dot and ambiguous case collisions.
- Each namespace handle is bound to one **trusted** tenant identity; caller
  authorization must occur before instantiating this class. No network API or
  tenant authentication is implemented. Private (0700) OS directory and database
  file 0600; do not share the DB over SMB/NFS.
- `put`, `rename` and `delete` use `BEGIN IMMEDIATE`, per-entry revision CAS,
  persisted tombstones and one-time idempotency operation IDs. A replay of the
  identical mutation in the same authority epoch returns its previous receipt;
  conflicting replays fail. Different tenants have distinct logical keyspaces.
- Monotonic local epoch fencing revokes stale callers **on the same database**.
  There is no quorum, physical fencing or immunity to copying/restoring an old
  database; E20 is still required to prevent split brain/rollback.
- Manifest SHA-256, archive SHA-256 and policy SHA-256 are externally supplied
  *pins*, not proof of source authenticity. An E15 HMAC/signature verifier must
  validate the actual manifest before use. Metadata delete never garbage
  collects encrypted archival data. No filesystem share is automatically exposed.

Example on a trusted operator host:

```bash
umask 077
mkdir -m 700 -p "$HOME/.omega-x/namespace"
python -m atlas.global_namespace --db "$HOME/.omega-x/namespace/meta.sqlite" \
  --tenant omega put models/qwen.gguf --manifest "$MANIFEST_PIN" \
  --archive "$ARCHIVE_SHA256" --policy "$POLICY_SHA256" --bytes 1048576 \
  --epoch 1 --expect 0 --op operator-001
python -m atlas.global_namespace --db "$HOME/.omega-x/namespace/meta.sqlite" \
  --tenant omega get models/qwen.gguf
```

**Acceptance:** 12 focused tests plus one real subprocess namespace CLI test,
including a concurrent 6-writer compare-and-swap race. Physical SMB2/SMB3
read/write and crash testing, metadata-to-E15 restore integration, real locking,
versioned ACLs, cross-host fencing, Windows ACL semantics and large file
I/O remain **BLOCKED / NOT_RUN**. The repository already contains a separate
Samba SMB2/SMB3 gateway; no compatibility or production qualification is claimed.
