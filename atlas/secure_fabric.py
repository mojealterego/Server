"""E14: authenticated AES-256-GCM chunk archives with opt-in Rclone providers.

The built-in store is private local CAS. Remote writes require a pinned registry,
operator authorization AND a quota reservation. No key or cookie is stored in a
manifest. Cross-provider availability, charges and failure domains need real E2E.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from . import provider_registry as providers
from . import quota_ledger as quotas

SCHEMA = "omega.secure-fabric.v1"
MAGIC = b"OMEGA14\x00"
HEX = re.compile(r"[0-9a-f]{64}\Z")
ARCHIVE = re.compile(r"[0-9a-f]{32}\Z")


def valid_hex(value: object) -> bool:
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def valid_archive(value: object) -> bool:
    return isinstance(value, str) and ARCHIVE.fullmatch(value) is not None
MIN_BLOCK = 64 * 1024
MAX_BLOCK = 16 * 1024 * 1024
MAX_BLOCKS = 65536
MAX_MANIFEST = 16 * 1024 * 1024
MAX_FILE = MAX_BLOCK * MAX_BLOCKS


class SecureError(ValueError):
    pass


def require(value: bool, message: str) -> None:
    if not value:
        raise SecureError(message)


def canon(doc: Any) -> bytes:
    try:
        raw = json.dumps(doc, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (TypeError, ValueError) as exc:
        raise SecureError("Invalid secure manifest") from exc
    require(len(raw) <= MAX_MANIFEST, "Manifest exceeds size limit")
    return raw


def hexdigest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as inp:
        while piece := inp.read(1024 * 1024):
            size += len(piece)
            h.update(piece)
    return h.hexdigest(), size


def private_key(path: Path) -> bytes:
    p = Path(path)
    require(p.is_absolute() and not p.is_symlink(), "Key path must be absolute and private")
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid()
                and st.st_nlink == 1 and st.st_mode & 0o077 == 0 and st.st_size == 32,
                "Invalid private root key")
        raw = os.read(fd, 33)
        require(len(raw) == 32, "Invalid root key length")
        return raw
    finally:
        os.close(fd)


def subkeys(root: bytes) -> tuple[bytes, bytes]:
    require(type(root) is bytes and len(root) == 32, "AES key must be 32 random bytes")
    return (hmac.digest(root, b"OMEGA-E14-DATA-v1", "sha256"),
            hmac.digest(root, b"OMEGA-E14-MANIFEST-v1", "sha256"))


def _aad(archive_id: str, index: int, policy_pin: str, length: int) -> bytes:
    return canon([SCHEMA, archive_id, index, policy_pin, length])


def encrypt_chunk(key: bytes, archive_id: str, index: int, pin: str, plain: bytes) -> bytes:
    require(ARCHIVE.fullmatch(archive_id) and type(index) is int and index >= 0
            and HEX.fullmatch(pin) and isinstance(plain, bytes) and 0 < len(plain) <= MAX_BLOCK,
            "Invalid chunk encryption input")
    nonce = os.urandom(12)
    data_key = hmac.digest(key, b"OMEGA-E14-DATA-v1:" + bytes.fromhex(archive_id), "sha256")
    return MAGIC + nonce + AESGCM(data_key).encrypt(nonce, plain, _aad(archive_id, index, pin, len(plain)))


def decrypt_chunk(key: bytes, archive_id: str, index: int, pin: str,
                  payload: bytes, plain_length: int) -> bytes:
    require(isinstance(payload, bytes) and type(plain_length) is int and
            0 < plain_length <= MAX_BLOCK and len(payload) == plain_length + len(MAGIC) + 28
            and payload.startswith(MAGIC), "Invalid ciphertext frame")
    data_key = hmac.digest(key, b"OMEGA-E14-DATA-v1:" + bytes.fromhex(archive_id), "sha256")
    return AESGCM(data_key).decrypt(payload[len(MAGIC):len(MAGIC)+12],
                                      payload[len(MAGIC)+12:],
                                      _aad(archive_id, index, pin, plain_length))


def sign_manifest(doc: dict[str, Any], root: bytes) -> dict[str, Any]:
    require(isinstance(doc, dict) and "mac" not in doc, "Invalid unsigned manifest")
    _, key = subkeys(root)
    mac = hmac.new(key, canon(doc), hashlib.sha256).hexdigest()
    return {**doc, "mac": mac}


def validate_manifest(doc: dict[str, Any], root: bytes, pin: str) -> None:
    require(isinstance(doc, dict) and set(doc) == {"schema", "archive", "policy_sha256",
            "size_bytes", "chunk_bytes", "sha256", "key_id", "stores", "blocks", "mac"},
            "Invalid manifest fields")
    require(doc["schema"] == SCHEMA and isinstance(pin, str) and HEX.fullmatch(pin),
            "Invalid manifest schema or pin")
    require(valid_archive(doc["archive"]) and valid_hex(doc["policy_sha256"])
            and valid_hex(doc["sha256"]), "Invalid manifest identity")
    require(type(doc["size_bytes"]) is int and 0 < doc["size_bytes"] <= MAX_FILE and
            type(doc["chunk_bytes"]) is int and MIN_BLOCK <= doc["chunk_bytes"] <= MAX_BLOCK,
            "Invalid manifest geometry")
    require(doc["key_id"] == hexdigest(root)[:16], "Wrong encryption root key")
    unsigned = {k: v for k, v in doc.items() if k != "mac"}
    _, mk = subkeys(root)
    expected = hmac.new(mk, canon(unsigned), hashlib.sha256).hexdigest()
    require(isinstance(doc["mac"], str) and hmac.compare_digest(doc["mac"], expected),
            "Manifest authenticity check failed")
    require(hmac.compare_digest(hexdigest(canon(doc)), pin), "External manifest pin mismatch")
    require(isinstance(doc["stores"], dict) and 1 <= len(doc["stores"]) <= 16,
            "Invalid store inventory")
    for name, meta in doc["stores"].items():
        require(isinstance(name, str) and providers.IDENT.fullmatch(name) and
                isinstance(meta, dict) and set(meta) == {"domain", "adapter"}
                and isinstance(meta["domain"], str) and providers.IDENT.fullmatch(meta["domain"])
                and meta["adapter"] in ("local", "rclone"), "Invalid store declaration")
    blocks = doc["blocks"]
    require(isinstance(blocks, list) and 1 <= len(blocks) <= MAX_BLOCKS, "Invalid block list")
    consumed = 0
    all_pools: set[str] = set()
    for index, block in enumerate(blocks):
        require(isinstance(block, dict) and set(block) == {"index", "length", "plain_sha256",
                "cipher_sha256", "pools"}, "Invalid block fields")
        n = block["length"]
        require(type(block["index"]) is int and block["index"] == index
                and type(n) is int and n == min(doc["chunk_bytes"], doc["size_bytes"] - consumed)
                and n > 0, "Block geometry mismatch")
        require(valid_hex(block["plain_sha256"]) and valid_hex(block["cipher_sha256"]),
                "Invalid block digest")
        pools = block["pools"]
        require(isinstance(pools, list) and len(pools) >= 2 and len(pools) <= len(doc["stores"])
                and all(isinstance(x, str) and x in doc["stores"] for x in pools)
                and len(set(pools)) == len(pools),
                "Invalid replica set")
        require(len({doc["stores"][pool]["domain"] for pool in pools}) == len(pools),
                "Replicas share a failure domain")
        all_pools.update(pools)
        consumed += n
    require(consumed == doc["size_bytes"] and all_pools == set(doc["stores"]),
            "Incomplete archive or unused pool")


class LocalStore:
    def __init__(self, root: Path, *, pool: str, domain: str):
        self.pool = pool
        self.domain = domain
        self.adapter = "local"
        require(providers.IDENT.fullmatch(pool) and providers.IDENT.fullmatch(domain), "Invalid store identity")
        self.root = Path(root)
        require(self.root.is_dir() and not self.root.is_symlink(), "Missing local store")
        st = self.root.stat()
        require(st.st_uid == os.getuid() and st.st_mode & 0o077 == 0, "Store must be private")
        self.objects = self.root / "objects"
        self.objects.mkdir(mode=0o700, exist_ok=True)
        require(self.objects.is_dir() and not self.objects.is_symlink() and
                self.objects.stat().st_mode & 0o077 == 0, "Unsafe object store")

    def put(self, archive: str, index: int, digest: str, data: bytes) -> None:
        require(HEX.fullmatch(digest) and hexdigest(data) == digest, "Invalid ciphertext digest")
        target = self.objects / digest
        fd, tempname = tempfile.mkstemp(prefix=".pending-", dir=self.objects)
        try:
            with os.fdopen(fd, "wb") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(tempname, target, follow_symlinks=False)
            except FileExistsError:
                require(self.get(archive, index, digest, len(data)) == data,
                        "Existing object has invalid content")
            _fsync_dir(self.objects)
        finally:
            Path(tempname).unlink(missing_ok=True)

    def get(self, archive: str, index: int, digest: str, size: int) -> bytes:
        require(HEX.fullmatch(digest) and type(size) is int and 1 <= size <= MAX_BLOCK + len(MAGIC) + 28,
                "Invalid object request")
        path = self.objects / digest
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            st = os.fstat(fd)
            require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size == size,
                    "Unsafe object")
            with os.fdopen(os.dup(fd), "rb") as handle:
                content = handle.read(size + 1)
            require(len(content) == size and hexdigest(content) == digest, "Ciphertext integrity check failed")
            return content
        finally:
            os.close(fd)


def _fsync_dir(root: Path) -> None:
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class RcloneStore:
    """Production adapter guarded by E12 enrollment and E13 durable quotas."""
    def __init__(self, *, pool: str, domain: str, alias: str, row: dict[str, Any],
                 config: Path, registry: dict[str, Any], registry_pin: str,
                 ledger: quotas.Ledger, epoch: int, permit_remote: bool,
                 executable: str = "rclone"):
        require(permit_remote is True and row["write_enabled"] is True and
                row["authorized"] is True and row["free_tier_attested"] is True,
                "Explicit remote write authorization required")
        require(pool == row["id"] and domain == row["domain"] and alias == row["alias"],
                "Remote identity mismatch")
        providers.validate(registry)
        require(providers.digest(registry) == registry_pin and row in registry["providers"],
                "Registry not pinned")
        self.pool, self.domain, self.adapter = pool, domain, "rclone"
        self.alias, self.config, self.executable = alias, config, executable
        self.ledger, self.epoch = ledger, epoch
        outcome = providers.inspect(registry, registry_pin, now=int(time.time()),
                                    config=config, executable=executable)
        require(outcome["providers"][pool]["status"] == "ENROLLED_READ_ONLY", "Remote not enrolled")
        require(outcome["providers"][pool]["write_opt_in"] is True, "Remote write opt-in absent")

    def _object(self, archive: str, index: int, digest: str) -> str:
        require(ARCHIVE.fullmatch(archive) and type(index) is int and 0 <= index < MAX_BLOCKS
                and HEX.fullmatch(digest), "Invalid remote object name")
        return f"{self.alias}:omega-secure/v1/{archive}/{index:08x}-{digest}.enc"

    def put(self, archive: str, index: int, digest: str, data: bytes) -> None:
        require(hexdigest(data) == digest, "Invalid remote ciphertext")
        self.ledger.require_active(self.pool, archive, epoch=self.epoch, now=int(time.time()))
        with tempfile.TemporaryDirectory(prefix="omega-crypt-") as temporary:
            path = Path(temporary) / "chunk.enc"
            path.write_bytes(data)
            path.chmod(0o600)
            # Any error after this call starts is an ambiguous remote side effect.
            providers.command(["copyto", str(path), self._object(archive, index, digest), "--no-traverse"],
                              config=self.config, timeout=30, executable=self.executable)

    def get(self, archive: str, index: int, digest: str, size: int,
            *, prepaid: bool = False) -> bytes:
        now = int(time.time())
        if prepaid:
            self.ledger.require_active(self.pool, archive, epoch=self.epoch, now=now)
            return self._download(archive, index, digest, size)
        request = hexdigest(f"read:{archive}:{index}:{self.pool}:{uuid.uuid4().hex}".encode())
        counters = {field: 0 for field in quotas.FIELDS}
        counters.update(read_bytes=size, read_ops=1, egress_bytes=size)
        self.ledger.reserve(self.pool, request, counters, epoch=self.epoch, ttl=30, now=now)
        try:
            data = self._download(archive, index, digest, size)
            self.ledger.commit(self.pool, request, epoch=self.epoch, now=int(time.time()))
            return data
        except BaseException:
            try:
                self.ledger.uncertain(self.pool, request, epoch=self.epoch, now=int(time.time()))
            except (quotas.QuotaError, OSError):
                pass
            raise

    def _download(self, archive: str, index: int, digest: str, size: int) -> bytes:
        data = providers.command(["cat", self._object(archive, index, digest)], config=self.config,
                                 timeout=30, executable=self.executable, max_output=size)
        require(len(data) == size and hexdigest(data) == digest, "Remote ciphertext corrupted")
        return data


def _read_key(key_path: Path) -> bytes:
    return private_key(key_path)


def _store_info(stores: dict[str, Any]) -> dict[str, dict[str, str]]:
    require(isinstance(stores, dict) and 2 <= len(stores) <= 16, "Need at least two providers")
    result = {}
    for name, store in stores.items():
        require(providers.IDENT.fullmatch(name) and store.pool == name
                and providers.IDENT.fullmatch(store.domain) and store.adapter in ("local", "rclone"),
                "Invalid provider enrollment")
        result[name] = {"domain": store.domain, "adapter": store.adapter}
    require(len({s["domain"] for s in result.values()}) == len(result),
            "Requested replica stores must have distinct domains")
    return result


def ingest(source: Path, manifest: Path, *, key_path: Path, policy_sha256: str,
           stores: dict[str, Any], ledger: quotas.Ledger, epoch: int,
           archive_id: str, chunk_bytes: int = 4 * 1024 * 1024,
           copies: int = 2, now: int | None = None) -> dict[str, object]:
    """Read bounded plaintext chunks; persist authenticated replicas before manifest."""
    require(HEX.fullmatch(policy_sha256) and ARCHIVE.fullmatch(archive_id), "Invalid archive/policy pin")
    require(type(chunk_bytes) is int and MIN_BLOCK <= chunk_bytes <= MAX_BLOCK and
            type(copies) is int and 2 <= copies <= 3, "Invalid chunk geometry/copies")
    info = _store_info(stores)
    require(len(stores) >= copies, "Insufficient independent stores")
    source, manifest = Path(source), Path(manifest)
    require(not source.is_symlink() and source.is_file(), "Unsafe source file")
    require(manifest.parent.is_dir() and not manifest.parent.is_symlink() and
            manifest.parent.stat().st_uid == os.getuid() and
            manifest.parent.stat().st_mode & 0o077 == 0 and
            not manifest.exists() and not manifest.is_symlink(), "Manifest parent must be private and target absent")
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    source_stat = os.fstat(source_fd)
    try:
        require(stat.S_ISREG(source_stat.st_mode), "Source must be regular")
        size = source_stat.st_size
    finally:
        os.close(source_fd)
    require(0 < size <= MAX_FILE and (size + chunk_bytes - 1)//chunk_bytes <= MAX_BLOCKS,
            "Archive outside supported size")
    root = _read_key(key_path)
    blocks = []
    file_hash = hashlib.sha256()
    counter_by_pool = {name: {k: 0 for k in quotas.FIELDS} for name in stores}
    # Reserve worst-case ciphertext bytes and readback operations before any write.
    for i in range((size + chunk_bytes - 1)//chunk_bytes):
        length = min(chunk_bytes, size - i*chunk_bytes)
        ciphertext = length + len(MAGIC) + 28
        names = list(stores)[:copies]
        for name in names:
            record = counter_by_pool[name]
            record["storage_bytes"] += ciphertext
            record["write_bytes"] += ciphertext
            record["read_bytes"] += ciphertext
            record["egress_bytes"] += ciphertext
            record["write_ops"] += 1
            record["read_ops"] += 1
    clock = (lambda: int(time.time())) if now is None else (lambda: now)
    ts = clock()
    reserved: list[str] = []
    touched = False
    last_renewal = ts
    try:
        for name, amounts in counter_by_pool.items():
            if amounts["write_ops"]:
                ticket = ledger.reserve(name, archive_id, amounts, epoch=epoch, ttl=3600, now=ts)
                require(ticket["state"] == "HELD", "Archive request already committed")
                reserved.append(name)
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            require((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) ==
                    (source_stat.st_dev, source_stat.st_ino, source_stat.st_size, source_stat.st_mtime_ns),
                    "Source swapped since admission")
            with os.fdopen(os.dup(fd), "rb") as inp:
                for index in range((size + chunk_bytes - 1)//chunk_bytes):
                    current = clock()
                    if current - last_renewal >= 600:
                        for pool in reserved:
                            ledger.renew(pool, archive_id, epoch=epoch, ttl=3600, now=current)
                        last_renewal = current
                    plain = inp.read(min(chunk_bytes, size - index*chunk_bytes))
                    require(plain, "Source truncated")
                    file_hash.update(plain)
                    payload = encrypt_chunk(root, archive_id, index, policy_sha256, plain)
                    digest = hexdigest(payload)
                    names = list(stores)[:copies]
                    for name in names:
                        touched = True
                        stores[name].put(archive_id, index, digest, payload)
                        if stores[name].adapter == "rclone":
                            readback = stores[name].get(archive_id, index, digest, len(payload), prepaid=True)
                        else:
                            readback = stores[name].get(archive_id, index, digest, len(payload))
                        require(hmac.compare_digest(readback, payload), "Readback mismatch")
                    blocks.append({"index": index, "length": len(plain), "plain_sha256": hexdigest(plain),
                                   "cipher_sha256": digest, "pools": names})
                require(not inp.read(1), "Source grew during ingest")
            check = os.fstat(fd)
        finally:
            os.close(fd)
        require((check.st_dev, check.st_ino, check.st_size, check.st_mtime_ns) ==
                (source_stat.st_dev, source_stat.st_ino, source_stat.st_size, source_stat.st_mtime_ns),
                "Source changed during ingest")
        used = {pool for b in blocks for pool in b["pools"]}
        content = {k: v for k, v in info.items() if k in used}
        doc = {"schema": SCHEMA, "archive": archive_id, "policy_sha256": policy_sha256,
               "size_bytes": size, "chunk_bytes": chunk_bytes, "sha256": file_hash.hexdigest(),
               "key_id": hexdigest(root)[:16], "stores": content, "blocks": blocks}
        signed = sign_manifest(doc, root)
        pin = hexdigest(canon(signed))
        validate_manifest(signed, root, pin)
        # Budget is charged before publication: crash is conservative, not a free upload.
        for pool in reserved:
            ledger.commit(pool, archive_id, epoch=epoch, now=clock())
        raw = canon(signed)
        fd, tmppath = tempfile.mkstemp(prefix=".omega-e14-", dir=manifest.parent)
        try:
            with os.fdopen(fd, "wb") as output:
                os.fchmod(output.fileno(), 0o600)
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            os.link(tmppath, manifest, follow_symlinks=False)
            _fsync_dir(manifest.parent)
        finally:
            Path(tmppath).unlink(missing_ok=True)
        return {"sha256": file_hash.hexdigest(), "manifest_sha256": pin,
                "chunks": len(blocks), "copies": copies, "status": "STAGED_ENCRYPTED"}
    except BaseException:
        for pool in reserved:
            try:
                if not touched:
                    ledger.release_unwritten(pool, archive_id, epoch=epoch,
                                             no_side_effects=True, now=ts)
                else:
                    ledger.uncertain(pool, archive_id, epoch=epoch, now=ts)
            except (quotas.QuotaError, OSError):
                pass  # Existing committed reservations stay spent; reconcile other states.
        raise


def _read_manifest(path: Path) -> bytes:
    """Bounded no-follow manifest read; never block on a special file."""
    path = Path(path)
    require(not path.is_symlink() and path.is_file(), "Manifest must be a regular file")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise SecureError("Cannot open manifest safely") from exc
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and before.st_nlink == 1 and not before.st_mode & 0o077
                and 0 < before.st_size <= MAX_MANIFEST, "Manifest is unsafe or too large")
        with os.fdopen(os.dup(fd), "rb") as source:
            raw = source.read(MAX_MANIFEST + 1)
        after = os.fstat(fd)
        require(len(raw) == before.st_size and
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                "Manifest changed while reading")
        return raw
    finally:
        os.close(fd)


def restore(manifest: Path, pin: str, destination: Path, *, key_path: Path,
            stores: dict[str, Any], ledger: quotas.Ledger | None = None,
            epoch: int | None = None, now: int | None = None) -> dict[str, object]:
    raw_manifest = _read_manifest(manifest)
    root = _read_key(key_path)
    try:
        def unique(pairs):
            result = {}
            for k, v in pairs:
                require(k not in result, "Duplicate manifest key")
                result[k] = v
            return result
        doc = json.loads(raw_manifest, object_pairs_hook=unique,
                         parse_constant=lambda _: (_ for _ in ()).throw(SecureError("Non-finite JSON")))
    except (ValueError, UnicodeError) as exc:
        raise SecureError("Invalid signed manifest") from exc
    validate_manifest(doc, root, pin)
    destination = Path(destination)
    require(destination.parent.is_dir() and not destination.parent.is_symlink() and
            destination.parent.stat().st_uid == os.getuid() and
            destination.parent.stat().st_mode & 0o077 == 0 and
            not destination.exists() and not destination.is_symlink(), "Refusing unsafe destination/overwrite")
    require(isinstance(stores, dict) and stores, "No enrolled recovery stores")
    for pool, store in stores.items():
        require(pool in doc["stores"] and store.pool == pool and
                store.domain == doc["stores"][pool]["domain"] and
                store.adapter == doc["stores"][pool]["adapter"], "Recovery store identity changed")
    full = hashlib.sha256()
    fd, tmppath = tempfile.mkstemp(prefix=".omega-e14-restore-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            os.fchmod(out.fileno(), 0o600)
            for block in doc["blocks"]:
                n = block["length"]
                for pool in block["pools"]:
                    if pool not in stores:
                        continue
                    try:
                        # Remote read-side budgeting is an operator requirement.
                        require(stores[pool].adapter == "local" or ledger is not None,
                                "Remote reads require quota ledger")
                        payload = stores[pool].get(doc["archive"], block["index"],
                                                   block["cipher_sha256"], n + len(MAGIC) + 28)
                        plain = decrypt_chunk(root, doc["archive"], block["index"],
                                              doc["policy_sha256"], payload, n)
                        require(hexdigest(plain) == block["plain_sha256"], "Bad plaintext digest")
                        break
                    except (OSError, SecureError, ValueError, InvalidTag, subprocess.SubprocessError):
                        continue
                else:
                    raise SecureError("No authenticated replica for block " + str(block["index"]))
                out.write(plain)
                full.update(plain)
            out.flush()
            os.fsync(out.fileno())
        require(full.hexdigest() == doc["sha256"] and os.stat(tmppath).st_size == doc["size_bytes"],
                "Restored archive digest mismatch")
        os.link(tmppath, destination, follow_symlinks=False)
        _fsync_dir(destination.parent)
        return {"sha256": doc["sha256"], "size_bytes": doc["size_bytes"], "status": "RESTORED_AUTHENTICATED"}
    finally:
        Path(tmppath).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--ledger", required=True, type=Path)
    parser.add_argument("--stores", required=True, type=Path,
                        help="JSON mapping pool ID to {path,domain}; local-only CLI")
    parser.add_argument("--epoch", required=True, type=int)
    commands = parser.add_subparsers(dest="command", required=True)
    ingest_cmd = commands.add_parser("ingest")
    ingest_cmd.add_argument("--source", required=True, type=Path)
    ingest_cmd.add_argument("--policy-sha256", required=True)
    ingest_cmd.add_argument("--archive-id", required=True)
    ingest_cmd.add_argument("--chunk-bytes", type=int, default=4*1024*1024)
    ingest_cmd.add_argument("--copies", type=int, default=2)
    restore_cmd = commands.add_parser("restore")
    restore_cmd.add_argument("--pin", required=True)
    restore_cmd.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        rows = providers.bounded_json(args.stores)
        stores = {name: LocalStore(Path(item["path"]), pool=name, domain=item["domain"])
                  for name, item in rows.items()}
        ledger = quotas.Ledger(args.ledger)
        if args.command == "ingest":
            result = ingest(args.source, args.manifest, key_path=args.key,
                            policy_sha256=args.policy_sha256, stores=stores, ledger=ledger,
                            epoch=args.epoch, archive_id=args.archive_id,
                            chunk_bytes=args.chunk_bytes, copies=args.copies)
        else:
            result = restore(args.manifest, args.pin, args.destination,
                             key_path=args.key, stores=stores, ledger=ledger, epoch=args.epoch)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (SecureError, quotas.QuotaError, providers.ProviderError, OSError, ValueError, TypeError,
            KeyError, subprocess.SubprocessError) as exc:
        print("SECURE FABRIC ERROR: " + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
