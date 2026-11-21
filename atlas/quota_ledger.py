"""E13: SQLite WAL resource reservations with epoch fencing and uncertain-write quarantine.

One trusted LOCAL filesystem and one SQLite writer authority only. Not an etcd
replacement and not a distributed global billing guard. No automatic refunds
on ambiguous provider outcomes.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import time
from typing import Iterator, Mapping

FIELDS = ("storage_bytes", "write_bytes", "read_bytes", "write_ops", "read_ops", "egress_bytes")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
MAX = 2**63 - 1


class QuotaError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise QuotaError(message)


def counters(data: Mapping[str, int]) -> tuple[int, ...]:
    require(isinstance(data, dict) and set(data) == set(FIELDS), "All six budget counters required")
    require(all(type(data[field]) is int and 0 <= data[field] <= MAX for field in FIELDS),
            "Invalid budget counter")
    return tuple(data[field] for field in FIELDS)


def safe_id(value: str) -> bool:
    return isinstance(value, str) and IDENT.fullmatch(value) is not None


def private_parent(path: Path) -> None:
    path = Path(path)
    require(path.is_absolute() and not path.is_symlink() and
            path.parent.is_dir() and not path.parent.is_symlink(), "Unsafe ledger path")
    st = path.parent.stat()
    require(st.st_uid == os.getuid() and st.st_mode & 0o077 == 0,
            "Ledger parent must be private (0700)")
    if path.exists():
        st = path.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and st.st_mode & 0o077 == 0,
                "Ledger must be a private regular file")
    # A SQLite WAL on NFS/SMB cannot serve as a cross-host coordination primitive.
    if sys.platform == "linux" and Path("/proc/self/mountinfo").exists():
        root = path.parent.resolve()
        mount = ""
        fstype = ""
        for line in Path("/proc/self/mountinfo").read_text().splitlines():
            left, sep, right = line.partition(" - ")
            if not sep:
                continue
            mountpoint = left.split()[4].replace("\\040", " ")
            base = Path(mountpoint)
            if root == base or base in root.parents:
                if len(mountpoint) > len(mount):
                    mount = mountpoint
                    fstype = right.split()[0]
        require(fstype not in {"cifs", "smb3", "nfs", "nfs4", "fuse.rclone", "fuse.sshfs"},
                "Ledger must not reside on a network filesystem")


class Ledger:
    def __init__(self, filename: Path):
        self.path = Path(filename)
        private_parent(self.path)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        private_parent(self.path)
        conn = sqlite3.connect(str(self.path), timeout=5, isolation_level=None)
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        except FileExistsError:
            private_parent(self.path)
        conn = self._connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("CREATE TABLE IF NOT EXISTS clock (id INTEGER PRIMARY KEY CHECK(id=1), last_now INTEGER NOT NULL)")
            conn.execute("INSERT OR IGNORE INTO clock(id,last_now) VALUES(1,0)")
            columns = ", ".join(f"max_{k} INTEGER NOT NULL, spent_{k} INTEGER NOT NULL DEFAULT 0" for k in FIELDS)
            conn.execute("CREATE TABLE IF NOT EXISTS pools (id TEXT PRIMARY KEY, epoch INTEGER NOT NULL, " + columns + ")")
            fields = ", ".join(f"{k} INTEGER NOT NULL" for k in FIELDS)
            conn.execute("CREATE TABLE IF NOT EXISTS reservations (pool TEXT NOT NULL REFERENCES pools(id), request TEXT NOT NULL, epoch INTEGER NOT NULL, state TEXT NOT NULL, expires INTEGER NOT NULL, " + fields + ", PRIMARY KEY(pool, request))")
            conn.execute("CREATE INDEX IF NOT EXISTS reservations_state ON reservations(pool,state)")
        finally:
            conn.close()
        private_parent(self.path)

    @contextmanager
    def _tx(self, now: int) -> Iterator[sqlite3.Connection]:
        require(type(now) is int and 0 <= now <= MAX, "Invalid UTC epoch")
        conn = self._connect()
        try:
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("BEGIN IMMEDIATE")
            current = conn.execute("SELECT last_now FROM clock WHERE id=1").fetchone()[0]
            require(now >= current, "Clock moved backwards; refuse budget reuse")
            conn.execute("UPDATE clock SET last_now=? WHERE id=1", (now,))
            # Expiry is not a refund: after a crash or a lost reply, uploaded bytes may exist.
            conn.execute("UPDATE reservations SET state='UNCERTAIN' WHERE state='HELD' AND expires<=?", (now,))
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def enroll(self, pool: str, limits: dict[str, int], *, epoch: int = 1, now: int) -> None:
        require(safe_id(pool) and type(epoch) is int and 1 <= epoch <= MAX, "Invalid pool/epoch")
        values = counters(limits)
        with self._tx(now) as conn:
            old = conn.execute("SELECT * FROM pools WHERE id=?", (pool,)).fetchone()
            if old:
                require(old[1] == epoch and tuple(old[2:][::2]) == values,
                        "Existing pool limits cannot be overwritten silently")
                return
            cols = ",".join(f"max_{k}" for k in FIELDS)
            conn.execute(f"INSERT INTO pools(id,epoch,{cols}) VALUES(?,?,{','.join('?' for _ in FIELDS)})",
                         (pool, epoch, *values))

    def fence(self, pool: str, current_epoch: int, new_epoch: int, *, now: int) -> None:
        require(safe_id(pool) and type(current_epoch) is int and type(new_epoch) is int
                and 1 <= current_epoch < new_epoch <= MAX, "Invalid fence transition")
        with self._tx(now) as conn:
            result = conn.execute("UPDATE pools SET epoch=? WHERE id=? AND epoch=?",
                                  (new_epoch, pool, current_epoch))
            require(result.rowcount == 1, "Fenced epoch not current")

    def reserve(self, pool: str, request: str, amount: dict[str, int], *, epoch: int,
                ttl: int, now: int) -> dict[str, object]:
        require(safe_id(pool) and safe_id(request) and type(epoch) is int and epoch > 0,
                "Invalid reservation identity")
        require(type(ttl) is int and 1 <= ttl <= 86400 and now <= MAX - ttl, "Invalid TTL")
        amounts = counters(amount)
        require(any(amounts), "Zero-resource reservation not permitted")
        with self._tx(now) as conn:
            row = conn.execute("SELECT epoch," + ",".join(f"max_{k},spent_{k}" for k in FIELDS)
                               + " FROM pools WHERE id=?", (pool,)).fetchone()
            require(row is not None and row[0] == epoch, "Pool absent or stale writer epoch")
            existing = conn.execute("SELECT epoch,state,expires," + ",".join(FIELDS)
                                    + " FROM reservations WHERE pool=? AND request=?", (pool, request)).fetchone()
            if existing:
                require(existing[0] == epoch and tuple(existing[3:]) == amounts,
                        "Idempotency key reused for different allocation")
                require(existing[1] in ("HELD", "COMMITTED"), "Reservation uncertain or released")
                return {"pool": pool, "request": request, "state": existing[1], "expires": existing[2]}
            totals = [0] * len(FIELDS)
            held = conn.execute("SELECT " + ",".join(FIELDS)
                                + " FROM reservations WHERE pool=? AND state IN ('HELD','UNCERTAIN')", (pool,))
            for reservation in held:
                for i, v in enumerate(reservation):
                    totals[i] += v
            for i, requested in enumerate(amounts):
                limit, spent = row[1 + i*2:3 + i*2]
                require(spent + totals[i] + requested <= limit, "Provider quota exhausted: " + FIELDS[i])
            conn.execute("INSERT INTO reservations(pool,request,epoch,state,expires," + ",".join(FIELDS)
                         + ") VALUES(?,?,?,'HELD',? ," + ",".join('?' for _ in FIELDS) + ")",
                         (pool, request, epoch, now + ttl, *amounts))
            return {"pool": pool, "request": request, "state": "HELD", "expires": now + ttl}

    def require_active(self, pool: str, request: str, *, epoch: int, now: int) -> None:
        """Admission check immediately before an external side effect."""
        require(safe_id(pool) and safe_id(request), "Invalid reservation key")
        with self._tx(now) as conn:
            owner = conn.execute("SELECT epoch FROM pools WHERE id=?", (pool,)).fetchone()
            row = conn.execute("SELECT state,expires,epoch FROM reservations WHERE pool=? AND request=?",
                               (pool, request)).fetchone()
            require(owner is not None and owner[0] == epoch and row is not None and
                    row[0] == "HELD" and row[1] > now and row[2] == epoch,
                    "No active quota authorization")

    def renew(self, pool: str, request: str, *, epoch: int, ttl: int, now: int) -> int:
        require(safe_id(pool) and safe_id(request) and type(ttl) is int and
                1 <= ttl <= 86400 and now <= MAX - ttl, "Invalid renewal")
        with self._tx(now) as conn:
            owner = conn.execute("SELECT epoch FROM pools WHERE id=?", (pool,)).fetchone()
            row = conn.execute("SELECT state,expires,epoch FROM reservations WHERE pool=? AND request=?",
                               (pool, request)).fetchone()
            require(owner is not None and owner[0] == epoch and row is not None and
                    row[0] == "HELD" and row[1] > now and row[2] == epoch,
                    "Cannot renew expired or fenced quota")
            expiry = max(row[1], now + ttl)
            conn.execute("UPDATE reservations SET expires=? WHERE pool=? AND request=?",
                         (expiry, pool, request))
            return expiry

    def commit(self, pool: str, request: str, *, epoch: int, now: int) -> str:
        require(safe_id(pool) and safe_id(request) and type(epoch) is int and epoch > 0,
                "Invalid commit identity")
        with self._tx(now) as conn:
            current = conn.execute("SELECT epoch FROM pools WHERE id=?", (pool,)).fetchone()
            require(current is not None and current[0] == epoch, "Stale writer epoch")
            row = conn.execute("SELECT state,expires," + ",".join(FIELDS)
                               + " FROM reservations WHERE pool=? AND request=? AND epoch=?",
                               (pool, request, epoch)).fetchone()
            require(row is not None and row[0] in ("HELD", "COMMITTED") and
                    (row[0] == "COMMITTED" or row[1] > now), "Missing/uncertain reservation")
            if row[0] == "COMMITTED":
                return "COMMITTED"
            for key, value in zip(FIELDS, row[2:]):
                conn.execute(f"UPDATE pools SET spent_{key}=spent_{key}+? WHERE id=?", (value, pool))
            conn.execute("UPDATE reservations SET state='COMMITTED' WHERE pool=? AND request=?",
                         (pool, request))
            return "COMMITTED"

    def uncertain(self, pool: str, request: str, *, epoch: int, now: int) -> None:
        require(safe_id(pool) and safe_id(request), "Invalid identity")
        with self._tx(now) as conn:
            current = conn.execute("SELECT epoch FROM pools WHERE id=?", (pool,)).fetchone()
            require(current is not None and current[0] == epoch, "Stale writer epoch")
            row = conn.execute("UPDATE reservations SET state='UNCERTAIN' WHERE pool=? AND request=? AND epoch=? AND state='HELD'",
                               (pool, request, epoch))
            require(row.rowcount == 1, "Reservation not currently held")

    def reconcile(self, pool: str, request: str, *, epoch: int, outcome: str,
                  confirmed: bool, now: int) -> str:
        require(safe_id(pool) and safe_id(request) and outcome in ("ABSENT", "COMMITTED")
                and confirmed is True, "Explicit operator reconciliation required")
        with self._tx(now) as conn:
            current = conn.execute("SELECT epoch FROM pools WHERE id=?", (pool,)).fetchone()
            require(current is not None and current[0] == epoch, "Stale writer epoch")
            row = conn.execute("SELECT state," + ",".join(FIELDS)
                               + " FROM reservations WHERE pool=? AND request=?", (pool, request)).fetchone()
            require(row is not None and row[0] == "UNCERTAIN", "Only uncertain writes can be reconciled")
            if outcome == "COMMITTED":
                for key, value in zip(FIELDS, row[1:]):
                    conn.execute(f"UPDATE pools SET spent_{key}=spent_{key}+? WHERE id=?", (value, pool))
            state = "RELEASED" if outcome == "ABSENT" else "COMMITTED"
            conn.execute("UPDATE reservations SET state=? WHERE pool=? AND request=?",
                         (state, pool, request))
            return state

    def release_unwritten(self, pool: str, request: str, *, epoch: int,
                          no_side_effects: bool, now: int) -> None:
        require(safe_id(pool) and safe_id(request) and no_side_effects is True,
                "Release requires proof of no started external operations")
        with self._tx(now) as conn:
            current = conn.execute("SELECT epoch FROM pools WHERE id=?", (pool,)).fetchone()
            require(current is not None and current[0] == epoch, "Stale writer epoch")
            result = conn.execute("UPDATE reservations SET state='RELEASED' WHERE pool=? AND request=? AND epoch=? AND state='HELD' AND expires>?",
                                  (pool, request, epoch, now))
            require(result.rowcount == 1, "Cannot release a started or uncertain write")

    def status(self, pool: str, *, now: int) -> dict[str, object]:
        require(safe_id(pool), "Invalid pool")
        with self._tx(now) as conn:
            row = conn.execute("SELECT epoch," + ",".join(f"max_{k},spent_{k}" for k in FIELDS)
                               + " FROM pools WHERE id=?", (pool,)).fetchone()
            require(row is not None, "Unknown pool")
            holds = [0]*len(FIELDS)
            for values in conn.execute("SELECT " + ",".join(FIELDS)
                                       + " FROM reservations WHERE pool=? AND state IN ('HELD','UNCERTAIN')", (pool,)):
                for i, value in enumerate(values):
                    holds[i] += value
            return {"pool": pool, "epoch": row[0], "available": {
                key: row[i*2+1] - row[i*2+2] - holds[i] for i, key in enumerate(FIELDS)
            }, "uncertain_count": conn.execute(
                "SELECT COUNT(*) FROM reservations WHERE pool=? AND state='UNCERTAIN'", (pool,)).fetchone()[0]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    enroll = commands.add_parser("enroll")
    enroll.add_argument("--pool", required=True)
    enroll.add_argument("--limits", required=True, type=Path)
    enroll.add_argument("--epoch", type=int, default=1)
    status = commands.add_parser("status")
    status.add_argument("--pool", required=True)
    args = parser.parse_args(argv)
    try:
        ledger = Ledger(args.database)
        now = int(time.time())
        if args.command == "enroll":
            limits = json.loads(args.limits.read_text())
            ledger.enroll(args.pool, limits, epoch=args.epoch, now=now)
            result = ledger.status(args.pool, now=now)
        else:
            result = ledger.status(args.pool, now=now)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, TypeError, OSError, sqlite3.Error) as exc:
        print("LEDGER ERROR: " + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
