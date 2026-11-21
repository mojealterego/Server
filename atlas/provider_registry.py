"""E12: pinned, operator-authorized provider registry with read-only Rclone preflight.

Quota observations are advisory. This module never initiates a remote write or OAuth grant.
"""
from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit
from typing import Any

SCHEMA = "omega.provider-registry.v1"
ALIAS = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
BACKENDS: dict[str, str] = {
    "google_drive": "drive",
    "onedrive": "onedrive",
    "dropbox": "dropbox",
    "backblaze_b2": "b2",
    "cloudflare_r2": "s3",
    "generic_s3": "s3",
    "webdav": "webdav",
}
MAX_DOCUMENT = 1_048_576
MAX_RESPONSE = 65_536


class ProviderError(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ProviderError(message)


def bounded_json(path: Path) -> dict[str, Any]:
    def pairs_unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result

    with Path(path).open("rb") as inp:
        raw = inp.read(MAX_DOCUMENT + 1)
    require(len(raw) <= MAX_DOCUMENT, "Registry too large")
    try:
        obj = json.loads(raw, object_pairs_hook=pairs_unique)
    except (ValueError, TypeError) as exc:
        raise ProviderError("Invalid registry JSON") from exc
    require(isinstance(obj, dict), "Expected JSON object")
    return obj


def canonical(data: dict[str, Any]) -> bytes:
    try:
        result = json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (ValueError, TypeError) as exc:
        raise ProviderError("Invalid document") from exc
    require(len(result) <= MAX_DOCUMENT, "Registry exceeds limit")
    return result


def digest(data: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(data)).hexdigest()


def validate(registry: dict[str, Any]) -> dict[str, Any]:
    require(isinstance(registry, dict) and set(registry) == {"schema", "max_age_seconds", "providers"}
            and registry["schema"] == SCHEMA, "Invalid provider registry schema")
    ttl = registry["max_age_seconds"]
    require(type(ttl) is int and 1 <= ttl <= 86400, "Invalid maximum age")
    rows = registry["providers"]
    require(isinstance(rows, list) and 1 <= len(rows) <= 64, "Expected 1..64 providers")
    ids: set[str] = set()
    accounts: set[str] = set()
    aliases: set[str] = set()
    for row in rows:
        require(isinstance(row, dict) and set(row) == {"id", "provider", "account", "domain", "alias",
                "authorized", "free_tier_attested", "write_enabled", "limit_bytes",
                "reserve_bytes", "monthly_write_bytes", "monthly_read_bytes", "monthly_operations", "attested_at"},
                "Invalid provider fields")
        for field in ("id", "account", "domain"):
            require(isinstance(row[field], str) and IDENT.fullmatch(row[field]), "Unsafe provider identifier")
        require(row["id"] not in ids and row["account"] not in accounts,
                "Duplicate provider or underlying account quota")
        ids.add(row["id"])
        accounts.add(row["account"])
        if row["provider"] == "terabox":
            require(row["alias"] is None and row["write_enabled"] is False,
                    "TeraBox official adapter is not yet enrolled")
        else:
            require(row["provider"] in BACKENDS and isinstance(row["alias"], str)
                    and ALIAS.fullmatch(row["alias"]), "Unsupported Rclone adapter")
            require(row["alias"] not in aliases, "Duplicate Rclone alias")
            aliases.add(row["alias"])
        require(all(type(row[k]) is bool for k in ("authorized", "free_tier_attested", "write_enabled")),
                "Operator flags must be boolean")
        require(all(type(row[k]) is int and 0 <= row[k] <= 2**63 - 1
                    for k in ("limit_bytes", "reserve_bytes", "monthly_write_bytes",
                              "monthly_read_bytes", "monthly_operations", "attested_at")), "Invalid provider budgets")
        require(row["reserve_bytes"] <= row["limit_bytes"], "Reserve exceeds limit")
        require(not row["write_enabled"] or (row["authorized"] and row["free_tier_attested"]),
                "Write enablement requires explicit operator attestations")
    canonical(registry)
    return registry


def private_config(path: Path) -> Path:
    path = Path(path)
    require(path.is_absolute() and not path.is_symlink(), "Rclone configuration must be an absolute regular file")
    st = path.stat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid()
            and st.st_mode & 0o077 == 0, "Rclone configuration must be owned and private")
    return path


def command(argv: list[str], *, config: Path, timeout: int = 12,
            executable: str = "rclone", extra_env: dict[str, str] | None = None,
            max_output: int = MAX_RESPONSE) -> bytes:
    """Bounded read-only subprocess; process-group kill also terminates descendants."""
    require(type(timeout) is int and 1 <= timeout <= 30, "Invalid subprocess timeout")
    require(type(max_output) is int and 1 <= max_output <= 32 * 1024 * 1024,
            "Invalid maximum subprocess output")
    conf = private_config(config)
    env = dict(os.environ if extra_env is None else extra_env)
    # Prevent injected backend/credentials from overriding a pinned configuration.
    require(not any(k.upper().startswith("RCLONE_") and k.upper() != "RCLONE_CONFIG_PASS"
                    for k in env), "Rclone environment overrides forbidden")
    try:
        proc = subprocess.Popen([executable, "--config", str(conf), *argv],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env=env, start_new_session=True)
    except OSError as exc:
        raise ProviderError("Rclone unavailable") from exc
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            assert proc.stdout is not None
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                left = deadline - time.monotonic()
                require(left > 0 and bool(selector.select(left)), "Rclone timeout")
                piece = os.read(proc.stdout.fileno(), min(8192, max_output + 1 - len(output)))
                if not piece:
                    break
                output.extend(piece)
                require(len(output) <= max_output, "Rclone output too large")
        require(proc.wait(timeout=max(0.001, deadline - time.monotonic())) == 0,
                "Rclone command failed")
        return bytes(output)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProviderError("Rclone command failed") from exc
    finally:
        if proc.poll() is None:
            import signal
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        if proc.stdout:
            proc.stdout.close()


def check_remote(row: dict[str, Any], *, config: Path, executable: str = "rclone",
                 timeout: int = 12, extra_env: dict[str, str] | None = None) -> tuple[int, int]:
    """Check Rclone backend and finite quota; this does not establish cost-free status."""
    alias = row["alias"]
    require(alias is not None and row["provider"] in BACKENDS, "No supported adapter")
    raw = command(["config", "redacted", alias], config=config, executable=executable,
                  timeout=timeout, extra_env=extra_env)
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(raw.decode("utf-8"))
    except (configparser.Error, UnicodeError) as exc:
        raise ProviderError("Invalid Rclone backend configuration") from exc
    require(not parser.defaults() and parser.sections() == [alias]
            and parser.get(alias, "type", fallback="") == BACKENDS[row["provider"]],
            "Configured remote backend does not match registry")
    if row["provider"] == "cloudflare_r2":
        # Rclone's 's3' type alone can silently point at a billable AWS bucket.
        require(parser.get(alias, "provider", fallback="") == "Cloudflare",
                "Expected Cloudflare R2 provider")
        endpoint = parser.get(alias, "endpoint", fallback="")
        try:
            parsed = urlsplit(endpoint)
            port = parsed.port
        except ValueError as exc:
            raise ProviderError("Invalid Cloudflare endpoint") from exc
        require(parsed.scheme == "https" and port is None and
                parsed.username is None and parsed.password is None and
                not parsed.path and not parsed.query and not parsed.fragment and
                re.fullmatch(r"[0-9a-f]{32}(?:\.eu)?\.r2\.cloudflarestorage\.com", parsed.hostname or ""),
                "Cloudflare R2 endpoint mismatch")
    raw_quota = command(["about", alias + ":", "--json"], config=config,
                        executable=executable, timeout=timeout, extra_env=extra_env)
    try:
        limits = json.loads(raw_quota)
    except (ValueError, UnicodeError) as exc:
        raise ProviderError("Invalid Rclone quota response") from exc
    require(isinstance(limits, dict) and all(type(limits.get(k)) is int and
            0 <= limits[k] <= 2**63 - 1 for k in ("total", "free")),
            "Unknown, unlimited or invalid quota")
    require(limits["free"] <= limits["total"], "Invalid free quota")
    if "used" in limits:
        used = limits["used"]
        require(type(used) is int and 0 <= used <= limits["total"], "Invalid used quota")
        free = min(limits["free"], limits["total"] - used)
    else:
        free = limits["free"]
    return limits["total"], free


def inspect(registry: dict[str, Any], expected_pin: str, *, now: int,
            config: Path | None = None, executable: str = "rclone",
            timeout: int = 12, extra_env: dict[str, str] | None = None) -> dict[str, Any]:
    validate(registry)
    require(isinstance(expected_pin, str) and re.fullmatch(r"[0-9a-f]{64}", expected_pin)
            and digest(registry) == expected_pin, "Provider registry pin mismatch")
    require(type(now) is int and 0 <= now <= 2**63 - 1, "Invalid inspection time")
    results: dict[str, Any] = {}
    for row in registry["providers"]:
        key = row["id"]
        if row["provider"] == "terabox":
            results[key] = {"status": "BLOCKED_OFFICIAL_OAUTH", "available_bytes": 0}
        elif not row["authorized"] or not row["free_tier_attested"]:
            results[key] = {"status": "BLOCKED_OPERATOR_AUTH", "available_bytes": 0}
        elif not 0 <= now - row["attested_at"] <= registry["max_age_seconds"]:
            results[key] = {"status": "BLOCKED_STALE_ATTESTATION", "available_bytes": 0}
        elif config is None:
            results[key] = {"status": "BLOCKED_NO_CONFIG", "available_bytes": 0}
        else:
            try:
                total, free = check_remote(row, config=config, executable=executable,
                                           timeout=timeout, extra_env=extra_env)
                usable = max(0, min(free, row["limit_bytes"] - row["reserve_bytes"],
                                    row["monthly_write_bytes"], row["monthly_read_bytes"]))
                status = "ENROLLED_READ_ONLY" if usable and row["monthly_operations"] > 0 else "BLOCKED_NO_QUOTA"
                results[key] = {"status": status, "available_bytes": usable,
                                "reported_total_bytes": total, "observed_at": now,
                                "write_opt_in": row["write_enabled"]}
            except (ProviderError, OSError):
                results[key] = {"status": "BLOCKED_PROBE", "available_bytes": 0}
    return {"schema": "omega.providers.inspection.v1", "registry_sha256": expected_pin,
            "checked_at": now, "providers": results}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--registry", required=True, type=Path)
    ap.add_argument("--registry-sha256", required=True)
    ap.add_argument("--config", type=Path)
    args = ap.parse_args(argv)
    try:
        print(json.dumps(inspect(bounded_json(args.registry), args.registry_sha256,
                                 now=int(time.time()), config=args.config), sort_keys=True))
        return 0
    except (ProviderError, OSError, TypeError) as exc:
        print("PROVIDER REGISTRY ERROR: " + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
