"""
Storage policy: optional size limit and retention window for the local SQLite store.

Both default to 0 = unlimited / keep forever, so nothing is deleted unless an operator
opts in (Settings screen, or STORAGE_LIMIT_GB / RETENTION_DAYS env vars). Pruning is
oldest-first and never removes an anomalous event whose alert is not yet Resolved.
"""
import asyncio
import os
import shutil
from typing import Any, Dict

from .config import config
from .db import db

GB = 1024 ** 3


def get_policy() -> Dict[str, Any]:
    limit = db.get_setting("storage_limit_gb")
    retention = db.get_setting("retention_days")
    return {
        "storage_limit_gb": float(limit) if limit is not None else config.STORAGE_LIMIT_GB,
        "retention_days": int(retention) if retention is not None else config.RETENTION_DAYS,
    }


def set_policy(storage_limit_gb: float, retention_days: int) -> Dict[str, Any]:
    db.set_setting("storage_limit_gb", storage_limit_gb)
    db.set_setting("retention_days", retention_days)
    return get_policy()


def _dir_size(path: str) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def stats() -> Dict[str, Any]:
    s = db.storage_stats()
    db_file = sum(os.path.getsize(p) for p in (config.DB_PATH, config.DB_PATH + "-wal", config.DB_PATH + "-journal")
                  if os.path.exists(p))
    uploads = _dir_size(config.UPLOAD_DIR)
    disk = shutil.disk_usage(config.DATA_DIR)
    policy = get_policy()
    limit_bytes = int(policy["storage_limit_gb"] * GB) if policy["storage_limit_gb"] > 0 else 0
    data_bytes = s["raw_log_bytes"] + s["normalized_bytes"]
    return {
        **s,
        "db_file_bytes": db_file,
        "uploads_bytes": uploads,
        "total_bytes": db_file + uploads,
        "data_bytes": data_bytes,  # what the size limit is measured against
        "disk_total_bytes": disk.total,
        "disk_free_bytes": disk.free,
        "policy": policy,
        "limit_bytes": limit_bytes,
        "limit_used_pct": round(data_bytes / limit_bytes * 100, 1) if limit_bytes else None,
    }


def enforce(vacuum: bool = True) -> Dict[str, Any]:
    policy = get_policy()
    limit_bytes = int(policy["storage_limit_gb"] * GB) if policy["storage_limit_gb"] > 0 else 0
    by_age, by_size = db.prune(policy["retention_days"], limit_bytes)
    if vacuum and (by_age or by_size):
        db.vacuum()  # actually shrink the file on disk
    if by_age or by_size:
        print(f"[STORAGE] Pruned {by_age} events past retention, {by_size} events over size limit")
    return {"deleted_by_retention": by_age, "deleted_by_size_limit": by_size}


async def maintenance_worker():
    """Applies the storage policy periodically. No-op while both are unlimited."""
    while True:
        try:
            policy = get_policy()
            if policy["storage_limit_gb"] > 0 or policy["retention_days"] > 0:
                await asyncio.to_thread(enforce)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            print(f"[STORAGE] Maintenance error: {e}")
        await asyncio.sleep(config.STORAGE_CHECK_INTERVAL)
