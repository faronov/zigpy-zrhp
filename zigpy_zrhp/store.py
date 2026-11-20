"""Sidecar host store ``zigbee_zrhp.db`` next to zigpy's ``zigbee.db`` (spec 8.8, 12.1).

SQLite with WAL and ``synchronous=FULL``: a ``TBL_WRITEBACK`` is acknowledged
only after its transaction is durable. All database work runs on one
dedicated worker thread so the event loop never blocks on ``fsync``.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import dataclasses
import json
import logging
import pathlib
import secrets
import sqlite3
import time
from typing import Any

LOGGER = logging.getLogger(__name__)

SIDECAR_NAME = "zigbee_zrhp.db"
SCHEMA_VERSION = 1
#: Floors passed to ``NWK_INIT`` are the last logged limit + 9 strides (8.4).
FLOOR_STRIDES = 9

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS link_keys (
    ieee BLOB PRIMARY KEY,
    key BLOB,
    type INTEGER NOT NULL DEFAULT 1,
    attrs INTEGER NOT NULL DEFAULT 2,
    origin INTEGER NOT NULL DEFAULT 2,
    key_seq INTEGER NOT NULL DEFAULT 0,
    rx_floor INTEGER NOT NULL DEFAULT 0,
    rev INTEGER NOT NULL DEFAULT 0,
    nwk INTEGER,
    updated REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS fc_checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain INTEGER NOT NULL,
    key_seq INTEGER NOT NULL,
    "limit" INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    time REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS gp_shadow (
    gpd_id BLOB PRIMARY KEY,
    record BLOB NOT NULL,
    updated REAL NOT NULL
);
"""


@dataclasses.dataclass
class LinkKeyRow:
    ieee: bytes
    key: bytes | None
    type: int = 1
    attrs: int = 2
    origin: int = 2
    key_seq: int = 0
    rx_floor: int = 0
    rev: int = 0
    nwk: int | None = None


def sidecar_path(database_path: str | None) -> str:
    """``zigbee_zrhp.db`` in the directory of zigpy's database (``:memory:`` if none)."""
    if not database_path:
        return ":memory:"
    return str(pathlib.Path(database_path).resolve().parent / SIDECAR_NAME)


class SidecarStore:
    """The ZRHP host store. Use the ``async`` methods from the event loop."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._db: sqlite3.Connection | None = None
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="zigpy-zrhp-db"
        )

    # --- Plumbing -------------------------------------------------------------

    async def _run(self, fn, *args):
        return await asyncio.get_running_loop().run_in_executor(self._executor, fn, *args)

    async def open(self) -> None:
        await self._run(self._open)

    def _open(self) -> None:
        db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        if self.path != ":memory:":
            db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.executescript(_SCHEMA)
        self._db = db
        if self._meta_get("schema_version") is None:
            self._meta_set_many(
                {
                    "schema_version": SCHEMA_VERSION,
                    "host_db_epoch": secrets.randbits(32) or 1,
                    "host_max_rev": 0,
                }
            )

    async def close(self) -> None:
        def close() -> None:
            if self._db is not None:
                self._db.close()
                self._db = None

        await self._run(close)
        self._executor.shutdown(wait=True)

    @property
    def db(self) -> sqlite3.Connection:
        if self._db is None:
            raise RuntimeError("store is not open")
        return self._db

    # --- meta -------------------------------------------------------------------

    def _meta_get(self, key: str) -> Any:
        row = self.db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else json.loads(row[0])

    def _meta_set_many(self, values: dict[str, Any]) -> None:
        db = self.db
        db.execute("BEGIN IMMEDIATE")
        try:
            for k, v in values.items():
                db.execute(
                    "INSERT INTO meta(key, value) VALUES(?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (k, json.dumps(v)),
                )
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise

    async def meta(self, key: str, default: Any = None) -> Any:
        value = await self._run(self._meta_get, key)
        return default if value is None else value

    async def set_meta(self, **values: Any) -> None:
        await self._run(self._meta_set_many, values)

    # --- link keys (TBL_WRITEBACK / TBL_LOOKUP) -------------------------------

    def _upsert_key(self, row: LinkKeyRow) -> bool:
        db = self.db
        db.execute("BEGIN IMMEDIATE")
        try:
            cur = db.execute("SELECT rev, rx_floor, key FROM link_keys WHERE ieee = ?", (row.ieee,))
            old = cur.fetchone()
            if old is not None and row.rev and old[0] >= row.rev and old[2] is not None:
                # I4: stale writeback; keep the higher floor anyway (I3).
                db.execute(
                    "UPDATE link_keys SET rx_floor = MAX(rx_floor, ?), updated = ? WHERE ieee = ?",
                    (row.rx_floor, time.time(), row.ieee),
                )
                db.execute("COMMIT")
                return False
            rx_floor = max(row.rx_floor, old[1] if old else 0)
            key = row.key if row.key is not None else (old[2] if old else None)
            db.execute(
                "INSERT INTO link_keys(ieee, key, type, attrs, origin, key_seq, rx_floor, rev, nwk, updated) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(ieee) DO UPDATE SET "
                "key = excluded.key, type = excluded.type, attrs = excluded.attrs, "
                "origin = excluded.origin, key_seq = excluded.key_seq, "
                "rx_floor = excluded.rx_floor, rev = excluded.rev, "
                "nwk = COALESCE(excluded.nwk, link_keys.nwk), updated = excluded.updated",
                (
                    row.ieee,
                    key,
                    row.type,
                    row.attrs,
                    row.origin,
                    row.key_seq,
                    rx_floor,
                    row.rev,
                    row.nwk,
                    time.time(),
                ),
            )
            cur = db.execute("SELECT value FROM meta WHERE key = 'host_max_rev'")
            max_rev = json.loads(cur.fetchone()[0])
            if row.rev > max_rev:
                db.execute(
                    "UPDATE meta SET value = ? WHERE key = 'host_max_rev'", (json.dumps(row.rev),)
                )
            db.execute("COMMIT")
            return True
        except BaseException:
            db.execute("ROLLBACK")
            raise

    async def upsert_link_key(self, row: LinkKeyRow) -> bool:
        """Durably store a key; ``False`` if the write was stale (I4)."""
        return await self._run(self._upsert_key, row)

    async def upsert_link_keys(self, rows: list[LinkKeyRow]) -> None:
        def run() -> None:
            for r in rows:
                self._upsert_key(r)

        await self._run(run)

    def _get_key(self, ieee: bytes | None, nwk: int | None) -> LinkKeyRow | None:
        if ieee is not None:
            cur = self.db.execute("SELECT * FROM link_keys WHERE ieee = ?", (ieee,))
        else:
            cur = self.db.execute("SELECT * FROM link_keys WHERE nwk = ?", (nwk,))
        row = cur.fetchone()
        if row is None:
            return None
        return LinkKeyRow(*row[:9])

    async def get_link_key(
        self, ieee: bytes | None = None, nwk: int | None = None
    ) -> LinkKeyRow | None:
        return await self._run(self._get_key, ieee, nwk)

    async def all_link_keys(self) -> list[LinkKeyRow]:
        def run() -> list[LinkKeyRow]:
            return [LinkKeyRow(*r[:9]) for r in self.db.execute("SELECT * FROM link_keys")]

        return await self._run(run)

    async def delete_link_key(self, ieee: bytes) -> None:
        await self._run(lambda: self.db.execute("DELETE FROM link_keys WHERE ieee = ?", (ieee,)))

    async def clear_network(self) -> None:
        """Forget per-network host tables (after ``NWK_LEAVE_RESET``)."""

        def run() -> None:
            db = self.db
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM link_keys")
            db.execute("DELETE FROM gp_shadow")
            db.execute("COMMIT")

        await self._run(run)

    # --- frame-counter checkpoints (8.4) ----------------------------------------

    async def add_checkpoint(self, domain: int, key_seq: int, limit: int, generation: int) -> None:
        def run() -> None:
            db = self.db
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                'INSERT INTO fc_checkpoints(domain, key_seq, "limit", generation, time) VALUES(?,?,?,?,?)',
                (domain, key_seq, limit, generation, time.time()),
            )
            db.execute(
                "DELETE FROM fc_checkpoints WHERE domain = ? AND id NOT IN "
                "(SELECT id FROM fc_checkpoints WHERE domain = ? ORDER BY id DESC LIMIT 64)",
                (domain, domain),
            )
            db.execute("COMMIT")

        await self._run(run)

    async def last_limit(self, domain: int) -> int:
        def run() -> int:
            row = self.db.execute(
                'SELECT MAX("limit") FROM fc_checkpoints WHERE domain = ?', (domain,)
            ).fetchone()
            return int(row[0] or 0)

        return await self._run(run)

    async def floors(self, stride: int) -> tuple[int, int]:
        """``(nwk_fc_floor, aps_fc_floor)`` for ``NWK_INIT`` (0 = none)."""
        nwk = await self.last_limit(1)
        aps = await self.last_limit(2)
        return (
            min(0xFFFFFFFF, nwk + FLOOR_STRIDES * stride) if nwk else 0,
            min(0xFFFFFFFF, aps + FLOOR_STRIDES * stride) if aps else 0,
        )

    # --- GP shadow ----------------------------------------------------------------

    async def gp_put(self, gpd_id: bytes, record: bytes) -> None:
        await self._run(
            lambda: self.db.execute(
                "INSERT INTO gp_shadow(gpd_id, record, updated) VALUES(?,?,?) "
                "ON CONFLICT(gpd_id) DO UPDATE SET record = excluded.record, updated = excluded.updated",
                (gpd_id, record, time.time()),
            )
        )

    async def gp_delete(self, gpd_id: bytes) -> None:
        await self._run(
            lambda: self.db.execute("DELETE FROM gp_shadow WHERE gpd_id = ?", (gpd_id,))
        )

    async def gp_all(self) -> dict[bytes, bytes]:
        return await self._run(
            lambda: dict(self.db.execute("SELECT gpd_id, record FROM gp_shadow").fetchall())
        )
