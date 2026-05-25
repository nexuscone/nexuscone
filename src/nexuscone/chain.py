"""Tamper-evident append-only audit ledger.

Every write produces a SQLite row whose entry_hash is the SHA-256 of the
canonical JSON of every other field, including previous_hash. Each new row's
previous_hash equals the prior row's entry_hash, forming an unbroken chain
anchored at a genesis row whose previous_hash is sixty-four zeros.

Writes are serialised under an asyncio lock so the tip of the chain (max
entry_id, its entry_hash) is always observed consistently by the next writer.
verify_chain walks the full table and recomputes every hash from scratch, so
any edit to a stored field, including via raw SQL, causes that row's
entry_hash check to fail and cascades into the next row's previous_hash check.

Signatures are optional. When a Signer is provided to log, the entry_hash is
also signed with Ed25519 and the signature plus signing_key_id are stored on
the row. A Verifier provided to verify_chain checks every signed row.

Chain format versions:

  format_version=1 (v0.1.0, legacy): hash inputs are entry_id, timestamp,
                                     actor, action, payload, previous_hash.
  format_version=2 (v0.2.0 and later): hash inputs are entry_id, timestamp,
                                       actor, action, event_type, payload,
                                       previous_hash. Including event_type in
                                       the hash means a tampering admin
                                       cannot change a 'request' row into a
                                       'cost_anomaly' row without detection.

New writes always use format_version=2. Legacy v0.1.0 databases continue to
verify under format_version=1; the verifier dispatches per-row.

Event types:

  Every entry carries an event_type discriminator. 'request' is the default
  and covers normal LLM/agent calls. The other types fire when an anomaly is
  detected and write their own chain entries so the audit timeline includes
  drift, scope violations, guardrail bypasses, and chain integrity breaks
  alongside ordinary traffic. The recognised types live in
  nexuscone.EVENT_TYPES; arbitrary strings are accepted at write time so
  downstream tools can extend the discriminator without forking nexuscone.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol

import aiosqlite

from nexuscone.canonical import canonical_json, sha256_hex
from nexuscone.schema import (
    ANCHORS_INDEX_CHAIN_HEAD,
    ANCHORS_INDEX_UNCONFIRMED,
    ANCHORS_TABLE_SQL,
)

GENESIS_PREVIOUS_HASH = "0" * 64

# Default event_type for ordinary write paths.
EVENT_TYPE_REQUEST = "request"

# Recognised drift / anomaly event types. Strings, not an Enum, so downstream
# tooling can extend the set without subclassing or forking. Hyperaxis writes
# these from its drift detectors; the chain treats them like any other entry.
EVENT_TYPE_SCHEMA_DRIFT = "schema_drift"
EVENT_TYPE_COST_ANOMALY = "cost_anomaly"
EVENT_TYPE_PROVIDER_DRIFT = "provider_drift"
EVENT_TYPE_GUARDRAIL_BYPASS = "guardrail_bypass"
EVENT_TYPE_UNSIGNED_PROMPT_CHANGE = "unsigned_prompt_change"
EVENT_TYPE_SCOPE_VIOLATION = "scope_violation"
EVENT_TYPE_CHAIN_BREAK = "chain_break"
EVENT_TYPE_BEHAVIOUR_DRIFT = "behaviour_drift"

EVENT_TYPES: frozenset[str] = frozenset(
    {
        EVENT_TYPE_REQUEST,
        EVENT_TYPE_SCHEMA_DRIFT,
        EVENT_TYPE_COST_ANOMALY,
        EVENT_TYPE_PROVIDER_DRIFT,
        EVENT_TYPE_GUARDRAIL_BYPASS,
        EVENT_TYPE_UNSIGNED_PROMPT_CHANGE,
        EVENT_TYPE_SCOPE_VIOLATION,
        EVENT_TYPE_CHAIN_BREAK,
        EVENT_TYPE_BEHAVIOUR_DRIFT,
    }
)

# Current chain hash format. New writes always use this version. Legacy rows
# loaded from a v0.1.0 database are verified under format_version=1.
CURRENT_FORMAT_VERSION = 2

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    entry_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    actor           TEXT    NOT NULL,
    action          TEXT    NOT NULL,
    event_type      TEXT    NOT NULL DEFAULT 'request',
    format_version  INTEGER NOT NULL DEFAULT 2,
    payload         TEXT    NOT NULL,
    previous_hash   TEXT    NOT NULL,
    entry_hash      TEXT    NOT NULL,
    signature       TEXT,
    signing_key_id  TEXT
)
"""

_INDEX_ACTOR = "CREATE INDEX IF NOT EXISTS idx_entries_actor ON entries(actor)"
_INDEX_TIMESTAMP = "CREATE INDEX IF NOT EXISTS idx_entries_ts ON entries(timestamp)"
_INDEX_EVENT_TYPE = "CREATE INDEX IF NOT EXISTS idx_entries_event_type ON entries(event_type)"


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    """A single row of the ledger, as it sits on disk after a write."""

    entry_id: int
    timestamp: str
    actor: str
    action: str
    payload: dict[str, Any]
    previous_hash: str
    entry_hash: str
    signature: str | None
    signing_key_id: str | None
    event_type: str = EVENT_TYPE_REQUEST
    format_version: int = CURRENT_FORMAT_VERSION


class Signer(Protocol):
    """Protocol any Ed25519 signer must satisfy."""

    @property
    def key_id(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


class Verifier(Protocol):
    """Protocol any Ed25519 verifier must satisfy."""

    def verify(self, key_id: str, message: bytes, signature: bytes) -> bool: ...


class ChainVerificationError(Exception):
    """Raised when verify_chain detects a hash mismatch, broken link, or bad signature."""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _compute_entry_hash(
    *,
    entry_id: int,
    timestamp: str,
    actor: str,
    action: str,
    payload_canonical: str,
    previous_hash: str,
    event_type: str,
    format_version: int,
) -> str:
    """Compute the entry hash for the given format version.

    format_version=1 (legacy v0.1.0) excludes event_type from the inputs.
    format_version=2 (v0.2.0+) includes event_type so it is covered by the
    tamper-evident chain.
    """
    fields: dict[str, Any] = {
        "entry_id": entry_id,
        "timestamp": timestamp,
        "actor": actor,
        "action": action,
        "payload": payload_canonical,
        "previous_hash": previous_hash,
    }
    if format_version >= 2:
        fields["event_type"] = event_type
    return sha256_hex(canonical_json(fields))


def _row_to_entry(row: aiosqlite.Row) -> LedgerEntry:
    return LedgerEntry(
        entry_id=int(row["entry_id"]),
        timestamp=row["timestamp"],
        actor=row["actor"],
        action=row["action"],
        payload=json.loads(row["payload"]),
        previous_hash=row["previous_hash"],
        entry_hash=row["entry_hash"],
        signature=row["signature"],
        signing_key_id=row["signing_key_id"],
        event_type=row["event_type"] if "event_type" in row.keys() else EVENT_TYPE_REQUEST,
        format_version=(
            int(row["format_version"]) if "format_version" in row.keys() else 1
        ),
    )


class Ledger:
    """Async SQLite-backed hash-chain audit ledger."""

    def __init__(self, db_path: Path | str) -> None:
        self._db_path: Path = Path(db_path)
        self._db: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()
        self._initialised = False

    async def __aenter__(self) -> Ledger:
        await self.init()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()

    async def init(self) -> None:
        """Open the database, create the entries table and indexes if missing.

        Idempotently migrates v0.1.0 databases to v0.2.0 by adding the
        event_type and format_version columns when they are missing. Legacy
        rows receive format_version=1 so they continue to verify under the
        v0.1.0 hash formula; new writes use format_version=2 explicitly.
        """
        if self._initialised:
            return
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self._db_path)
        self._db.row_factory = aiosqlite.Row
        # SQLite enforces foreign keys per connection, off by default. The
        # anchors table FK on entries(entry_id) needs this on to be useful.
        await self._db.execute("PRAGMA foreign_keys = ON")
        await self._db.execute(_SCHEMA)
        # Migrate legacy columns BEFORE creating indexes that depend on them,
        # otherwise CREATE INDEX on event_type fails on a v0.1.0 table.
        await self._migrate_legacy_columns()
        await self._db.execute(_INDEX_ACTOR)
        await self._db.execute(_INDEX_TIMESTAMP)
        await self._db.execute(_INDEX_EVENT_TYPE)
        await self._ensure_anchors_table()
        await self._db.commit()
        self._initialised = True

    async def _migrate_legacy_columns(self) -> None:
        """Add event_type and format_version columns to legacy v0.1.0 tables.

        Pre-existing rows in a v0.1.0 database are assigned format_version=1
        (so they continue to verify under the legacy hash formula) and
        event_type='request' (which does not affect the v1 hash since v1
        excludes event_type from inputs).
        """
        assert self._db is not None
        async with self._db.execute("PRAGMA table_info(entries)") as cursor:
            columns = {row["name"] for row in await cursor.fetchall()}

        if "event_type" not in columns:
            await self._db.execute(
                "ALTER TABLE entries ADD COLUMN event_type TEXT NOT NULL "
                "DEFAULT 'request'"
            )
        if "format_version" not in columns:
            # Legacy rows: format_version=1 so existing entry_hash values
            # continue to verify under the v0.1.0 hash formula.
            await self._db.execute(
                "ALTER TABLE entries ADD COLUMN format_version INTEGER NOT NULL "
                "DEFAULT 1"
            )

    async def _ensure_anchors_table(self) -> None:
        """Create the anchors table and its two indexes if missing.

        Idempotent: re-running on a database that already has the table is
        a no-op thanks to IF NOT EXISTS. The anchors table stores
        OpenTimestamps proofs that bind chain heads to Bitcoin blocks.
        """
        assert self._db is not None
        await self._db.execute(ANCHORS_TABLE_SQL)
        await self._db.execute(ANCHORS_INDEX_CHAIN_HEAD)
        await self._db.execute(ANCHORS_INDEX_UNCONFIRMED)

    async def close(self) -> None:
        """Close the underlying SQLite connection."""
        if self._db is not None:
            await self._db.close()
            self._db = None
        self._initialised = False

    async def log(
        self,
        *,
        actor: str,
        action: str,
        payload: dict[str, Any] | None = None,
        signer: Signer | None = None,
        event_type: str = EVENT_TYPE_REQUEST,
    ) -> LedgerEntry:
        """Append a new entry to the chain and return the stored row.

        event_type is a free-form string used to discriminate ordinary
        request entries from drift / anomaly entries. The well-known values
        are exposed as EVENT_TYPE_* constants in this module; callers may
        also pass custom strings for their own categorisations.
        """
        db = self._require_db()
        payload_dict: dict[str, Any] = payload or {}
        async with self._lock:
            async with db.execute(
                "SELECT entry_id, entry_hash FROM entries "
                "ORDER BY entry_id DESC LIMIT 1"
            ) as cursor:
                tip = await cursor.fetchone()

            if tip is None:
                next_id = 1
                previous_hash = GENESIS_PREVIOUS_HASH
            else:
                next_id = int(tip["entry_id"]) + 1
                previous_hash = tip["entry_hash"]

            timestamp = _utc_now_iso()
            payload_canonical = canonical_json(payload_dict)
            entry_hash = _compute_entry_hash(
                entry_id=next_id,
                timestamp=timestamp,
                actor=actor,
                action=action,
                payload_canonical=payload_canonical,
                previous_hash=previous_hash,
                event_type=event_type,
                format_version=CURRENT_FORMAT_VERSION,
            )

            signature_hex: str | None = None
            signing_key_id: str | None = None
            if signer is not None:
                signature_hex = signer.sign(entry_hash.encode("utf-8")).hex()
                signing_key_id = signer.key_id

            await db.execute(
                "INSERT INTO entries ("
                "entry_id, timestamp, actor, action, event_type, format_version, "
                "payload, previous_hash, entry_hash, signature, signing_key_id"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    next_id,
                    timestamp,
                    actor,
                    action,
                    event_type,
                    CURRENT_FORMAT_VERSION,
                    payload_canonical,
                    previous_hash,
                    entry_hash,
                    signature_hex,
                    signing_key_id,
                ),
            )
            await db.commit()

            return LedgerEntry(
                entry_id=next_id,
                timestamp=timestamp,
                actor=actor,
                action=action,
                payload=payload_dict,
                previous_hash=previous_hash,
                entry_hash=entry_hash,
                signature=signature_hex,
                signing_key_id=signing_key_id,
                event_type=event_type,
                format_version=CURRENT_FORMAT_VERSION,
            )

    async def verify_chain(self, verifier: Verifier | None = None) -> int:
        """Walk every entry, recompute hashes, raise on tamper.

        Returns the number of entries verified. When a verifier is provided,
        signed rows additionally have their Ed25519 signatures checked.
        """
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM entries ORDER BY entry_id ASC"
        ) as cursor:
            rows = list(await cursor.fetchall())

        expected_previous = GENESIS_PREVIOUS_HASH
        for row in rows:
            entry_id = int(row["entry_id"])
            stored_previous = row["previous_hash"]
            if stored_previous != expected_previous:
                raise ChainVerificationError(
                    f"entry {entry_id} previous_hash mismatch: "
                    f"expected {expected_previous}, stored {stored_previous}"
                )
            row_columns = row.keys()
            row_event_type = (
                row["event_type"] if "event_type" in row_columns else EVENT_TYPE_REQUEST
            )
            row_format_version = (
                int(row["format_version"]) if "format_version" in row_columns else 1
            )
            recomputed = _compute_entry_hash(
                entry_id=entry_id,
                timestamp=row["timestamp"],
                actor=row["actor"],
                action=row["action"],
                payload_canonical=row["payload"],
                previous_hash=stored_previous,
                event_type=row_event_type,
                format_version=row_format_version,
            )
            if recomputed != row["entry_hash"]:
                raise ChainVerificationError(
                    f"entry {entry_id} entry_hash mismatch: "
                    f"recomputed {recomputed}, stored {row['entry_hash']}"
                )
            if verifier is not None and row["signature"] is not None:
                if not verifier.verify(
                    row["signing_key_id"],
                    row["entry_hash"].encode("utf-8"),
                    bytes.fromhex(row["signature"]),
                ):
                    raise ChainVerificationError(
                        f"entry {entry_id} signature invalid for key "
                        f"{row['signing_key_id']}"
                    )
            expected_previous = row["entry_hash"]

        return len(rows)

    async def get_entry(self, entry_id: int) -> LedgerEntry:
        """Fetch a single entry by id; raises KeyError if not found."""
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM entries WHERE entry_id = ?", (entry_id,)
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            raise KeyError(f"ledger entry {entry_id} not found")
        return _row_to_entry(row)

    async def get_entries(
        self,
        *,
        actor: str | None = None,
        action: str | None = None,
        event_type: str | None = None,
        start: str | None = None,
        end: str | None = None,
        limit: int = 500,
        descending: bool = True,
    ) -> list[LedgerEntry]:
        """Fetch entries with optional filters, ordered by entry_id."""
        db = self._require_db()
        clauses: list[str] = []
        params: list[Any] = []
        if actor is not None:
            clauses.append("actor = ?")
            params.append(actor)
        if action is not None:
            clauses.append("action = ?")
            params.append(action)
        if event_type is not None:
            clauses.append("event_type = ?")
            params.append(event_type)
        if start is not None:
            clauses.append("timestamp >= ?")
            params.append(start)
        if end is not None:
            clauses.append("timestamp <= ?")
            params.append(end)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        order = "DESC" if descending else "ASC"
        query = f"SELECT * FROM entries{where} ORDER BY entry_id {order} LIMIT ?"
        params.append(int(limit))
        async with db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
        return [_row_to_entry(r) for r in rows]

    async def count(self) -> int:
        """Return the number of entries currently in the chain."""
        db = self._require_db()
        async with db.execute("SELECT COUNT(*) FROM entries") as cursor:
            row = await cursor.fetchone()
        return int(row[0]) if row is not None else 0

    def _require_db(self) -> aiosqlite.Connection:
        if self._db is None or not self._initialised:
            raise RuntimeError("Ledger.init() must be awaited before use")
        return self._db
