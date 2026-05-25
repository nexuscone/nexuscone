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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol

import aiosqlite
from opentimestamps.calendar import RemoteCalendar
from opentimestamps.core.serialize import BytesSerializationContext
from opentimestamps.core.timestamp import Timestamp

from nexuscone.anchor_schedule import AnchorSchedule
from nexuscone.anchors import AnchorRecord
from nexuscone.canonical import canonical_json, sha256_hex
from nexuscone.rfc3161 import TSAError, TSAResponse, submit_to_tsa
from nexuscone.schema import (
    ANCHORS_INDEX_CHAIN_HEAD,
    ANCHORS_INDEX_UNCONFIRMED,
    ANCHORS_TABLE_SQL,
    GENESIS_WITNESS_PREV_HASH,
    WITNESS_ATTESTATIONS_INDEX_HEAD,
    WITNESS_ATTESTATIONS_INDEX_WITNESS,
    WITNESS_ATTESTATIONS_TABLE_SQL,
    WITNESSES_INDEX_ACTIVE,
    WITNESSES_TABLE_SQL,
)
from nexuscone.witnesses import (
    WITNESS_ROLE_CONSORTIUM,
    WITNESS_ROLES,
    Witness,
    WitnessAttestation,
    WitnessVerificationError,
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


def _compute_witness_attestation_hash(
    *,
    witness_id: int,
    chain_head_entry_id: int,
    chain_head_hash: str,
    signed_at: str,
    prev_attestation_hash: str,
) -> str:
    """Hash one witness attestation over its five identifying fields.

    Canonical JSON keeps field order and separator format deterministic
    so the same five values always produce the same hex digest,
    regardless of process or platform.
    """
    return sha256_hex(
        canonical_json(
            {
                "witness_id": witness_id,
                "chain_head_entry_id": chain_head_entry_id,
                "chain_head_hash": chain_head_hash,
                "signed_at": signed_at,
                "prev_attestation_hash": prev_attestation_hash,
            }
        )
    )


def _row_to_witness(row: aiosqlite.Row) -> Witness:
    retired_raw = row["retired_at"]
    retired_at: datetime | None = (
        datetime.fromisoformat(retired_raw.replace("Z", "+00:00"))
        if retired_raw is not None
        else None
    )
    return Witness(
        witness_id=int(row["witness_id"]),
        label=row["label"],
        public_key_hex=row["public_key_hex"],
        role=row["role"],
        created_at=datetime.fromisoformat(
            row["created_at"].replace("Z", "+00:00")
        ),
        retired_at=retired_at,
    )


def _row_to_witness_attestation(row: aiosqlite.Row) -> WitnessAttestation:
    return WitnessAttestation(
        attestation_id=int(row["attestation_id"]),
        witness_id=int(row["witness_id"]),
        chain_head_entry_id=int(row["chain_head_entry_id"]),
        chain_head_hash=row["chain_head_hash"],
        signed_at=datetime.fromisoformat(
            row["signed_at"].replace("Z", "+00:00")
        ),
        prev_attestation_hash=row["prev_attestation_hash"],
        attestation_hash=row["attestation_hash"],
        signature_hex=row["signature_hex"],
    )


def _row_to_anchor(row: aiosqlite.Row) -> AnchorRecord:
    """Reconstruct an AnchorRecord from a SQLite row.

    calendar_servers is stored as JSON in TEXT; both anchor tracks
    contribute optional columns that may be NULL when one track failed
    or never ran.
    """

    def _parse_iso(value: str | None) -> datetime | None:
        if value is None:
            return None
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    return AnchorRecord(
        anchor_id=int(row["anchor_id"]),
        chain_head_hash=row["chain_head_hash"],
        chain_head_entry_id=int(row["chain_head_entry_id"]),
        submitted_at=datetime.fromisoformat(
            row["submitted_at"].replace("Z", "+00:00")
        ),
        calendar_servers=list(json.loads(row["calendar_servers"])),
        ots_proof_blob=row["ots_proof_blob"],
        confirmed_at=_parse_iso(row["confirmed_at"]),
        bitcoin_block_height=(
            int(row["bitcoin_block_height"])
            if row["bitcoin_block_height"] is not None
            else None
        ),
        bitcoin_block_hash=row["bitcoin_block_hash"],
        tst_blob=row["tst_blob"],
        tsa_url=row["tsa_url"],
        tsa_gen_time=_parse_iso(row["tsa_gen_time"]),
    )


class Ledger:
    """Async SQLite-backed hash-chain audit ledger."""

    def __init__(
        self,
        db_path: Path | str,
        *,
        anchor_schedule: AnchorSchedule | None = None,
    ) -> None:
        self._db_path: Path = Path(db_path)
        self._db: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()
        self._initialised = False
        self._anchor_schedule = anchor_schedule

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
        await self._ensure_witnesses_tables()
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

        Idempotent: re-running on a database that already has the table
        is a no-op thanks to IF NOT EXISTS. The anchors table stores
        OpenTimestamps proofs that bind chain heads to Bitcoin blocks
        and RFC 3161 TimeStampTokens that bind chain heads to a TSA's
        signed time attestation.

        Also migrates pre-Phase-4b anchor tables forward by ALTER TABLE
        adding tst_blob, tsa_url, and tsa_gen_time columns when they are
        missing. SQLite cannot drop a NOT NULL constraint with ALTER
        TABLE, so any existing table whose ots_proof_blob column was
        created NOT NULL stays that way; the v0.2.0 release schema
        creates it nullable from the start.
        """
        assert self._db is not None
        await self._db.execute(ANCHORS_TABLE_SQL)
        await self._db.execute(ANCHORS_INDEX_CHAIN_HEAD)
        await self._db.execute(ANCHORS_INDEX_UNCONFIRMED)
        await self._migrate_anchors_columns()

    async def _ensure_witnesses_tables(self) -> None:
        """Create the witnesses and witness_attestations tables if missing.

        Both tables are fresh in v0.2.0; databases already opened under
        Phase 4 or 4b simply pick up the new CREATE TABLE IF NOT EXISTS
        on the next open. No ALTER TABLE migration is required.
        """
        assert self._db is not None
        await self._db.execute(WITNESSES_TABLE_SQL)
        await self._db.execute(WITNESSES_INDEX_ACTIVE)
        await self._db.execute(WITNESS_ATTESTATIONS_TABLE_SQL)
        await self._db.execute(WITNESS_ATTESTATIONS_INDEX_WITNESS)
        await self._db.execute(WITNESS_ATTESTATIONS_INDEX_HEAD)

    async def _migrate_anchors_columns(self) -> None:
        """Add tst_blob, tsa_url, and tsa_gen_time columns when missing.

        Pre-Phase-4b databases (an older anchors table from a Phase 4
        dev build) gain the three new columns idempotently. Newly
        created tables already have them via ANCHORS_TABLE_SQL.
        """
        assert self._db is not None
        async with self._db.execute("PRAGMA table_info(anchors)") as cursor:
            columns = {row["name"] for row in await cursor.fetchall()}

        if "tst_blob" not in columns:
            await self._db.execute("ALTER TABLE anchors ADD COLUMN tst_blob BLOB")
        if "tsa_url" not in columns:
            await self._db.execute("ALTER TABLE anchors ADD COLUMN tsa_url TEXT")
        if "tsa_gen_time" not in columns:
            await self._db.execute("ALTER TABLE anchors ADD COLUMN tsa_gen_time TEXT")

    async def anchor(
        self,
        schedule: AnchorSchedule | None = None,
    ) -> AnchorRecord | None:
        """Submit the current chain head to OpenTimestamps and an RFC 3161 TSA.

        Two parallel proof tracks run for every anchor:

          1. OpenTimestamps: each calendar URL in the schedule is
             contacted in turn. Successful calendars contribute
             attestations that are merged into one Timestamp and
             serialised into ots_proof_blob.
          2. RFC 3161: the first TSA URL in the schedule is contacted.
             A signed TimeStampToken response is persisted into
             tst_blob alongside the TSA URL and the genTime parsed
             from inside the token.

        Either track may fail entirely without blocking the other; the
        anchor row records whichever tracks succeeded. If both tracks
        fail, RuntimeError is raised with the per-track errors and no
        anchor row is written.

        Returns the new AnchorRecord with submitted_at set, confirmed_at,
        bitcoin_block_height, and bitcoin_block_hash all None. Bitcoin
        confirmation for the OpenTimestamps proof lands later via the
        background poller. The TSA's tsa_gen_time field is set
        immediately on the returned record because the TST is signed
        on receipt.

        Returns None when the ledger has no entries to anchor.

        Raises RuntimeError when no AnchorSchedule is configured (neither
        passed in nor set on the Ledger), when the schedule is disabled,
        or when every configured calendar server AND every configured
        TSA URL fail to accept the submission.

        The opentimestamps and rfc3161 client libraries are synchronous,
        so each submission is wrapped in run_in_executor to keep the
        Ledger interface async-friendly.
        """
        schedule = schedule or self._anchor_schedule
        if schedule is None or not schedule.enabled:
            raise RuntimeError(
                "Cannot anchor: no AnchorSchedule configured, or schedule "
                "is disabled. Construct Ledger(..., anchor_schedule=...) "
                "with enabled=True, or pass a schedule explicitly."
            )

        async with self._lock:
            latest_entry = await self._get_latest_entry_locked()
            if latest_entry is None:
                return None

            head_hash_bytes = bytes.fromhex(latest_entry.entry_hash)
            loop = asyncio.get_running_loop()

            ots_result = await self._submit_ots_track(
                head_hash_bytes, schedule.calendar_servers, loop
            )
            successful_calendars, ots_proof_blob, ots_errors = ots_result

            tsa_response, tsa_error = await self._submit_tsa_track(
                head_hash_bytes, schedule.tsa_urls, loop
            )

            if not successful_calendars and tsa_response is None:
                raise RuntimeError(
                    "Both anchor tracks failed. "
                    f"OTS errors: {ots_errors}. TSA error: {tsa_error!r}"
                )

            return await self._insert_anchor_locked(
                chain_head_hash=latest_entry.entry_hash,
                chain_head_entry_id=latest_entry.entry_id,
                ots_proof_blob=ots_proof_blob,
                calendar_servers=successful_calendars,
                tsa_response=tsa_response,
            )

    async def _submit_ots_track(
        self,
        head_hash_bytes: bytes,
        calendar_servers: list[str],
        loop: asyncio.AbstractEventLoop,
    ) -> tuple[list[str], bytes | None, dict[str, str]]:
        """Submit to every OpenTimestamps calendar URL in turn.

        Returns (successful_urls, serialised_proof_or_None, per_url_errors).
        The serialised proof is None when no calendar accepted the
        submission. Errors are still returned even on overall success so
        the caller can log partial failures.
        """
        merged_timestamp = Timestamp(head_hash_bytes)
        successful_calendars: list[str] = []
        errors: dict[str, str] = {}

        for calendar_url in calendar_servers:
            try:
                partial = await loop.run_in_executor(
                    None,
                    self._submit_to_calendar,
                    head_hash_bytes,
                    calendar_url,
                )
            except Exception as exc:  # noqa: BLE001
                errors[calendar_url] = repr(exc)
                continue
            merged_timestamp.merge(partial)
            successful_calendars.append(calendar_url)

        if not successful_calendars:
            return [], None, errors

        proof_ctx = BytesSerializationContext()
        merged_timestamp.serialize(proof_ctx)
        return successful_calendars, proof_ctx.getbytes(), errors

    async def _submit_tsa_track(
        self,
        head_hash_bytes: bytes,
        tsa_urls: list[str],
        loop: asyncio.AbstractEventLoop,
    ) -> tuple[TSAResponse | None, str | None]:
        """Submit to the first available RFC 3161 TSA in the list.

        Iterates the tsa_urls list and stops at the first success. The
        rest are fallbacks for the case where the primary TSA is down.
        Returns (response, None) on success and (None, last_error_repr)
        when every URL failed. Returns (None, None) when tsa_urls is
        empty (TSA track disabled).
        """
        if not tsa_urls:
            return None, None

        last_error: str | None = None
        for tsa_url in tsa_urls:
            try:
                response = await loop.run_in_executor(
                    None,
                    submit_to_tsa,
                    head_hash_bytes,
                    tsa_url,
                )
            except TSAError as exc:
                last_error = repr(exc)
                continue
            return response, None
        return None, last_error

    @staticmethod
    def _submit_to_calendar(
        digest: bytes,
        calendar_url: str,
        timeout_seconds: int = 30,
    ) -> Timestamp:
        """Synchronous calendar submission, run inside the default executor.

        Wraps opentimestamps.calendar.RemoteCalendar.submit so the async
        anchor() method can call it via loop.run_in_executor without each
        callsite repeating the RemoteCalendar construction.
        """
        return RemoteCalendar(calendar_url).submit(digest, timeout=timeout_seconds)

    async def _get_latest_entry_locked(self) -> LedgerEntry | None:
        """Return the highest-entry_id row, or None on an empty ledger.

        Caller must already hold self._lock.
        """
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM entries ORDER BY entry_id DESC LIMIT 1"
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return None
        return _row_to_entry(row)

    async def _insert_anchor_locked(
        self,
        *,
        chain_head_hash: str,
        chain_head_entry_id: int,
        ots_proof_blob: bytes | None,
        calendar_servers: list[str],
        tsa_response: TSAResponse | None,
    ) -> AnchorRecord:
        """Persist an anchor row and return the AnchorRecord with its id.

        Caller must already hold self._lock. calendar_servers is stored
        as JSON in the calendar_servers TEXT column so URL formats
        round-trip without lossy delimiter handling. The TSA fields are
        all None when the RFC 3161 track was absent or failed.
        """
        db = self._require_db()
        submitted_at = datetime.now(timezone.utc)
        tsa_gen_time_iso: str | None = (
            tsa_response.gen_time.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            )
            if tsa_response is not None
            else None
        )
        cursor = await db.execute(
            "INSERT INTO anchors ("
            "chain_head_hash, chain_head_entry_id, ots_proof_blob, "
            "submitted_at, calendar_servers, "
            "tst_blob, tsa_url, tsa_gen_time"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                chain_head_hash,
                chain_head_entry_id,
                ots_proof_blob,
                submitted_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                json.dumps(calendar_servers),
                tsa_response.tst_blob if tsa_response is not None else None,
                tsa_response.tsa_url if tsa_response is not None else None,
                tsa_gen_time_iso,
            ),
        )
        anchor_id = cursor.lastrowid
        await db.commit()
        return AnchorRecord(
            anchor_id=int(anchor_id) if anchor_id is not None else 0,
            chain_head_hash=chain_head_hash,
            chain_head_entry_id=chain_head_entry_id,
            submitted_at=submitted_at,
            calendar_servers=list(calendar_servers),
            ots_proof_blob=ots_proof_blob,
            tst_blob=tsa_response.tst_blob if tsa_response is not None else None,
            tsa_url=tsa_response.tsa_url if tsa_response is not None else None,
            tsa_gen_time=tsa_response.gen_time if tsa_response is not None else None,
        )

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

    async def list_unconfirmed_anchors(
        self,
        *,
        max_age_minutes: int | None = None,
        limit: int = 500,
    ) -> list[AnchorRecord]:
        """Return anchors with confirmed_at NULL and ots_proof_blob NOT NULL.

        Ordered by anchor_id ascending. max_age_minutes optionally
        filters to anchors submitted within the given window, so the
        background poller can skip anchors older than the typical
        Bitcoin confirmation lag (~24 hours by default in the poller).
        """
        db = self._require_db()
        clauses = [
            "confirmed_at IS NULL",
            "ots_proof_blob IS NOT NULL",
        ]
        params: list[Any] = []
        if max_age_minutes is not None:
            cutoff = datetime.now(timezone.utc) - timedelta(
                minutes=max_age_minutes
            )
            clauses.append("submitted_at >= ?")
            params.append(cutoff.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
        sql = (
            "SELECT * FROM anchors WHERE "
            + " AND ".join(clauses)
            + " ORDER BY anchor_id LIMIT ?"
        )
        params.append(int(limit))
        async with db.execute(sql, params) as cursor:
            rows = await cursor.fetchall()
        return [_row_to_anchor(row) for row in rows]

    async def confirm_anchor(
        self,
        *,
        anchor_id: int,
        upgraded_proof_blob: bytes,
        bitcoin_block_height: int,
        bitcoin_block_hash: str | None,
        confirmed_at: datetime | None = None,
    ) -> AnchorRecord:
        """Persist a Bitcoin-confirmed proof on an existing anchor row.

        Updates ots_proof_blob with the upgraded serialisation,
        populates bitcoin_block_height and bitcoin_block_hash, and
        stamps confirmed_at. Returns the refreshed AnchorRecord.

        Raises KeyError if anchor_id does not exist.
        """
        confirmed_at = confirmed_at or datetime.now(timezone.utc)
        db = self._require_db()
        async with self._lock:
            await db.execute(
                "UPDATE anchors SET "
                "ots_proof_blob = ?, "
                "bitcoin_block_height = ?, "
                "bitcoin_block_hash = ?, "
                "confirmed_at = ? "
                "WHERE anchor_id = ?",
                (
                    upgraded_proof_blob,
                    bitcoin_block_height,
                    bitcoin_block_hash,
                    confirmed_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    anchor_id,
                ),
            )
            await db.commit()
        async with db.execute(
            "SELECT * FROM anchors WHERE anchor_id = ?", (anchor_id,)
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            raise KeyError(f"No anchor with anchor_id={anchor_id}")
        return _row_to_anchor(row)

    async def get_anchor(self, anchor_id: int) -> AnchorRecord:
        """Fetch a single anchor by id; raises KeyError if not found."""
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM anchors WHERE anchor_id = ?", (anchor_id,)
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            raise KeyError(f"No anchor with anchor_id={anchor_id}")
        return _row_to_anchor(row)

    async def get_anchors(
        self,
        *,
        confirmed: bool | None = None,
        limit: int = 500,
    ) -> list[AnchorRecord]:
        """List anchors ordered by anchor_id ascending.

        confirmed=True returns only Bitcoin-confirmed rows; confirmed=False
        returns only pending rows; None (default) returns all anchors.
        """
        db = self._require_db()
        sql = "SELECT * FROM anchors"
        if confirmed is True:
            sql += " WHERE confirmed_at IS NOT NULL"
        elif confirmed is False:
            sql += " WHERE confirmed_at IS NULL"
        sql += " ORDER BY anchor_id LIMIT ?"
        async with db.execute(sql, (int(limit),)) as cursor:
            rows = await cursor.fetchall()
        return [_row_to_anchor(row) for row in rows]

    async def register_witness(
        self,
        *,
        label: str,
        public_key_hex: str,
        role: str = WITNESS_ROLE_CONSORTIUM,
    ) -> Witness:
        """Register a new witness identity.

        label and public_key_hex are both UNIQUE in the witnesses table;
        attempting to register a duplicate raises sqlite3.IntegrityError
        (propagated through aiosqlite). role must be a member of
        WITNESS_ROLES.
        """
        if role not in WITNESS_ROLES:
            raise ValueError(
                f"role must be one of {sorted(WITNESS_ROLES)}, got {role!r}"
            )
        db = self._require_db()
        created_at = datetime.now(timezone.utc)
        async with self._lock:
            cursor = await db.execute(
                "INSERT INTO witnesses (label, public_key_hex, role, created_at) "
                "VALUES (?, ?, ?, ?)",
                (
                    label,
                    public_key_hex,
                    role,
                    created_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                ),
            )
            witness_id = cursor.lastrowid
            await db.commit()
        return Witness(
            witness_id=int(witness_id) if witness_id is not None else 0,
            label=label,
            public_key_hex=public_key_hex,
            role=role,
            created_at=created_at,
        )

    async def retire_witness(self, witness_id: int) -> Witness:
        """Mark a witness retired.

        Future attest_with_witness calls against this witness_id raise.
        Existing attestations remain verifiable. Idempotent: retiring an
        already-retired witness preserves the original retired_at.
        """
        db = self._require_db()
        now = datetime.now(timezone.utc)
        async with self._lock:
            await db.execute(
                "UPDATE witnesses SET retired_at = ? "
                "WHERE witness_id = ? AND retired_at IS NULL",
                (now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), witness_id),
            )
            await db.commit()
        return await self._get_witness(witness_id)

    async def list_witnesses(
        self,
        *,
        include_retired: bool = False,
    ) -> list[Witness]:
        """Return all witnesses, ordered by witness_id.

        Retired witnesses are excluded by default.
        """
        db = self._require_db()
        sql = "SELECT * FROM witnesses"
        if not include_retired:
            sql += " WHERE retired_at IS NULL"
        sql += " ORDER BY witness_id"
        async with db.execute(sql) as cursor:
            rows = await cursor.fetchall()
        return [_row_to_witness(row) for row in rows]

    async def _get_witness(self, witness_id: int) -> Witness:
        db = self._require_db()
        async with db.execute(
            "SELECT * FROM witnesses WHERE witness_id = ?",
            (witness_id,),
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            raise KeyError(f"No witness with witness_id={witness_id}")
        return _row_to_witness(row)

    async def _get_last_witness_attestation_hash(
        self,
        witness_id: int,
    ) -> str:
        db = self._require_db()
        async with db.execute(
            "SELECT attestation_hash FROM witness_attestations "
            "WHERE witness_id = ? ORDER BY attestation_id DESC LIMIT 1",
            (witness_id,),
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return GENESIS_WITNESS_PREV_HASH
        return str(row["attestation_hash"])

    async def attest_with_witness(
        self,
        *,
        witness_id: int,
        signer: Signer,
    ) -> WitnessAttestation | None:
        """Have a witness sign the current chain head.

        Returns None when the ledger has no entries to attest. Raises:
            KeyError if witness_id does not exist.
            RuntimeError if the witness is retired.
            RuntimeError if the signer's key_id does not match the
                witness's registered public key (defensive cross-check).
        """
        db = self._require_db()
        async with self._lock:
            witness = await self._get_witness(witness_id)
            if witness.retired_at is not None:
                raise RuntimeError(
                    f"Witness {witness_id} ({witness.label}) is retired "
                    f"and cannot sign new attestations."
                )
            if signer.key_id != witness.public_key_hex:
                raise RuntimeError(
                    f"signer.key_id does not match witness public key. "
                    f"Witness {witness_id} registered "
                    f"{witness.public_key_hex[:16]}..."
                    f"; signer offered {signer.key_id[:16]}..."
                )

            latest_entry = await self._get_latest_entry_locked()
            if latest_entry is None:
                return None

            prev_attestation_hash = await self._get_last_witness_attestation_hash(
                witness_id
            )

            signed_at = datetime.now(timezone.utc)
            signed_at_iso = signed_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            attestation_hash = _compute_witness_attestation_hash(
                witness_id=witness_id,
                chain_head_entry_id=latest_entry.entry_id,
                chain_head_hash=latest_entry.entry_hash,
                signed_at=signed_at_iso,
                prev_attestation_hash=prev_attestation_hash,
            )
            signature_bytes = signer.sign(bytes.fromhex(attestation_hash))
            signature_hex = signature_bytes.hex()

            cursor = await db.execute(
                "INSERT INTO witness_attestations ("
                "witness_id, chain_head_entry_id, chain_head_hash, "
                "signed_at, prev_attestation_hash, attestation_hash, "
                "signature_hex"
                ") VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    witness_id,
                    latest_entry.entry_id,
                    latest_entry.entry_hash,
                    signed_at_iso,
                    prev_attestation_hash,
                    attestation_hash,
                    signature_hex,
                ),
            )
            attestation_id = cursor.lastrowid
            await db.commit()

            return WitnessAttestation(
                attestation_id=int(attestation_id) if attestation_id is not None else 0,
                witness_id=witness_id,
                chain_head_entry_id=latest_entry.entry_id,
                chain_head_hash=latest_entry.entry_hash,
                signed_at=signed_at,
                prev_attestation_hash=prev_attestation_hash,
                attestation_hash=attestation_hash,
                signature_hex=signature_hex,
            )

    async def get_witness_attestations(
        self,
        *,
        witness_id: int | None = None,
        chain_head_entry_id: int | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 500,
    ) -> list[WitnessAttestation]:
        """Query witness attestations with optional filters.

        since / until are ISO-8601 UTC strings compared against
        signed_at. Results are ordered by attestation_id ascending.
        """
        clauses: list[str] = []
        params: list[Any] = []
        if witness_id is not None:
            clauses.append("witness_id = ?")
            params.append(witness_id)
        if chain_head_entry_id is not None:
            clauses.append("chain_head_entry_id = ?")
            params.append(chain_head_entry_id)
        if since is not None:
            clauses.append("signed_at >= ?")
            params.append(since)
        if until is not None:
            clauses.append("signed_at <= ?")
            params.append(until)
        sql = "SELECT * FROM witness_attestations"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY attestation_id LIMIT ?"
        params.append(int(limit))

        db = self._require_db()
        async with db.execute(sql, params) as cursor:
            rows = await cursor.fetchall()
        return [_row_to_witness_attestation(row) for row in rows]

    async def verify_witness_attestations(
        self,
        verifier: Verifier,
    ) -> int:
        """Walk every witness attestation and verify it end-to-end.

        For each attestation:
          - Recompute attestation_hash from the stored fields.
          - Check the per-witness sub-chain link via
            prev_attestation_hash.
          - Verify the Ed25519 signature against the witness's
            registered public key (looked up as the verifier's key_id).

        Returns the number of attestations verified. Raises
        WitnessVerificationError on any mismatch, with the offending
        attestation_id and witness_id in the message.
        """
        db = self._require_db()
        async with db.execute("SELECT * FROM witnesses") as witness_cursor:
            witness_rows = await witness_cursor.fetchall()
        witnesses_by_id: dict[int, Witness] = {
            int(row["witness_id"]): _row_to_witness(row) for row in witness_rows
        }

        expected_prev: dict[int, str] = {}
        verified = 0

        async with db.execute(
            "SELECT * FROM witness_attestations "
            "ORDER BY witness_id, attestation_id"
        ) as cursor:
            async for row in cursor:
                attestation_id = int(row["attestation_id"])
                witness_id = int(row["witness_id"])
                witness = witnesses_by_id.get(witness_id)
                if witness is None:
                    raise WitnessVerificationError(
                        f"Attestation {attestation_id} references "
                        f"witness_id={witness_id} which does not exist."
                    )

                prev = expected_prev.get(witness_id, GENESIS_WITNESS_PREV_HASH)
                stored_prev = str(row["prev_attestation_hash"])
                if stored_prev != prev:
                    raise WitnessVerificationError(
                        f"Attestation {attestation_id} from witness "
                        f"{witness_id} ({witness.label}) "
                        f"prev_attestation_hash mismatch: expected {prev}, "
                        f"stored {stored_prev}"
                    )

                recomputed = _compute_witness_attestation_hash(
                    witness_id=witness_id,
                    chain_head_entry_id=int(row["chain_head_entry_id"]),
                    chain_head_hash=row["chain_head_hash"],
                    signed_at=row["signed_at"],
                    prev_attestation_hash=stored_prev,
                )
                if recomputed != row["attestation_hash"]:
                    raise WitnessVerificationError(
                        f"Attestation {attestation_id} from witness "
                        f"{witness_id} ({witness.label}) "
                        f"attestation_hash mismatch: expected {recomputed}, "
                        f"stored {row['attestation_hash']}"
                    )

                try:
                    ok = verifier.verify(
                        witness.public_key_hex,
                        bytes.fromhex(recomputed),
                        bytes.fromhex(row["signature_hex"]),
                    )
                except Exception as exc:  # noqa: BLE001
                    raise WitnessVerificationError(
                        f"Attestation {attestation_id} from witness "
                        f"{witness_id} ({witness.label}) "
                        f"signature verification raised: {exc!r}"
                    ) from exc
                if not ok:
                    raise WitnessVerificationError(
                        f"Attestation {attestation_id} from witness "
                        f"{witness_id} ({witness.label}) "
                        f"signature verification failed."
                    )

                expected_prev[witness_id] = str(row["attestation_hash"])
                verified += 1

        return verified

    def _require_db(self) -> aiosqlite.Connection:
        if self._db is None or not self._initialised:
            raise RuntimeError("Ledger.init() must be awaited before use")
        return self._db
