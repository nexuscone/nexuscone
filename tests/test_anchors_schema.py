"""Tests for the anchors table schema and its migration into Ledger.init."""

from __future__ import annotations

from pathlib import Path

import aiosqlite
import pytest

from nexuscone.chain import Ledger


@pytest.mark.asyncio
async def test_anchors_table_created_on_fresh_database(tmp_path: Path) -> None:
    db_path = tmp_path / "fresh.db"
    async with Ledger(db_path):
        pass

    async with aiosqlite.connect(db_path) as raw:
        raw.row_factory = aiosqlite.Row
        async with raw.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name = 'anchors'"
        ) as cursor:
            rows = await cursor.fetchall()
        assert len(rows) == 1

        async with raw.execute("PRAGMA table_info(anchors)") as cursor:
            columns = {row["name"] for row in await cursor.fetchall()}
        expected = {
            "anchor_id",
            "chain_head_hash",
            "chain_head_entry_id",
            "ots_proof_blob",
            "submitted_at",
            "calendar_servers",
            "confirmed_at",
            "bitcoin_block_height",
            "bitcoin_block_hash",
        }
        assert expected.issubset(columns)

        async with raw.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'index' AND tbl_name = 'anchors'"
        ) as cursor:
            index_names = {row["name"] for row in await cursor.fetchall()}
        assert "idx_anchors_chain_head" in index_names
        assert "idx_anchors_unconfirmed" in index_names


@pytest.mark.asyncio
async def test_anchors_migration_is_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "idempotent.db"
    async with Ledger(db_path):
        pass
    async with Ledger(db_path):
        pass
    # Third open for good measure; a non-idempotent CREATE would have raised
    # OperationalError by now.
    async with Ledger(db_path) as ledger:
        await ledger.log(actor="agent", action="post-migration")
        count = await ledger.verify_chain()
    assert count == 1


@pytest.mark.asyncio
async def test_anchors_foreign_key_rejects_orphan_chain_head(tmp_path: Path) -> None:
    """Inserting an anchor whose chain_head_entry_id has no matching entries
    row must raise an IntegrityError. PRAGMA foreign_keys = ON is set inside
    Ledger.init, so the FK is enforced on this connection too once the
    pragma is re-enabled below."""
    db_path = tmp_path / "fk.db"
    async with Ledger(db_path) as ledger:
        await ledger.log(actor="agent", action="tick")

    async with aiosqlite.connect(db_path) as raw:
        await raw.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(aiosqlite.IntegrityError):
            await raw.execute(
                "INSERT INTO anchors ("
                "chain_head_hash, chain_head_entry_id, ots_proof_blob, "
                "submitted_at, calendar_servers"
                ") VALUES (?, ?, ?, ?, ?)",
                (
                    "0" * 64,
                    9999,
                    b"\x00proof",
                    "2026-05-25T19:00:00.000000Z",
                    "https://alice.btc.calendar.opentimestamps.org",
                ),
            )
            await raw.commit()


@pytest.mark.asyncio
async def test_anchors_foreign_key_accepts_real_chain_head(tmp_path: Path) -> None:
    """Inserting an anchor whose chain_head_entry_id matches a real entry
    must succeed. Confirms the FK is enforced in the rejecting direction
    only, not as a blanket block on every anchor insert."""
    db_path = tmp_path / "fk_ok.db"
    async with Ledger(db_path) as ledger:
        entry = await ledger.log(actor="agent", action="tick")

    async with aiosqlite.connect(db_path) as raw:
        await raw.execute("PRAGMA foreign_keys = ON")
        await raw.execute(
            "INSERT INTO anchors ("
            "chain_head_hash, chain_head_entry_id, ots_proof_blob, "
            "submitted_at, calendar_servers"
            ") VALUES (?, ?, ?, ?, ?)",
            (
                entry.entry_hash,
                entry.entry_id,
                b"\x00proof",
                "2026-05-25T19:00:00.000000Z",
                "https://alice.btc.calendar.opentimestamps.org",
            ),
        )
        await raw.commit()

        async with raw.execute("SELECT COUNT(*) AS n FROM anchors") as cursor:
            row = await cursor.fetchone()
        assert row is not None and row[0] == 1
