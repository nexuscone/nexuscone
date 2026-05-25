"""Integration tests for the nexuscone-verify CLI.

verifier_main() is a synchronous entry point that calls asyncio.run
internally, so these tests are plain sync functions. Ledger setup is
done by running short async helpers through asyncio.run before each
CLI invocation.

Seeded ledgers use a fake OpenTimestamps calendar so no real network
calls fire. Confirmed anchors are produced by constructing a Timestamp
that carries a BitcoinBlockHeaderAttestation directly and persisting
it via Ledger.confirm_anchor.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from opentimestamps.core.notary import (
    BitcoinBlockHeaderAttestation,
    PendingAttestation,
)
from opentimestamps.core.serialize import BytesSerializationContext
from opentimestamps.core.timestamp import Timestamp

from nexuscone.anchor_schedule import AnchorSchedule
from nexuscone.chain import Ledger
from nexuscone.verifier import main as verifier_main

CALENDAR_URL = "https://alice.example.invalid"


class _FakeSubmitCalendar:
    """Stand-in for RemoteCalendar.submit used by Ledger.anchor."""

    def __init__(self, url: str, user_agent: str = "test") -> None:
        self.url = url

    def submit(self, digest: bytes, timeout: int | None = None) -> Timestamp:
        ts = Timestamp(digest)
        ts.attestations.add(PendingAttestation(self.url))
        return ts


@pytest.fixture
def patch_submit_calendar(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("nexuscone.chain.RemoteCalendar", _FakeSubmitCalendar)


def _build_confirmed_proof_blob(chain_head_hash: str, height: int) -> bytes:
    """Manufacture a serialised OTS proof carrying a Bitcoin attestation.

    Used to mark an anchor row as confirmed inside the test so the
    --check-anchors flow has something to verify. The proof root msg
    is the chain head bytes, which is exactly what verifier.py passes
    as initial_msg when it deserialises.
    """
    ts = Timestamp(bytes.fromhex(chain_head_hash))
    ts.attestations.add(BitcoinBlockHeaderAttestation(height))
    ctx = BytesSerializationContext()
    ts.serialize(ctx)
    return ctx.getbytes()


async def _seed_mixed_anchors(db_path: Path) -> tuple[int, int]:
    """Create one confirmed and one pending anchor.

    Returns (confirmed_anchor_id, pending_anchor_id).
    """
    schedule = AnchorSchedule(
        enabled=True,
        calendar_servers=[CALENDAR_URL],
        tsa_urls=[],
    )
    async with Ledger(db_path, anchor_schedule=schedule) as ledger:
        await ledger.log(actor="user", action="one")
        first = await ledger.anchor()
        assert first is not None
        upgraded_blob = _build_confirmed_proof_blob(first.chain_head_hash, 850_000)
        await ledger.confirm_anchor(
            anchor_id=first.anchor_id,
            upgraded_proof_blob=upgraded_blob,
            bitcoin_block_height=850_000,
            bitcoin_block_hash="aa" * 32,
        )
        await ledger.log(actor="user", action="two")
        second = await ledger.anchor()
        assert second is not None
        return first.anchor_id, second.anchor_id


async def _seed_one_entry(db_path: Path) -> None:
    async with Ledger(db_path) as ledger:
        await ledger.log(actor="user", action="ok")


async def _seed_anchor_with_wrong_height(db_path: Path) -> int:
    schedule = AnchorSchedule(
        enabled=True,
        calendar_servers=[CALENDAR_URL],
        tsa_urls=[],
    )
    async with Ledger(db_path, anchor_schedule=schedule) as ledger:
        await ledger.log(actor="user", action="x")
        record = await ledger.anchor()
        assert record is not None
        blob = _build_confirmed_proof_blob(record.chain_head_hash, 700)
        await ledger.confirm_anchor(
            anchor_id=record.anchor_id,
            upgraded_proof_blob=blob,
            bitcoin_block_height=9_999_999,
            bitcoin_block_hash="bb" * 32,
        )
        return record.anchor_id


async def _seed_one_pending_for_upgrade(db_path: Path) -> None:
    schedule = AnchorSchedule(
        enabled=True,
        calendar_servers=[CALENDAR_URL],
        tsa_urls=[],
    )
    async with Ledger(db_path, anchor_schedule=schedule) as ledger:
        await ledger.log(actor="user", action="anything")
        record = await ledger.anchor()
        assert record is not None


def test_default_command_runs_chain_verify(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db_path = tmp_path / "ledger.db"
    asyncio.run(_seed_one_entry(db_path))

    exit_code = verifier_main([str(db_path)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "chain valid" in captured.out
    assert "1 entries" in captured.out


def test_check_anchors_reports_confirmed_and_pending(
    tmp_path: Path,
    patch_submit_calendar: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    db_path = tmp_path / "ledger.db"
    asyncio.run(_seed_mixed_anchors(db_path))

    exit_code = verifier_main(["--check-anchors", str(db_path)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "VERIFIED" in captured.out
    assert "bitcoin_block=850000" in captured.out
    assert "PENDING" in captured.out
    assert "1 confirmed, 1 pending, 0 failed" in captured.out


def test_check_anchors_flags_height_mismatch_as_failed(
    tmp_path: Path,
    patch_submit_calendar: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    db_path = tmp_path / "ledger.db"
    asyncio.run(_seed_anchor_with_wrong_height(db_path))

    exit_code = verifier_main(["--check-anchors", str(db_path)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "height mismatch" in captured.err
    assert "1 failed" in captured.out


def test_print_anchor_prints_row_fields(
    tmp_path: Path,
    patch_submit_calendar: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    db_path = tmp_path / "ledger.db"
    confirmed_id, _ = asyncio.run(_seed_mixed_anchors(db_path))

    exit_code = verifier_main(["--print-anchor", str(confirmed_id), str(db_path)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "anchor_id" in captured.out
    assert "chain_head_hash" in captured.out
    assert "bitcoin_block_height : 850000" in captured.out


def test_print_anchor_unknown_id_exits_with_error(
    tmp_path: Path,
    patch_submit_calendar: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    db_path = tmp_path / "ledger.db"
    asyncio.run(_seed_mixed_anchors(db_path))

    exit_code = verifier_main(["--print-anchor", "9999", str(db_path)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "No anchor with anchor_id=9999" in captured.err


def test_upgrade_pending_prints_counters(
    tmp_path: Path,
    patch_submit_calendar: None,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    db_path = tmp_path / "ledger.db"

    class _NoBitcoinCalendar:
        def __init__(self, uri: str, user_agent: str = "test") -> None:
            self.uri = uri

        def get_timestamp(
            self, commitment: bytes, timeout: int | None = None
        ) -> Timestamp:
            # Empty Timestamp at the commitment: no Bitcoin attestation,
            # so the anchor stays pending and the counter reports it.
            return Timestamp(commitment)

    monkeypatch.setattr("nexuscone.poller.RemoteCalendar", _NoBitcoinCalendar)
    asyncio.run(_seed_one_pending_for_upgrade(db_path))

    exit_code = verifier_main(["--upgrade-pending", str(db_path)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "attempted: 1" in captured.out
    assert "still_pending: 1" in captured.out


def test_check_tst_with_no_tst_anchors_reports_skipped(
    tmp_path: Path,
    patch_submit_calendar: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The seeded ledger has tsa_urls=[] so no TST blobs are stored.
    --check-tst should report 'without TST' as the skipped count."""
    db_path = tmp_path / "ledger.db"
    asyncio.run(_seed_mixed_anchors(db_path))

    exit_code = verifier_main(["--check-tst", str(db_path)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "0 verified" in captured.out
    assert "0 failed" in captured.out
    assert "2 without TST" in captured.out
