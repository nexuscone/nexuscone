"""End-to-end v0.2.0 scenario.

Walks the full happy path of the OpenTimestamps anchoring track:

1. Fresh ledger.
2. 1500 logged entries (over the every_n_entries threshold).
3. Anchor against a mocked calendar.
4. Simulate Bitcoin confirmation by persisting an upgraded proof that
   carries a BitcoinBlockHeaderAttestation.
5. Run the nexuscone-verify --check-anchors CLI through main() and
   confirm it prints VERIFIED for the confirmed anchor.

No real network calls fire. The mocked calendar substitutes for the
OpenTimestamps RemoteCalendar.submit path; the Bitcoin confirmation
is fabricated by constructing a Timestamp containing a
BitcoinBlockHeaderAttestation directly.
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

CALENDAR_URL = "https://alice.btc.calendar.example.invalid"


class _FakeCalendar:
    def __init__(self, url: str, user_agent: str = "test") -> None:
        self.url = url

    def submit(self, digest: bytes, timeout: int | None = None) -> Timestamp:
        ts = Timestamp(digest)
        ts.attestations.add(PendingAttestation(self.url))
        return ts


def _build_confirmed_proof_blob(chain_head_hash: str, height: int) -> bytes:
    ts = Timestamp(bytes.fromhex(chain_head_hash))
    ts.attestations.add(BitcoinBlockHeaderAttestation(height))
    ctx = BytesSerializationContext()
    ts.serialize(ctx)
    return ctx.getbytes()


async def _seed_and_anchor(db_path: Path) -> tuple[int, str, int]:
    """Drive the production path against a mocked OTS calendar.

    Returns (anchor_id, chain_head_hash, total_entries).
    """
    schedule = AnchorSchedule(
        every_n_entries=1000,
        every_m_minutes=60,
        calendar_servers=[CALENDAR_URL],
        tsa_urls=[],
        enabled=True,
    )
    async with Ledger(db_path, anchor_schedule=schedule) as ledger:
        for index in range(1500):
            await ledger.log(
                actor="api",
                action="request",
                payload={"id": f"r-{index:04d}"},
            )

        assert await ledger.count() == 1500

        anchor = await ledger.anchor()
        assert anchor is not None
        assert anchor.calendar_servers == [CALENDAR_URL]
        assert anchor.ots_proof_blob is not None
        assert anchor.confirmed_at is None

        confirmed_blob = _build_confirmed_proof_blob(
            anchor.chain_head_hash, height=851_234
        )
        confirmed = await ledger.confirm_anchor(
            anchor_id=anchor.anchor_id,
            upgraded_proof_blob=confirmed_blob,
            bitcoin_block_height=851_234,
            bitcoin_block_hash="cc" * 32,
        )
        assert confirmed.confirmed_at is not None
        assert confirmed.bitcoin_block_height == 851_234

        return anchor.anchor_id, anchor.chain_head_hash, 1500


def test_full_v020_happy_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("nexuscone.chain.RemoteCalendar", _FakeCalendar)

    db_path = tmp_path / "ledger.db"
    anchor_id, chain_head_hash, total = asyncio.run(_seed_and_anchor(db_path))

    capsys.readouterr()  # drop any incidental output before the CLI call

    chain_exit = verifier_main([str(db_path)])
    chain_captured = capsys.readouterr()
    assert chain_exit == 0
    assert f"{total} entries" in chain_captured.out

    anchors_exit = verifier_main(["--check-anchors", str(db_path)])
    anchors_captured = capsys.readouterr()
    assert anchors_exit == 0
    assert "VERIFIED" in anchors_captured.out
    assert "bitcoin_block=851234" in anchors_captured.out
    assert "1 confirmed, 0 pending, 0 failed" in anchors_captured.out

    print_exit = verifier_main(["--print-anchor", str(anchor_id), str(db_path)])
    print_captured = capsys.readouterr()
    assert print_exit == 0
    assert chain_head_hash in print_captured.out
    assert "bitcoin_block_height : 851234" in print_captured.out
