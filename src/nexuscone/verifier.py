"""Standalone chain verification utility, callable as a CLI script.

Subcommand-style flags (mutually exclusive):

    nexuscone-verify <db_path>                       chain integrity only (default)
    nexuscone-verify <db_path> --check-anchors       deserialise OTS proofs and
                                                     confirm Bitcoin attestation
                                                     heights match the stored row
    nexuscone-verify <db_path> --check-tst           verify each RFC 3161
                                                     TimeStampToken against its
                                                     chain head digest
    nexuscone-verify <db_path> --upgrade-pending     ask calendars to upgrade
                                                     incomplete proofs (Phase 5
                                                     poller)
    nexuscone-verify <db_path> --print-anchor <id>   pretty-print one anchor row

Exit code is 0 on success and 1 on any failure surfaced during the
chosen operation. Output goes to stdout; errors go to stderr.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from opentimestamps.core.serialize import BytesDeserializationContext
from opentimestamps.core.timestamp import Timestamp

from nexuscone.chain import ChainVerificationError, Ledger
from nexuscone.poller import _first_bitcoin_attestation, upgrade_pending_anchors
from nexuscone.rfc3161 import TSAError, verify_tst


async def _verify_chain(db_path: Path) -> int:
    async with Ledger(db_path) as ledger:
        try:
            count = await ledger.verify_chain()
        except ChainVerificationError as exc:
            print(f"FAIL · {exc}", file=sys.stderr)
            return 1
    print(f"OK · chain valid ({count} entries)")
    return 0


async def _check_anchors(db_path: Path) -> int:
    """Walk every anchor; verify confirmed proofs and list pending ones.

    A confirmed anchor passes verification when its serialised OTS
    proof carries a BitcoinBlockHeaderAttestation whose height matches
    the bitcoin_block_height column. A pending anchor is reported but
    not verified; the proof is still maturing on the OpenTimestamps
    calendar side.
    """
    confirmed_n = 0
    pending_n = 0
    failed_n = 0
    async with Ledger(db_path) as ledger:
        anchors = await ledger.get_anchors()
        for anchor in anchors:
            head_short = anchor.chain_head_hash[:16]
            if anchor.confirmed_at is not None and anchor.ots_proof_blob is not None:
                try:
                    ts = Timestamp.deserialize(
                        BytesDeserializationContext(anchor.ots_proof_blob),
                        bytes.fromhex(anchor.chain_head_hash),
                    )
                    btc = _first_bitcoin_attestation(ts)
                    if btc is None:
                        raise ValueError(
                            "confirmed anchor's proof carries no "
                            "BitcoinBlockHeaderAttestation"
                        )
                    stored_height = anchor.bitcoin_block_height
                    if stored_height is None or int(btc.height) != stored_height:
                        raise ValueError(
                            f"height mismatch: proof says {btc.height}, "
                            f"row says {stored_height}"
                        )
                    print(
                        f"VERIFIED chain_head={head_short}... "
                        f"bitcoin_block={anchor.bitcoin_block_height}"
                    )
                    confirmed_n += 1
                except Exception as exc:  # noqa: BLE001
                    print(
                        f"FAILED anchor_id={anchor.anchor_id}: {exc}",
                        file=sys.stderr,
                    )
                    failed_n += 1
            else:
                cals = (
                    ", ".join(anchor.calendar_servers)
                    if anchor.calendar_servers
                    else "(none)"
                )
                print(
                    f"PENDING  chain_head={head_short}... "
                    f"submitted={anchor.submitted_at.isoformat()} "
                    f"calendars={cals}"
                )
                pending_n += 1
    print(
        f"\nSummary: {confirmed_n} confirmed, {pending_n} pending, "
        f"{failed_n} failed"
    )
    return 1 if failed_n > 0 else 0


async def _check_tst(db_path: Path) -> int:
    """Verify each stored RFC 3161 TST against its chain head digest."""
    verified_n = 0
    failed_n = 0
    skipped_n = 0
    async with Ledger(db_path) as ledger:
        anchors = await ledger.get_anchors()
        for anchor in anchors:
            head_short = anchor.chain_head_hash[:16]
            if anchor.tst_blob is None:
                skipped_n += 1
                continue
            try:
                response = verify_tst(
                    anchor.tst_blob,
                    bytes.fromhex(anchor.chain_head_hash),
                    tsa_url=anchor.tsa_url or "",
                )
                print(
                    f"VERIFIED chain_head={head_short}... "
                    f"tsa={response.tsa_url or '(unknown)'} "
                    f"gen_time={response.gen_time.isoformat()}"
                )
                verified_n += 1
            except TSAError as exc:
                print(
                    f"FAILED anchor_id={anchor.anchor_id}: {exc}",
                    file=sys.stderr,
                )
                failed_n += 1
    print(
        f"\nSummary: {verified_n} verified, {failed_n} failed, "
        f"{skipped_n} without TST"
    )
    return 1 if failed_n > 0 else 0


async def _upgrade_pending(db_path: Path) -> int:
    async with Ledger(db_path) as ledger:
        counters = await upgrade_pending_anchors(ledger)
    for key in ("attempted", "upgraded", "still_pending", "failed"):
        print(f"{key}: {counters[key]}")
    return 0


async def _print_anchor(db_path: Path, anchor_id: int) -> int:
    async with Ledger(db_path) as ledger:
        try:
            anchor = await ledger.get_anchor(anchor_id)
        except KeyError as exc:
            print(f"FAIL · {exc}", file=sys.stderr)
            return 1

    def _fmt_optional_iso(value: object) -> str:
        if value is None:
            return "None"
        return str(value)

    fields = [
        ("anchor_id", anchor.anchor_id),
        ("chain_head_hash", anchor.chain_head_hash),
        ("chain_head_entry_id", anchor.chain_head_entry_id),
        ("submitted_at", anchor.submitted_at.isoformat()),
        ("calendar_servers", anchor.calendar_servers),
        (
            "confirmed_at",
            anchor.confirmed_at.isoformat() if anchor.confirmed_at else "None",
        ),
        ("bitcoin_block_height", anchor.bitcoin_block_height),
        ("bitcoin_block_hash", anchor.bitcoin_block_hash),
        (
            "ots_proof_blob_bytes",
            len(anchor.ots_proof_blob) if anchor.ots_proof_blob else 0,
        ),
        ("tst_blob_bytes", len(anchor.tst_blob) if anchor.tst_blob else 0),
        ("tsa_url", anchor.tsa_url),
        ("tsa_gen_time", _fmt_optional_iso(anchor.tsa_gen_time)),
    ]
    width = max(len(name) for name, _ in fields)
    for name, value in fields:
        print(f"{name.ljust(width)} : {value}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Exit 0 on pass, 1 on fail."""
    parser = argparse.ArgumentParser(
        description=(
            "Verify the integrity of a Nexuscone ledger database and its "
            "OpenTimestamps and RFC 3161 anchors."
        )
    )
    parser.add_argument(
        "db_path",
        type=Path,
        help="Path to the SQLite database file containing the ledger.",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--check-anchors",
        action="store_true",
        help=(
            "Verify each OpenTimestamps proof: deserialise and confirm "
            "the Bitcoin block height matches the stored row."
        ),
    )
    group.add_argument(
        "--check-tst",
        action="store_true",
        help=(
            "Verify each RFC 3161 TimeStampToken against its chain "
            "head digest."
        ),
    )
    group.add_argument(
        "--upgrade-pending",
        action="store_true",
        help=(
            "Ask the OpenTimestamps calendars to upgrade any pending "
            "proofs; persist Bitcoin confirmations as they arrive."
        ),
    )
    group.add_argument(
        "--print-anchor",
        type=int,
        metavar="ANCHOR_ID",
        help="Pretty-print the named anchor row.",
    )
    args = parser.parse_args(argv)

    if args.check_anchors:
        return asyncio.run(_check_anchors(args.db_path))
    if args.check_tst:
        return asyncio.run(_check_tst(args.db_path))
    if args.upgrade_pending:
        return asyncio.run(_upgrade_pending(args.db_path))
    if args.print_anchor is not None:
        return asyncio.run(_print_anchor(args.db_path, int(args.print_anchor)))
    return asyncio.run(_verify_chain(args.db_path))


if __name__ == "__main__":
    raise SystemExit(main())
