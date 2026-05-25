"""Data model for OpenTimestamps anchor records.

An AnchorRecord represents one submission of a chain head to one or more
OpenTimestamps calendar servers. The record is created when Ledger.anchor
posts the chain head and is updated later (via a separate row write, not
in-place mutation) once Bitcoin confirms the proof.

The record is intentionally frozen. The background confirmation poller
writes a new row state to the database directly rather than mutating an
in-memory dataclass, which keeps the model safe to pass across the async
event loop without coordination.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class AnchorRecord:
    """One OpenTimestamps anchor submitted for a given chain head.

    Fields:
        anchor_id:            autoincrement primary key in the anchors table.
        chain_head_hash:      the entry_hash being anchored, hex.
        chain_head_entry_id:  the entry_id of that chain head.
        ots_proof_blob:       serialised OpenTimestamps proof, raw bytes.
        submitted_at:         when the proof was posted to the calendar(s).
        calendar_servers:     URLs of the calendar servers that accepted it.
        confirmed_at:         when Bitcoin confirmed the proof. None until
                              the background poller upgrades the proof.
        bitcoin_block_height: Bitcoin block that contains the proof, once
                              confirmed. None before confirmation.
        bitcoin_block_hash:   Bitcoin block hash containing the proof, once
                              confirmed. None before confirmation.
    """

    anchor_id: int
    chain_head_hash: str
    chain_head_entry_id: int
    ots_proof_blob: bytes
    submitted_at: datetime
    calendar_servers: list[str]
    confirmed_at: datetime | None = None
    bitcoin_block_height: int | None = None
    bitcoin_block_hash: str | None = None
