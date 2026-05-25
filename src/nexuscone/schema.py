"""SQL schema fragments for nexuscone tables created after the v0.1.0 baseline.

The original entries-table schema lives in nexuscone.chain alongside the
Ledger class that owns it. From v0.2.0 onwards new tables and their
migration helpers live here so the chain module stays focused on the
hash-chain primitive.

The ANCHORS_TABLE_SQL constant defines the table used to store
OpenTimestamps proofs that anchor chain heads to Bitcoin. The two indexes
support the two query patterns used by Ledger.anchor (lookup by chain
head) and the background confirmation poller (find unconfirmed anchors).
"""

from __future__ import annotations

ANCHORS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS anchors (
    anchor_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_head_hash      TEXT    NOT NULL,
    chain_head_entry_id  INTEGER NOT NULL,
    ots_proof_blob       BLOB    NOT NULL,
    submitted_at         TEXT    NOT NULL,
    calendar_servers     TEXT    NOT NULL,
    confirmed_at         TEXT,
    bitcoin_block_height INTEGER,
    bitcoin_block_hash   TEXT,
    FOREIGN KEY (chain_head_entry_id) REFERENCES entries(entry_id)
)
"""

ANCHORS_INDEX_CHAIN_HEAD = (
    "CREATE INDEX IF NOT EXISTS idx_anchors_chain_head "
    "ON anchors(chain_head_hash)"
)

ANCHORS_INDEX_UNCONFIRMED = (
    "CREATE INDEX IF NOT EXISTS idx_anchors_unconfirmed "
    "ON anchors(confirmed_at) WHERE confirmed_at IS NULL"
)
