"""Nexuscone: tamper-evident append-only audit ledger.

Public API:
    Ledger: async SQLite-backed hash-chain ledger
    LedgerEntry: typed entry returned by the chain
    ChainVerificationError: raised when verify_chain detects tamper
    GENESIS_PREVIOUS_HASH: sixty-four zero characters; the chain anchor
    canonical_json: canonical JSON serialisation utility
    sha256_hex: SHA-256 hex digest utility

Event types (v0.2.0 and later):
    EVENT_TYPE_REQUEST: the default for ordinary writes
    EVENT_TYPE_SCHEMA_DRIFT, EVENT_TYPE_COST_ANOMALY,
    EVENT_TYPE_PROVIDER_DRIFT, EVENT_TYPE_GUARDRAIL_BYPASS,
    EVENT_TYPE_UNSIGNED_PROMPT_CHANGE, EVENT_TYPE_SCOPE_VIOLATION,
    EVENT_TYPE_CHAIN_BREAK, EVENT_TYPE_BEHAVIOUR_DRIFT
    EVENT_TYPES: frozenset of all recognised values
    CURRENT_FORMAT_VERSION: the chain hash format used by new writes

Optional API (requires ``pip install "nexuscone[signing]"``):
    nexuscone.signing.Ed25519Signer
    nexuscone.signing.Ed25519Verifier
"""

from nexuscone.canonical import canonical_json, sha256_hex
from nexuscone.chain import (
    CURRENT_FORMAT_VERSION,
    EVENT_TYPE_BEHAVIOUR_DRIFT,
    EVENT_TYPE_CHAIN_BREAK,
    EVENT_TYPE_COST_ANOMALY,
    EVENT_TYPE_GUARDRAIL_BYPASS,
    EVENT_TYPE_PROVIDER_DRIFT,
    EVENT_TYPE_REQUEST,
    EVENT_TYPE_SCHEMA_DRIFT,
    EVENT_TYPE_SCOPE_VIOLATION,
    EVENT_TYPE_UNSIGNED_PROMPT_CHANGE,
    EVENT_TYPES,
    GENESIS_PREVIOUS_HASH,
    ChainVerificationError,
    Ledger,
    LedgerEntry,
)

__version__ = "0.2.1"

__all__ = [
    "CURRENT_FORMAT_VERSION",
    "EVENT_TYPE_BEHAVIOUR_DRIFT",
    "EVENT_TYPE_CHAIN_BREAK",
    "EVENT_TYPE_COST_ANOMALY",
    "EVENT_TYPE_GUARDRAIL_BYPASS",
    "EVENT_TYPE_PROVIDER_DRIFT",
    "EVENT_TYPE_REQUEST",
    "EVENT_TYPE_SCHEMA_DRIFT",
    "EVENT_TYPE_SCOPE_VIOLATION",
    "EVENT_TYPE_UNSIGNED_PROMPT_CHANGE",
    "EVENT_TYPES",
    "GENESIS_PREVIOUS_HASH",
    "ChainVerificationError",
    "Ledger",
    "LedgerEntry",
    "canonical_json",
    "sha256_hex",
    "__version__",
]
