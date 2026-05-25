"""RFC 3161 Time-Stamp Authority submission.

A parallel proof to OpenTimestamps. Where OpenTimestamps anchors the
chain head to Bitcoin (trust-minimised but ~1 hour confirmation), an
RFC 3161 TSA returns a signed TimeStampToken immediately, attesting
that a digest was submitted at a given time under the TSA's
certificate. The two proofs sit side by side on the anchor row: a
regulator who prefers a regulated TSA over a public blockchain can
verify the TST; an auditor who prefers proof-of-work can verify the
OpenTimestamps proof; an audit that wants both gets both.

The high-level shape:

    digest = bytes.fromhex(ledger_entry.entry_hash)
    response = submit_to_tsa(digest, "https://freetsa.org/tsr")
    # response.tst_blob is the full TimeStampResp DER, persisted in
    # the anchor row's tst_blob column.

Mocking in tests: submit_to_tsa goes through the module-level urlopen
binding. A test can monkeypatch nexuscone.rfc3161.urlopen to control
the simulated TSA response without making real network calls.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.request import Request, urlopen

from rfc3161_client import (
    HashAlgorithm,
    PKIStatus,
    TimestampRequestBuilder,
    decode_timestamp_response,
)

_SHA256_OID = "2.16.840.1.101.3.4.2.1"

DEFAULT_TSA_URLS: list[str] = [
    "https://freetsa.org/tsr",
    "http://timestamp.digicert.com",
    "http://timestamp.sectigo.com",
]

_TIMESTAMP_QUERY_CONTENT_TYPE = "application/timestamp-query"


class TSAError(Exception):
    """Raised when a TSA submission fails for any reason.

    Wraps the underlying cause (network failure, malformed response,
    non-success PKIStatus) so callers can catch one exception type
    regardless of where the failure surfaced.
    """


@dataclass(frozen=True, slots=True)
class TSAResponse:
    """One successful TSA submission.

    Fields:
        tst_blob:        the full TimeStampResp DER, as the TSA returned
                         it. Persisted verbatim so a future verifier can
                         re-parse it without needing the original
                         TimeStampToken extraction logic.
        tsa_url:         the URL that returned this token.
        gen_time:        the TSA's stated time of attestation, parsed
                         from the TST's genTime field.
        hash_algorithm:  the dotted OID of the hash algorithm the TSA
                         used in its message imprint (for example
                         "2.16.840.1.101.3.4.2.1" for SHA-256). Stored
                         as the dotted form rather than a friendly name
                         because cryptography's ObjectIdentifier exposes
                         dotted_string as its only stable public
                         attribute. A small lookup is the caller's
                         responsibility when a friendlier label is
                         needed.
        serial_number:   the TST serial number, as a decimal string.
                         Useful for log lines and TSA-side correlation;
                         not authoritative for verification.
    """

    tst_blob: bytes
    tsa_url: str
    gen_time: datetime
    hash_algorithm: str
    serial_number: str


def submit_to_tsa(
    digest: bytes,
    tsa_url: str,
    timeout_seconds: int = 30,
) -> TSAResponse:
    """Submit a digest to an RFC 3161 TSA, return the signed TimeStampToken.

    The digest argument is the data being timestamped, not a pre-computed
    hash of it. The rfc3161_client builder hashes the bytes internally
    under the chosen algorithm (SHA-256 here) before submission, so the
    TSA's message imprint commits to sha256(digest_bytes). Verification
    must rehash the stored digest under the same algorithm to compare
    against the TST's stored imprint.

    Raises TSAError on any failure: network error, non-200 HTTP status,
    malformed TimeStampResp, or PKIStatus other than GRANTED or
    GRANTED_WITH_MODS.
    """
    builder = (
        TimestampRequestBuilder()
        .data(digest)
        .hash_algorithm(HashAlgorithm.SHA256)
        .nonce(nonce=False)
    )
    request_der = builder.build().as_bytes()

    http_request = Request(
        tsa_url,
        data=request_der,
        headers={"Content-Type": _TIMESTAMP_QUERY_CONTENT_TYPE},
    )
    try:
        with urlopen(http_request, timeout=timeout_seconds) as http_response:
            status = http_response.status
            body = http_response.read()
    except Exception as exc:  # noqa: BLE001
        raise TSAError(f"TSA HTTP submission failed for {tsa_url}: {exc!r}") from exc

    if status != 200:
        raise TSAError(
            f"TSA {tsa_url} returned HTTP {status}, expected 200"
        )

    try:
        response = decode_timestamp_response(body)
    except Exception as exc:  # noqa: BLE001
        raise TSAError(
            f"TSA {tsa_url} returned a malformed TimeStampResp: {exc!r}"
        ) from exc

    pki_status = int(response.status)
    if pki_status not in (int(PKIStatus.GRANTED), int(PKIStatus.GRANTED_WITH_MODS)):
        raise TSAError(
            f"TSA {tsa_url} rejected the request, PKIStatus={pki_status}"
        )

    tst_info = response.tst_info
    if tst_info is None:
        raise TSAError(f"TSA {tsa_url} response had no TSTInfo")

    gen_time = tst_info.gen_time
    if gen_time.tzinfo is None:
        gen_time = gen_time.replace(tzinfo=timezone.utc)

    hash_algorithm_oid = tst_info.message_imprint.hash_algorithm.dotted_string
    serial_number = str(tst_info.serial_number)

    return TSAResponse(
        tst_blob=body,
        tsa_url=tsa_url,
        gen_time=gen_time,
        hash_algorithm=hash_algorithm_oid,
        serial_number=serial_number,
    )


def verify_tst(
    tst_blob: bytes,
    digest: bytes,
    *,
    tsa_url: str = "",
) -> TSAResponse:
    """Verify a stored TimeStampToken against the digest it covers.

    Decodes the TST, confirms the PKIStatus is GRANTED, recomputes
    sha256(digest), and confirms the recomputed imprint equals the
    message imprint inside the TST. Returns the parsed TSAResponse on
    success; raises TSAError on any structural or content mismatch.

    Verification is content-only and deliberately does NOT validate the
    TSA certificate chain against a trust store. Chain validation is a
    higher-tier verifier responsibility that lives outside v0.2.0.

    Only SHA-256 imprints are supported. submit_to_tsa always uses
    SHA-256, so any TST in a nexuscone-produced database will have the
    expected algorithm; a non-SHA-256 imprint indicates a TST minted
    outside this package and is rejected explicitly.
    """
    try:
        response = decode_timestamp_response(tst_blob)
    except Exception as exc:  # noqa: BLE001
        raise TSAError(f"Malformed TimeStampResp: {exc!r}") from exc

    pki_status = int(response.status)
    if pki_status not in (int(PKIStatus.GRANTED), int(PKIStatus.GRANTED_WITH_MODS)):
        raise TSAError(
            f"TST PKIStatus={pki_status}, expected GRANTED or GRANTED_WITH_MODS"
        )

    tst_info = response.tst_info
    if tst_info is None:
        raise TSAError("TST has no TSTInfo")

    imprint = tst_info.message_imprint
    hash_algorithm_oid = imprint.hash_algorithm.dotted_string
    if hash_algorithm_oid != _SHA256_OID:
        raise TSAError(
            f"TST imprint hash {hash_algorithm_oid} is not SHA-256; "
            "v0.2.0 verifier only supports SHA-256 imprints."
        )

    expected = hashlib.sha256(digest).digest()
    stored = bytes(imprint.message)
    if expected != stored:
        raise TSAError(
            "TST message imprint does not match sha256(digest); "
            f"expected {expected.hex()}, stored {stored.hex()}"
        )

    gen_time = tst_info.gen_time
    if gen_time.tzinfo is None:
        gen_time = gen_time.replace(tzinfo=timezone.utc)

    return TSAResponse(
        tst_blob=tst_blob,
        tsa_url=tsa_url,
        gen_time=gen_time,
        hash_algorithm=hash_algorithm_oid,
        serial_number=str(tst_info.serial_number),
    )
