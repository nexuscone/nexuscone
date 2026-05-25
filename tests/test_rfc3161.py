"""Tests for the RFC 3161 TSA submission primitive.

submit_to_tsa is wrapped around urllib.request.urlopen at module scope
so tests can monkeypatch nexuscone.rfc3161.urlopen with a stand-in
that simulates whichever TSA behaviour each test cares about. No real
network traffic fires in this suite.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from nexuscone import rfc3161
from nexuscone.rfc3161 import (
    DEFAULT_TSA_URLS,
    TSAError,
    submit_to_tsa,
    verify_tst,
)


class _FakeHttpResponse:
    """Stand-in for urllib's http.client.HTTPResponse context manager."""

    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeHttpResponse:
        return self

    def __exit__(self, *_: Any) -> None:
        return None


def test_default_tsa_urls_lists_freetsa_first() -> None:
    """FreeTSA is the free public option. It leads the default list so
    a customer who has not configured a commercial TSA still gets a
    working RFC 3161 anchor out of the box."""
    assert DEFAULT_TSA_URLS[0] == "https://freetsa.org/tsr"
    assert len(DEFAULT_TSA_URLS) >= 1


def test_submit_to_tsa_returns_response_on_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real-shape TSA response is decoded into a TSAResponse with
    the expected fields populated."""
    body = _real_freetsa_grant_body()

    def fake_urlopen(req: Any, timeout: int | None = None) -> _FakeHttpResponse:
        assert req.headers.get("Content-type") == "application/timestamp-query"
        return _FakeHttpResponse(200, body)

    monkeypatch.setattr(rfc3161, "urlopen", fake_urlopen)
    response = submit_to_tsa(b"\x00" * 32, "https://freetsa.test.invalid/tsr")

    assert response.tsa_url == "https://freetsa.test.invalid/tsr"
    assert response.tst_blob == body
    assert response.serial_number != ""
    assert isinstance(response.gen_time, datetime)
    assert response.gen_time.tzinfo is not None
    # Hash algorithm comes back as a dotted OID string.
    assert "." in response.hash_algorithm


def test_submit_to_tsa_raises_on_http_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(req: Any, timeout: int | None = None) -> _FakeHttpResponse:
        return _FakeHttpResponse(503, b"service unavailable")

    monkeypatch.setattr(rfc3161, "urlopen", fake_urlopen)
    with pytest.raises(TSAError, match="HTTP 503"):
        submit_to_tsa(b"\x00" * 32, "https://broken.test.invalid/tsr")


def test_submit_to_tsa_raises_on_network_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(req: Any, timeout: int | None = None) -> _FakeHttpResponse:
        raise ConnectionError("simulated DNS failure")

    monkeypatch.setattr(rfc3161, "urlopen", fake_urlopen)
    with pytest.raises(TSAError, match="HTTP submission failed"):
        submit_to_tsa(b"\x00" * 32, "https://unreachable.test.invalid/tsr")


def test_submit_to_tsa_raises_on_malformed_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(req: Any, timeout: int | None = None) -> _FakeHttpResponse:
        return _FakeHttpResponse(200, b"not a valid TimeStampResp DER")

    monkeypatch.setattr(rfc3161, "urlopen", fake_urlopen)
    with pytest.raises(TSAError, match="malformed TimeStampResp"):
        submit_to_tsa(b"\x00" * 32, "https://lying.test.invalid/tsr")


def test_verify_tst_accepts_the_real_grant_fixture() -> None:
    """The recorded FreeTSA grant was minted against b"\\x00" * 32. The
    verifier rederives the SHA-256 imprint and confirms it matches."""
    body = _real_freetsa_grant_body()
    response = verify_tst(body, b"\x00" * 32, tsa_url="https://freetsa.test.invalid/tsr")
    assert response.tsa_url == "https://freetsa.test.invalid/tsr"
    assert response.tst_blob == body
    assert response.hash_algorithm == "2.16.840.1.101.3.4.2.1"
    assert response.gen_time.tzinfo is not None


def test_verify_tst_rejects_digest_mismatch() -> None:
    """A TST minted for one digest must not verify against another."""
    body = _real_freetsa_grant_body()
    with pytest.raises(TSAError, match="message imprint does not match"):
        verify_tst(body, b"\x01" * 32)


def test_verify_tst_rejects_malformed_blob() -> None:
    """A bytes blob that is not a valid TimeStampResp DER raises."""
    with pytest.raises(TSAError, match="Malformed TimeStampResp"):
        verify_tst(b"not a real timestamp response", b"\x00" * 32)


def _real_freetsa_grant_body() -> bytes:
    """Return a real FreeTSA grant response body cached on disk.

    The fixture file at tests/fixtures/freetsa_grant.tsr.bin was
    captured from the live FreeTSA endpoint and committed so the
    suite is offline-deterministic. When the fixture is missing the
    test that needs it is skipped with a clear message rather than
    hitting the network silently.
    """
    fixture_path = Path(__file__).parent / "fixtures" / "freetsa_grant.tsr.bin"
    if not fixture_path.exists():
        pytest.skip(
            f"Missing fixture {fixture_path}; re-record by submitting "
            f"to https://freetsa.org/tsr with a SHA-256 digest input."
        )
    return fixture_path.read_bytes()
