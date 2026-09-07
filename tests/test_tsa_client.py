"""Tests for the TSA and OpenTimestamps clients against a local mock HTTP server.

The real endpoints are not reachable from CI. These tests cover the request
encoding, the response validation, and the calendar failover, which is
everything in the client except the network itself.
"""

from __future__ import annotations

import base64
import hashlib
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from retina_custody.tsa_client import (
    OpenTimestampsClient,
    TimestampManager,
    TSAClient,
    _build_tsa_request,
    _tsa_response_ok,
)

DIGEST_HEX = hashlib.sha256(b"probe").hexdigest()
DIGEST = bytes.fromhex(DIGEST_HEX)


def der_seq(*parts: bytes) -> bytes:
    body = b"".join(parts)
    assert len(body) < 128
    return b"\x30" + bytes([len(body)]) + body


def der_int(v: int) -> bytes:
    return b"\x02\x01" + bytes([v])


TOKEN = der_seq(der_int(1))  # stand-in for a real timeStampToken; the client does not parse it
GRANTED = der_seq(der_seq(der_int(0)), TOKEN)
GRANTED_WITH_MODS = der_seq(der_seq(der_int(1)), TOKEN)
REJECTED = der_seq(der_seq(der_int(2)))
GRANTED_NO_TOKEN = der_seq(der_seq(der_int(0)))


class MockServer:
    """Single-threaded HTTP server that records requests and serves a scripted response per path.

    Shutting one down costs 0.5 s (HTTPServer.shutdown polls), so the fixtures
    below share two servers across the module and reset them between tests.
    """

    def __init__(self):
        self.requests: list[dict] = []
        self.responses: dict[str, tuple[int, bytes]] = {}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                outer.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                status, payload = outer.responses.get(self.path, (404, b""))
                self.send_response(status)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    def reset(self):
        self.requests.clear()
        self.responses.clear()


@pytest.fixture(scope="module")
def _servers():
    with MockServer() as a, MockServer() as b:
        yield a, b


@pytest.fixture()
def server(_servers):
    _servers[0].reset()
    return _servers[0]


@pytest.fixture()
def second(_servers):
    _servers[1].reset()
    return _servers[1]


def unused_port_url() -> str:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return f"http://127.0.0.1:{sock.getsockname()[1]}"


# ── Request encoding ─────────────────────────────────────────────────────────


class TestBuildTsaRequest:
    def test_structure(self):
        der = _build_tsa_request(DIGEST)
        # TimeStampReq SEQUENCE { version, MessageImprint, nonce, certReq }
        assert der[0] == 0x30
        assert der[1] == len(der) - 2
        body = der[2:]
        assert body[:3] == b"\x02\x01\x01"  # version 1
        imprint_len = body[4]
        imprint = body[5 : 5 + imprint_len]
        sha256_alg = b"\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00"
        assert imprint.startswith(sha256_alg)
        assert imprint[len(sha256_alg) :] == b"\x04\x20" + DIGEST
        rest = body[5 + imprint_len :]
        assert rest[0] == 0x02 and rest[1] == 8  # 8-byte nonce INTEGER
        assert rest[10:] == b"\x01\x01\xff"  # certReq TRUE

    def test_nonce_differs_between_requests(self):
        a, b = _build_tsa_request(DIGEST), _build_tsa_request(DIGEST)
        assert a[:-11] == b[:-11]  # identical up to the nonce
        assert a[-11:-3] != b[-11:-3]  # nonce differs
        assert a[-3:] == b[-3:]  # certReq identical

    def test_nonce_is_non_negative_integer(self):
        der = _build_tsa_request(DIGEST)
        nonce = der[-11:-3]
        assert nonce[0] & 0x80 == 0  # DER INTEGER with clear sign bit


# ── Response validation ──────────────────────────────────────────────────────


class TestTsaResponseValidation:
    @pytest.mark.parametrize("resp", [GRANTED, GRANTED_WITH_MODS])
    def test_granted_accepted(self, resp):
        assert _tsa_response_ok(resp) == (True, "ok")

    def test_rejected_status(self):
        ok, reason = _tsa_response_ok(REJECTED)
        assert not ok and "PKIStatus 2" in reason

    def test_granted_without_token(self):
        ok, reason = _tsa_response_ok(GRANTED_NO_TOKEN)
        assert not ok and "no timeStampToken" in reason

    def test_not_a_sequence(self):
        ok, _ = _tsa_response_ok(b"<html>error</html>")
        assert not ok

    def test_truncated(self):
        ok, _ = _tsa_response_ok(GRANTED[:5])
        assert not ok

    def test_empty(self):
        ok, _ = _tsa_response_ok(b"")
        assert not ok

    def test_long_form_length(self):
        # Outer SEQUENCE with a 2-byte length; content is a granted status plus a 200-byte token.
        token = b"\x30\x81\xc8" + b"\x05\x00" * 100
        body = der_seq(der_int(0)) + token
        resp = b"\x30\x81" + bytes([len(body)]) + body
        assert _tsa_response_ok(resp) == (True, "ok")


# ── TSAClient against a mock server ──────────────────────────────────────────


class TestTSAClient:
    def test_sends_well_formed_request_and_returns_token(self, server):
        server.responses["/"] = (200, GRANTED)
        token = TSAClient(url=server.url + "/").request_timestamp(DIGEST_HEX)
        assert token is not None
        assert base64.b64decode(token) == GRANTED
        (req,) = server.requests
        assert req["headers"]["Content-Type"] == "application/timestamp-query"
        assert req["body"][0] == 0x30
        assert DIGEST in req["body"]

    def test_rejected_response_returns_none(self, server):
        server.responses["/"] = (200, REJECTED)
        assert TSAClient(url=server.url + "/").request_timestamp(DIGEST_HEX) is None

    def test_http_error_returns_none(self, server):
        server.responses["/"] = (500, b"boom")
        assert TSAClient(url=server.url + "/").request_timestamp(DIGEST_HEX) is None

    def test_connection_refused_returns_none(self):
        assert TSAClient(url=unused_port_url() + "/").request_timestamp(DIGEST_HEX) is None

    def test_bad_hex_returns_none(self, server):
        server.responses["/"] = (200, GRANTED)
        assert TSAClient(url=server.url + "/").request_timestamp("not-hex") is None
        assert server.requests == []


# ── OpenTimestampsClient against a mock server ───────────────────────────────


class TestOpenTimestampsClient:
    def test_submits_raw_digest_and_returns_proof(self, server):
        server.responses["/digest"] = (200, b"\x00proof-bytes")
        proof = OpenTimestampsClient(calendar_urls=[server.url]).submit(DIGEST_HEX)
        assert base64.b64decode(proof) == b"\x00proof-bytes"
        (req,) = server.requests
        assert req["path"] == "/digest"
        assert req["body"] == DIGEST
        assert req["headers"]["Content-Type"] == "application/x-opentimestamps"

    def test_fails_over_to_next_calendar(self, server, second):
        server.responses["/digest"] = (500, b"")
        second.responses["/digest"] = (200, b"ok")
        proof = OpenTimestampsClient(calendar_urls=[server.url, second.url]).submit(DIGEST_HEX)
        assert base64.b64decode(proof) == b"ok"
        assert len(server.requests) == 1
        assert len(second.requests) == 1

    def test_unreachable_calendar_is_skipped(self, server):
        server.responses["/digest"] = (200, b"ok")
        proof = OpenTimestampsClient(calendar_urls=[unused_port_url(), server.url]).submit(DIGEST_HEX)
        assert base64.b64decode(proof) == b"ok"

    def test_all_calendars_fail_returns_none(self, server):
        server.responses["/digest"] = (500, b"")
        assert OpenTimestampsClient(calendar_urls=[server.url, server.url]).submit(DIGEST_HEX) is None
        assert len(server.requests) == 2

    def test_empty_body_treated_as_failure(self, server):
        server.responses["/digest"] = (200, b"")
        assert OpenTimestampsClient(calendar_urls=[server.url]).submit(DIGEST_HEX) is None


# ── TimestampManager ─────────────────────────────────────────────────────────


class TestTimestampManager:
    def test_returns_both_when_available(self, server):
        server.responses["/"] = (200, GRANTED)
        server.responses["/digest"] = (200, b"ots")
        mgr = TimestampManager()
        mgr.tsa = TSAClient(url=server.url + "/")
        mgr.ots = OpenTimestampsClient(calendar_urls=[server.url])
        tsa, ots = mgr.timestamp_entry(DIGEST_HEX)
        assert base64.b64decode(tsa) == GRANTED
        assert base64.b64decode(ots) == b"ots"

    def test_disabled_services_return_none(self):
        assert TimestampManager(enable_tsa=False, enable_ots=False).timestamp_entry(DIGEST_HEX) == (None, None)

    def test_one_failure_does_not_block_the_other(self, server):
        server.responses["/"] = (500, b"")
        server.responses["/digest"] = (200, b"ots")
        mgr = TimestampManager()
        mgr.tsa = TSAClient(url=server.url + "/")
        mgr.ots = OpenTimestampsClient(calendar_urls=[server.url])
        assert mgr.timestamp_entry(DIGEST_HEX) == (None, base64.b64encode(b"ots").decode())
