import pytest
from requests import exceptions

from SatyamSingh_AutomatedWebSecurityScanner import scan_url, validate_url


def test_validate_url_accepts_http_and_https():
    assert validate_url("https://example.com/path").scheme == "https"
    assert validate_url("http://localhost:8000").scheme == "http"


def test_validate_url_rejects_invalid_urls():
    with pytest.raises(ValueError):
        validate_url("not-a-url")
    with pytest.raises(ValueError):
        validate_url(123)
    with pytest.raises(ValueError):
        validate_url("")


def test_scan_url_reports_successful_response_with_headers():
    class DummyResponse:
        status_code = 200
        url = "https://example.com/"
        history = []
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
            "Access-Control-Allow-Origin": "https://example.com",
            "Access-Control-Allow-Credentials": "true",
        }

    import requests

    def fake_get(*args, **kwargs):
        return DummyResponse()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(requests, "get", fake_get)
    try:
        result = scan_url("https://example.com")
    finally:
        monkeypatch.undo()

    assert result["http_status"] == 200
    assert result["summary"]["request_succeeded"] is True
    assert result["summary"]["headers_present"] >= 6
    assert result["cors_review"]["wildcard_origin_observed"] is False


def test_scan_url_reports_missing_security_headers():
    class DummyResponse:
        status_code = 404
        url = "https://example.com/missing"
        history = []
        headers = {"Server": "nginx"}

    import requests

    def fake_get(*args, **kwargs):
        return DummyResponse()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(requests, "get", fake_get)
    try:
        result = scan_url("https://example.com/missing")
    finally:
        monkeypatch.undo()

    assert result["http_status"] == 404
    missing_headers = [item for item in result["findings"] if item["status"] == "Missing"]
    assert len(missing_headers) == len(result["findings"])
    assert result["summary"]["headers_missing"] == len(result["findings"])


def test_scan_url_handles_timeout():
    import requests

    def fake_get(*args, **kwargs):
        raise exceptions.Timeout("timed out")

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(requests, "get", fake_get)
    try:
        result = scan_url("https://example.com")
    finally:
        monkeypatch.undo()

    assert result["summary"]["request_succeeded"] is False
    assert any("timed out" in msg.lower() for msg in result["errors"])


def test_scan_url_handles_connection_errors():
    import requests

    def fake_get(*args, **kwargs):
        raise exceptions.ConnectionError("connection refused")

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(requests, "get", fake_get)
    try:
        result = scan_url("https://example.com")
    finally:
        monkeypatch.undo()

    assert result["summary"]["request_succeeded"] is False
    assert any("connection" in msg.lower() for msg in result["errors"])


def test_scan_url_handles_unexpected_response_conditions():
    class DummyResponse:
        status_code = 200
        url = "https://example.com/"
        history = []
        headers = {}

    import requests

    def fake_get(*args, **kwargs):
        return DummyResponse()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(requests, "get", fake_get)
    try:
        result = scan_url("https://example.com")
    finally:
        monkeypatch.undo()

    assert result["http_status"] == 200
    assert all(item["status"] == "Missing" for item in result["findings"])
    assert result["summary"]["headers_missing"] == len(result["findings"])


def test_scan_url_handles_invalid_url_in_request_path():
    with pytest.raises(ValueError):
        scan_url("ftp://example.com")
