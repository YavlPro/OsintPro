"""
API Tests for the OsintPro web interface
=========================================
All external calls (Etherscan, Blockstream, URLhaus, GitHub, HIBP, WHOIS,
SSL) are mocked so the suite runs fully offline and deterministically.
"""

import os
import sys
from pathlib import Path

# Deterministic environment BEFORE importing web.app (load_dotenv must not
# override these, and analyzers must be created without real keys).
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["ETHERSCAN_API_KEY"] = ""
os.environ["HIBP_API_KEY"] = ""

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import socket
import tldextract
import whois
import requests
from datetime import datetime, timedelta
from types import SimpleNamespace
from urllib.parse import urlparse
from unittest.mock import Mock

import pytest

import web.app as webapp


# ---------------------------------------------------------------------------
# Mock infrastructure
# ---------------------------------------------------------------------------
class FakeResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(self, json_data=None, status_code=200, text="", url=""):
        self._json = json_data if json_data is not None else {}
        self.status_code = status_code
        self.text = text
        self.url = url
        self.elapsed = timedelta(seconds=0.1)

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} error")


def route(url, method="get", **kwargs):
    """Return a FakeResponse based on the requested URL/params."""
    if "api.etherscan.io" in url:
        action = (kwargs.get("params") or {}).get("action")
        if action == "balance":
            return FakeResponse({"status": "1", "message": "OK", "result": "1000000000000000000"})
        return FakeResponse({"status": "1", "message": "OK", "result": []})
    if "blockstream.info" in url:
        return FakeResponse({
            "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "chain_stats": {
                "funded_txo_count": 2, "funded_txo_sum": 5000000000,
                "spent_txo_count": 1, "spent_txo_sum": 2000000000,
                "tx_count": 5,
            },
            "mempool_stats": {},
        })
    if "urlhaus-api.abuse.ch" in url:
        return FakeResponse({"query_status": "no_results"})
    if "api.github.com" in url:
        if url.endswith("/commits"):
            return FakeResponse([{"sha": "a" * 40} for _ in range(12)])
        if url.endswith("/readme"):
            return FakeResponse({"content": "fake readme"})
        return FakeResponse({
            "description": "Test repo",
            "stargazers_count": 42,
            "forks_count": 7,
            "open_issues_count": 1,
            "language": "Python",
            "created_at": "2020-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "license": None,
        })
    # Generic website fetch (project analyzer)
    return FakeResponse(
        status_code=200,
        url=url,
        text="welcome terms of service privacy policy contact us",
    )


class FakeSession:
    """Replaces requests.Session for every analyzer (also works where
    tldextract mounts a file adapter — not that we let it hit the network)."""

    def __init__(self, *args, **kwargs):
        self.headers = {}

    def get(self, url, **kwargs):
        return route(url, method="get", **kwargs)

    def post(self, url, **kwargs):
        return route(url, method="post", **kwargs)

    def mount(self, *args, **kwargs):
        return None

    def close(self):
        return None


def fake_extract(url):
    """Deterministic replacement for tldextract.extract (no network)."""
    netloc = urlparse(url).netloc or str(url)
    netloc = netloc.split(":")[0]
    parts = netloc.split(".")
    if len(parts) >= 2:
        return SimpleNamespace(
            subdomain=".".join(parts[:-2]) if len(parts) > 2 else "",
            domain=parts[-2],
            suffix=parts[-1],
        )
    return SimpleNamespace(subdomain="", domain=parts[0], suffix="")


FAKE_WHOIS = SimpleNamespace(
    creation_date=datetime(2020, 1, 1),
    expiration_date=datetime(2030, 1, 1),
    registrar="Fake Registrar",
    name_servers=["ns1.fake.com", "ns2.fake.com"],
    status=["clientTransferProhibited"],
    name="Fake Name",
    org="Fake Org",
    country="US",
)


@pytest.fixture(autouse=True)
def mock_external_services(monkeypatch):
    monkeypatch.setattr(requests, "Session", FakeSession)
    monkeypatch.setattr(whois, "whois", lambda domain: FAKE_WHOIS)
    monkeypatch.setattr(tldextract, "extract", fake_extract)

    def _blocked_socket(*args, **kwargs):
        raise OSError("connection blocked by test mock")

    monkeypatch.setattr(socket, "create_connection", _blocked_socket)

    # The analyzers in web.app were instantiated at import time with a real
    # requests.Session — swap their sessions for the fake one.
    for obj in (
        webapp.wallet_checker,
        webapp.wallet_checker.eth_analyzer,
        webapp.wallet_checker.btc_analyzer,
        webapp.url_checker,
        webapp.email_analyzer,
        webapp.domain_checker,
        webapp.project_analyzer,
        webapp.breach_checker,
    ):
        if hasattr(obj, "session"):
            obj.session = FakeSession()


@pytest.fixture
def client():
    webapp.app.config["TESTING"] = True
    webapp.rate_limiter._hits.clear()
    with webapp.app.test_client() as c:
        yield c
    webapp.rate_limiter._hits.clear()


# ---------------------------------------------------------------------------
# Configuration tests
# ---------------------------------------------------------------------------
class TestConfiguration:
    def test_secret_key_comes_from_env(self):
        assert webapp.app.secret_key == "test-secret-key"

    def test_analyzers_created_without_keys_by_default(self):
        assert webapp.wallet_checker.eth_analyzer.api_key is None
        assert webapp.email_analyzer.hibp_api_key is None
        assert webapp.breach_checker.hibp_api_key is None


# ---------------------------------------------------------------------------
# Endpoint tests
# ---------------------------------------------------------------------------
class TestIndex:
    def test_index_page(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"OsintPro" in resp.data


class TestCrypto:
    def test_ethereum_wallet(self, client):
        resp = client.post("/api/crypto/check", json={"address": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD3e"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["network"] == "Ethereum"
        assert data["balance"]["balance_eth"] == 1.0

    def test_bitcoin_wallet(self, client):
        resp = client.post("/api/crypto/check", json={"address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["network"] == "Bitcoin"
        assert data["address_info"]["balance_btc"] == 30.0

    def test_unknown_address_returns_error_payload(self, client):
        resp = client.post("/api/crypto/check", json={"address": "not-an-address"})
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "error"

    def test_missing_address_returns_400(self, client):
        resp = client.post("/api/crypto/check", json={})
        assert resp.status_code == 400


class TestPhishing:
    def test_url_check(self, client):
        resp = client.post("/api/phishing/url", json={"url": "https://example.com"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["overall_risk"] in ("MINIMAL", "LOW", "MEDIUM", "HIGH")
        assert data["structure_analysis"]["domain"] == "example.com"

    def test_email_check(self, client):
        resp = client.post("/api/phishing/email", json={"email": "user@example.com"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["validation"]["is_valid_format"] is True

    def test_domain_check(self, client):
        resp = client.post("/api/phishing/domain", json={"domain": "example.com"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["domain"] == "example.com"
        assert "SSL" in " ".join(data["risk_factors"]) or data["ssl"]["valid"] is False

    def test_missing_email_returns_400(self, client):
        resp = client.post("/api/phishing/email", json={})
        assert resp.status_code == 400


class TestDomain:
    def test_whois_lookup(self, client):
        resp = client.post("/api/domain/whois", json={"domain": "example.com"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status_code"] == "success"
        assert data["registrar"] == "Fake Registrar"
        assert data["domain_age_days"] > 0

    def test_project_analysis(self, client):
        resp = client.post("/api/domain/project", json={
            "name": "TestCoin",
            "website": "https://example.com",
            "github": "https://github.com/owner/repo",
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["github_analysis"]["stars"] == 42
        assert data["overall_risk"] in ("LOW", "MEDIUM", "HIGH")

    def test_project_missing_fields_returns_400(self, client):
        resp = client.post("/api/domain/project", json={"name": "OnlyName"})
        assert resp.status_code == 400


class TestBreach:
    def test_breach_check_without_key(self, client):
        resp = client.post("/api/breach/check", json={"email": "user@example.com"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["hibp"]["status"] == "skipped"

    def test_breach_check_missing_email_returns_400(self, client):
        resp = client.post("/api/breach/check", json={})
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
class TestRateLimit:
    def test_api_rate_limit_enforced(self, client, monkeypatch):
        monkeypatch.setenv("RATE_LIMIT_API", "2")
        webapp.rate_limiter._hits.clear()
        for _ in range(2):
            resp = client.post("/api/crypto/check", json={"address": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD3e"})
            assert resp.status_code == 200
        resp = client.post("/api/crypto/check", json={"address": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD3e"})
        assert resp.status_code == 429
        assert resp.get_json()["status"] == 429

    def test_web_route_not_limited_by_api_limit(self, client, monkeypatch):
        monkeypatch.setenv("RATE_LIMIT_API", "1")
        monkeypatch.setenv("RATE_LIMIT_WEB", "5")
        webapp.rate_limiter._hits.clear()
        for _ in range(3):
            resp = client.get("/")
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Unit tests for key wiring (keys passed through to providers)
# ---------------------------------------------------------------------------
class TestKeyWiring:
    def test_etherscan_key_passed_in_params(self, monkeypatch):
        from src.crypto import EthereumAnalyzer

        session = Mock()
        session.get.return_value = FakeResponse({"status": "1", "message": "OK", "result": "1"})
        monkeypatch.setattr(requests, "Session", lambda *a, **k: session)

        analyzer = EthereumAnalyzer(api_key="secret-key-123")
        analyzer.get_balance("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD3e")
        params = session.get.call_args.kwargs["params"]
        assert params["apikey"] == "secret-key-123"

    def test_hibp_found(self, monkeypatch):
        from src.breach_monitor import BreachChecker

        payload = [{"Name": "Adobe", "BreachDate": "2013-10-04", "PwnCount": 152445165,
                    "DataClasses": ["Email addresses"]}]
        session = Mock()
        session.get.return_value = FakeResponse(payload, status_code=200)
        monkeypatch.setattr(requests, "Session", lambda *a, **k: session)

        checker = BreachChecker(hibp_api_key="test-key")
        result = checker.check_haveibeenpwned("user@example.com")
        assert result["found"] is True
        assert result["breach_count"] == 1
        assert result["breaches"][0]["name"] == "Adobe"

    def test_hibp_not_found(self, monkeypatch):
        from src.breach_monitor import BreachChecker

        session = Mock()
        session.get.return_value = FakeResponse({}, status_code=404)
        monkeypatch.setattr(requests, "Session", lambda *a, **k: session)

        checker = BreachChecker(hibp_api_key="test-key")
        result = checker.check_haveibeenpwned("nobody@example.com")
        assert result["found"] is False
        assert result["breach_count"] == 0
