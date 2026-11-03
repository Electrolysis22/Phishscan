import socket

import pytest
import requests
from bs4 import BeautifulSoup

import analyzer
import app as app_module
import engine
from features import normalize, reg_domain


def titles(findings):
    return {f["title"] for f in findings}


def finding(category, severity, points, title="x"):
    return {"category": category, "severity": severity, "points": points, "title": title, "detail": ""}


def test_normalize_adds_https():
    assert normalize("example.com/login") == "https://example.com/login"
    assert normalize("http://example.com") == "http://example.com"


def test_reg_domain():
    assert reg_domain("login.paypal.com") == "paypal.com"
    assert reg_domain("a.b.example.co.uk") == "example.co.uk"


@pytest.mark.parametrize("ip,expected", [
    ("127.0.0.1", False),
    ("10.1.2.3", False),
    ("192.168.0.5", False),
    ("169.254.169.254", False),
    ("::1", False),
    ("::ffff:127.0.0.1", False),
    ("8.8.8.8", True),
])
def test_is_public_ip(ip, expected):
    assert analyzer.is_public_ip(ip) is expected


def test_rebinding_to_loopback_is_blocked(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(analyzer, "ALLOW_PRIVATE", False)
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    session = requests.Session()
    session.trust_env = False
    with pytest.raises(requests.exceptions.ConnectionError):
        session.get("http://rebind.example/", timeout=2)


def test_ip_host_is_flagged():
    found = analyzer.url_findings("http://203.0.113.5/login", 0.1)
    assert "IP address used instead of a domain name" in titles(found)


def test_brand_on_wrong_domain_is_flagged():
    found = analyzer.url_findings("https://paypal-secure-login.xyz/", 0.1)
    assert any(t.startswith("Domain mentions 'paypal'") for t in titles(found))


def test_official_brand_domain_is_not_flagged():
    found = analyzer.url_findings("https://www.paypal.com/signin", 0.1)
    assert not any("mentions" in t or "references" in t for t in titles(found))


FAKE_PAGE = """<html><head><title>PayPal - Log in</title></head><body>
<p>PayPal login. PayPal security.</p>
<form action="http://collector.example.net/post.php"><input name="email"><input type="password" name="pw"></form>
</body></html>"""

OWN_LOGIN = """<html><head><title>Sign in</title></head><body>
<form action="/session" method="post"><input name="user"><input type="password" name="pw"></form></body></html>"""


def test_fake_login_page_gets_two_strong_findings():
    soup = BeautifulSoup(FAKE_PAGE, "html.parser")
    found = analyzer.content_findings(soup, FAKE_PAGE, "https://evil-site.example.org/login")
    high = [f for f in found if f["severity"] == "high"]
    assert len(high) >= 2


def test_normal_login_page_is_not_flagged():
    soup = BeautifulSoup(OWN_LOGIN, "html.parser")
    assert analyzer.content_findings(soup, OWN_LOGIN, "https://shop.example.com/login") == []


def test_two_strong_content_findings_mean_phishing():
    r = engine.decide([finding("content", "high", 40), finding("content", "high", 20)], True, None)
    assert r["verdict"] == "phishing"
    assert r["score"] >= 70


def test_trust_credit_never_cancels_strong_evidence():
    r = engine.decide([finding("content", "high", 40), finding("trust", "info", -10)], True, None)
    assert r["trust_points"] == 0
    assert r["score"] == 40


def test_clean_fetched_page_is_likely_safe():
    assert engine.decide([], True, 1000)["verdict"] == "likely_safe"


def test_unfetched_page_without_evidence_is_inconclusive():
    assert engine.decide([], False, None)["verdict"] == "inconclusive"


def test_unfetched_old_clean_domain_is_limited_legitimate():
    r = engine.decide([], False, 2000)
    assert r["verdict"] == "likely_safe"
    assert r["limited"] is True


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


@pytest.mark.parametrize("payload", [
    None,
    [],
    "text",
    {"url": 5},
    {"url": ["a"]},
    {"url": ""},
    {"url": "x" * 3000},
    {"url": "exa\nmple.com"},
])
def test_bad_payloads_return_400(client, payload):
    assert client.post("/api/analyze", json=payload).status_code == 400


def test_valid_request_is_not_cached(client, monkeypatch):
    monkeypatch.setattr(app_module, "analyze", lambda url: {"verdict": "likely_safe", "url": url})
    r = client.post("/api/analyze", json={"url": "example.com"})
    assert r.status_code == 200
    assert r.headers["Cache-Control"] == "no-store"


def test_unexpected_error_returns_500_without_details(client, monkeypatch):
    def boom(url):
        raise RuntimeError("secret https://private.example")

    monkeypatch.setattr(app_module, "analyze", boom)
    r = client.post("/api/analyze", json={"url": "example.com"})
    assert r.status_code == 500
    assert "secret" not in r.get_data(as_text=True)