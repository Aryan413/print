"""
tests/test_url_checker.py
──────────────────────────
Run with:  pytest tests/
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.url_checker import URLChecker

checker = URLChecker()


# ── Protocol ──────────────────────────────────────────────────────────────────
def test_https_is_safe():
    r = checker.analyze("https://hdfcbank.com/pay")
    assert r["protocol"]["status"] == "safe"

def test_http_is_danger():
    r = checker.analyze("http://hdfcbank.com/pay")
    assert r["protocol"]["status"] == "danger"


# ── Domain trust ──────────────────────────────────────────────────────────────
def test_known_domain_safe():
    r = checker.analyze("https://hdfcbank.com")
    assert r["domain"]["status"] == "safe"

def test_subdomain_of_trusted_safe():
    r = checker.analyze("https://net.hdfcbank.com")
    assert r["domain"]["status"] == "safe"

def test_unknown_domain_warn():
    r = checker.analyze("https://random-site.xyz")
    assert r["domain"]["status"] == "warn"


# ── Red flags ─────────────────────────────────────────────────────────────────
def test_no_flags_on_clean_url():
    r = checker.analyze("https://zomato.com/table/45")
    assert r["flags"]["count"] == 0

def test_scam_keyword_flagged():
    r = checker.analyze("http://pay-tm-win-prize.in/claim")
    assert r["flags"]["count"] >= 1

def test_at_symbol_flagged():
    r = checker.analyze("http://evil.com@hdfcbank.com")
    items = r["flags"]["items"]
    assert any("@" in i for i in items)

def test_typosquat_detected():
    r = checker.analyze("http://z0mato-food.in/order")
    assert r["flags"]["count"] >= 1

def test_ip_address_flagged():
    r = checker.analyze("http://192.168.1.1/pay")
    items = r["flags"]["items"]
    assert any("IP" in i for i in items)

def test_long_url_flagged():
    long_url = "https://suspicious.in/" + "a" * 120
    r = checker.analyze(long_url)
    assert any("long" in i.lower() for i in r["flags"]["items"])
