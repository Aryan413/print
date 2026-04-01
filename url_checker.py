"""
url_checker.py  —  VisionGuard AI v6.0
Multi-layer URL safety analysis:
  1. Protocol check (HTTPS vs HTTP)
  2. Trusted domain list (India-focused)
  3. Heuristic red-flag detection
  4. 12-feature Ensemble ML model (RF + GB)
  5. Google Safe Browsing API (if GOOGLE_API_KEY set)
"""

import re
import os
import requests
from urllib.parse import urlparse
from typing import Dict, Any

try:
    import joblib
    import numpy as np
    _ML_AVAILABLE = True
except ImportError:
    _ML_AVAILABLE = False

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ── Trusted domains (India-focused) ──────────────────────────────────────────
TRUSTED_DOMAINS = {
    "hdfcbank.com", "sbi.co.in", "icicibank.com", "axisbank.com",
    "kotak.com", "yesbank.in", "pnbindia.in", "bankofbaroda.in",
    "canarabank.com", "unionbankofindia.co.in", "indianbank.in",
    "iob.in", "bankofindia.co.in", "rblbank.com",
    "federalbank.co.in", "idbibank.com", "indusind.com",
    "bandhanbank.com", "paytm.com", "phonepe.com", "gpay.app",
    "bhimupi.org.in", "npci.org.in", "mobikwik.com",
    "freecharge.in", "airtelbank.com", "jiopay.in",
    "amazonpay.in", "razorpay.com", "cashfree.com",
    "payumoney.com", "instamojo.com", "amazon.in", "flipkart.com",
    "myntra.com", "snapdeal.com", "meesho.com", "nykaa.com",
    "tatacliq.com", "ajio.com", "bigbasket.com", "blinkit.com",
    "zepto.com", "jiomart.com", "zomato.com", "swiggy.com",
    "dunzo.com", "irctc.co.in", "makemytrip.com", "goibibo.com",
    "cleartrip.com", "yatra.com", "ixigo.com", "redbus.in",
    "india.gov.in", "uidai.gov.in", "incometax.gov.in",
    "gst.gov.in", "mca.gov.in", "epfindia.gov.in",
    "digitalindia.gov.in", "digilocker.gov.in", "umang.gov.in",
    "passport.gov.in", "jio.com", "airtel.in", "vi.in",
    "bsnl.co.in", "google.com", "apple.com", "microsoft.com",
    "paypal.com", "linkedin.com", "github.com",
}

SCAM_KEYWORDS = [
    "win", "prize", "free", "claim", "verify", "secure-login",
    "confirm", "update", "kyc", "aadhaar", "otp", "reward",
    "wallet", "topup", "recharge", "cashback", "lucky", "survey",
    "download", "apk", "install", "win-prize", "win_prize",
    "free-recharge", "lucky-draw", "getmoney", "wallet-topup",
    "upi-reward", "verify-now", "confirm-account", "pay-tm",
    "payment-redirect", "upi-pay",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".click",
    ".loan", ".work", ".gq", ".info", ".biz", ".pw",
    ".site", ".online", ".store", ".live",
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "s.id", "rb.gy", "cutt.ly", "short.gy", "tiny.one",
    "is.gd", "v.gd", "buff.ly",
]

TYPOSQUAT_MAP = {
    "hdfcbank": ["hdfcc", "hdffc", "h-dfc", "hdfc-bank", "hdfcbankk"],
    "paytm":    ["pay-tm", "p4ytm", "paytem", "paytm-upi"],
    "sbi":      ["sbi-net", "sbionline", "s-bi", "sbi-india"],
    "icici":    ["icicii", "1cici", "icic1", "icici-bank"],
    "zomato":   ["z0mato", "zom4to", "zomat0", "zomatto"],
    "swiggy":   ["sw1ggy", "swigy", "swiggy-offer"],
    "phonepe":  ["ph0nepe", "phone-pe", "phonepee"],
    "npci":     ["npci-upi", "npci-india", "npc1"],
}


def _extract_features(url: str, parsed, hostname: str, full_url: str) -> "np.ndarray":
    """Extract 12 features matching train_model.py."""
    path = (parsed.path or "").lower()
    return np.array([[
        len(full_url),                                                              # 1 url_length
        1 if parsed.scheme == "https" else 0,                                      # 2 has_https
        sum(1 for k in SCAM_KEYWORDS if k in full_url),                            # 3 num_scam_kw
        1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0,               # 4 is_ip
        1 if "@" in full_url else 0,                                               # 5 has_at
        hostname.count("-"),                                                       # 6 num_hyphens
        max(0, len(hostname.split(".")) - 2),                                      # 7 subdomain_depth
        1 if any(hostname.endswith(t) for t in SUSPICIOUS_TLDS) else 0,           # 8 suspicious_tld
        1 if any(s in hostname for s in SHORTENERS) else 0,                       # 9 is_shortener
        1 if any(hostname == d or hostname.endswith("." + d)
                 for d in TRUSTED_DOMAINS) else 0,                                # 10 is_trusted
        path.count("/"),                                                           # 11 path_depth
        1 if parsed.query else 0,                                                  # 12 has_query_params
    ]], dtype=float)


class URLChecker:
    def __init__(self, google_api_key: str = None):
        self.google_api_key = google_api_key or os.getenv("GOOGLE_API_KEY")
        self.ml_model = None
        self.qr_model = None
        if _ML_AVAILABLE:
            try:
                model_path = os.path.join(os.path.dirname(__file__), "url_classifier.joblib")
                if os.path.exists(model_path):
                    self.ml_model = joblib.load(model_path)
                qr_model_path = os.path.join(os.path.dirname(__file__), "qr_classifier.joblib")
                if os.path.exists(qr_model_path):
                    self.qr_model = joblib.load(qr_model_path)
            except Exception:
                pass

    def analyze(self, url: str) -> Dict[str, Any]:
        if not url.startswith("http"):
            url = "https://" + url

        parsed   = urlparse(url)
        hostname = (parsed.hostname or "").replace("www.", "").lower()
        full_url = url.lower()

        report = {
            "url":                  url,
            "protocol":             self._check_protocol(parsed),
            "domain":               self._check_domain(hostname),
            "flags":                self._check_flags(full_url, hostname),
            "ml_verdict":           self._check_ml_model(url, parsed, hostname, full_url),
            "safe_browsing_checked": False,
            "safe_browsing_result": None,
        }

        if self.google_api_key:
            sb = self._check_safe_browsing(url)
            report["safe_browsing_checked"] = True
            report["safe_browsing_result"]  = sb

        return report

    # ── Checks ────────────────────────────────────────────────────────────────

    def _check_protocol(self, parsed) -> Dict:
        ok = parsed.scheme == "https"
        return {
            "value":  parsed.scheme.upper(),
            "status": "safe" if ok else "danger",
            "detail": "Encrypted HTTPS connection" if ok else "Unencrypted HTTP — credentials sent in plaintext",
        }

    def _check_domain(self, hostname: str) -> Dict:
        if hostname in TRUSTED_DOMAINS:
            return {"value": hostname, "status": "safe", "detail": "Verified trusted domain"}
        for td in TRUSTED_DOMAINS:
            if hostname.endswith("." + td):
                return {"value": hostname, "status": "safe", "detail": f"Verified subdomain of {td}"}
        return {"value": hostname, "status": "warn", "detail": "Domain not in trusted list — verify manually"}

    def _check_flags(self, full_url: str, hostname: str) -> Dict:
        flags = []
        domain_part = hostname.split(".")[0]
        if "-" in domain_part:
            flags.append(f'Hyphen in domain: "{domain_part}"')
        if "@" in full_url:
            flags.append('"@" symbol in URL (can redirect to different host)')
        for kw in SCAM_KEYWORDS:
            if kw in full_url and f'"{kw}"' not in str(flags):
                flags.append(f'Suspicious keyword: "{kw}"')
                break
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
            flags.append("IP address used instead of a real domain name")
        if len(hostname.split(".")) > 4:
            flags.append(f"Excessive subdomains ({len(hostname.split('.'))} levels)")
        if len(full_url) > 100:
            flags.append(f"Unusually long URL ({len(full_url)} chars)")
        if any(hostname.endswith(t) for t in SUSPICIOUS_TLDS):
            flags.append(f"High-risk TLD detected in domain")
        for brand, variants in TYPOSQUAT_MAP.items():
            for v in variants:
                if v in hostname:
                    flags.append(f'Typosquat of "{brand}": found "{v}"')
        for brand in TYPOSQUAT_MAP:
            if brand in hostname and not any(hostname == d or hostname.endswith("." + d)
                                             for d in TRUSTED_DOMAINS):
                flags.append(f'Brand name "{brand}" in untrusted domain')

        count = len(flags)
        status = "safe" if count == 0 else ("warn" if count <= 2 else "danger")
        return {
            "count":  count,
            "status": status,
            "items":  flags,
            "detail": "; ".join(flags[:3]) if flags else "No suspicious patterns found",
        }

    def _check_ml_model(self, url: str, parsed, hostname: str, full_url: str) -> Dict:
        if not self.ml_model or not _ML_AVAILABLE:
            return {"status": "skipped", "detail": "ML model not loaded.", "confidence_score": 0.0}
        try:
            features = _extract_features(url, parsed, hostname, full_url)
            proba    = self.ml_model.predict_proba(features)[0]
            pred     = self.ml_model.predict(features)[0]
            conf     = float(proba[1] * 100)
            if pred == 1:
                return {"status": "danger",
                        "detail": "Ensemble model (RF+GB) flags URL structure as HIGH-RISK.",
                        "confidence_score": conf}
            return {"status": "safe",
                    "detail": "Ensemble model evaluates URL structure as safe.",
                    "confidence_score": conf}
        except Exception as e:
            return {"status": "error", "detail": str(e), "confidence_score": 0.0}

    def analyze_qr_ml(self, url: str, tamper_report: Dict) -> Dict:
        if not self.qr_model or not _ML_AVAILABLE:
            return {"status": "skipped", "detail": "QR ML model not loaded.", "confidence_score": 0.0}
        try:
            if not url.startswith("http"):
                url = "https://" + url
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").replace("www.", "").lower()
            full_url = url.lower()
            url_feats = _extract_features(url, parsed, hostname, full_url)[0].tolist()
            
            sigs = [s["name"] for s in tamper_report.get("signals", [])]
            sig_str = ",".join(sorted(sigs)) if sigs else "none"
            
            weights = {
                "none": 0, "double_border": 1, "shadow_artifact": 1, "texture_discontinuity": 1,
                "double_border,shadow_artifact": 2, "double_border,texture_discontinuity": 2,
                "shadow_artifact,texture_discontinuity": 2,
                "double_border,shadow_artifact,texture_discontinuity": 3,
            }
            weight = weights.get(sig_str, 0)
            conf_t = float(tamper_report.get("confidence", 0)) / 100.0
            is_upi = 1 if "upi-payment" in url else 0
            has_sig = 1 if sig_str != "none" else 0
            
            qr_extra = [weight, conf_t, is_upi, has_sig]
            all_feats = np.array([url_feats + qr_extra], dtype=float)
            
            proba = self.qr_model.predict_proba(all_feats)[0]
            pred = self.qr_model.predict(all_feats)[0]
            conf = float(proba[1] * 100)
            if pred == 1:
                return {"status": "danger",
                        "detail": "QR Forensic Engine (16-feature) flags code as HIGH-RISK.",
                        "confidence_score": conf}
            return {"status": "safe",
                    "detail": "QR Forensic Engine evaluates code as safe.",
                    "confidence_score": conf}
        except Exception as e:
            return {"status": "error", "detail": str(e), "confidence_score": 0.0}

    def _check_safe_browsing(self, url: str) -> Dict:
        endpoint = (
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
            f"?key={self.google_api_key}"
        )
        payload = {
            "client": {"clientId": "visionguard-ai", "clientVersion": "6.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            resp = requests.post(endpoint, json=payload, timeout=5)
            data = resp.json()
            if data.get("matches"):
                threat = data["matches"][0].get("threatType", "UNKNOWN")
                return {"status": "danger", "threat": threat}
            return {"status": "safe", "threat": None}
        except Exception as e:
            return {"status": "error", "detail": str(e)}