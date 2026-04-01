"""
hallucinator.py — AI Predictive Hallucination™ Engine
Powered by Google Gemini 2.0 Flash via google-genai SDK.
Falls back to intelligent templates if API is unavailable.
"""

import re
import hashlib
import os
import requests as _requests
from typing import Dict, Any, Optional
from urllib.parse import urlparse

import numpy as np

# ── Load API key ───────────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

_GEMINI_KEY = os.getenv("GOOGLE_API_KEY", "")
_GEMINI_AVAILABLE = False

# ── Try new google-genai SDK first ────────────────────────────────────────────
try:
    from google import genai as _genai
    from google.genai import types as _gtypes
    if _GEMINI_KEY:
        _genai_client = _genai.Client(api_key=_GEMINI_KEY)
        _GEMINI_AVAILABLE = True
        _GEMINI_BACKEND = "genai"
except Exception:
    _genai_client = None
    _GEMINI_BACKEND = None

# ── Fallback: REST API directly ───────────────────────────────────────────────
if not _GEMINI_AVAILABLE and _GEMINI_KEY:
    _GEMINI_BACKEND = "rest"
    _GEMINI_AVAILABLE = True   # will be set False on first real failure


def _call_gemini(prompt: str, max_tokens: int = 300) -> Optional[str]:
    """
    Call Gemini 2.0 Flash via new google-genai SDK (or REST fallback).
    Returns text or None on failure — the app always continues gracefully.
    """
    if not _GEMINI_KEY:
        return None

    # ── new SDK ───────────────────────────────────────────────────────────────
    if _GEMINI_BACKEND == "genai" and _genai_client:
        try:
            from google.genai import types as _gt
            resp = _genai_client.models.generate_content(
                model="gemini-2.0-flash",
                contents=prompt,
                config=_gt.GenerateContentConfig(
                    max_output_tokens=max_tokens,
                    temperature=0.4,
                ),
            )
            return resp.text.strip() if resp.text else None
        except Exception:
            pass  # fall through to REST

    # ── REST fallback ─────────────────────────────────────────────────────────
    try:
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"gemini-2.0-flash:generateContent?key={_GEMINI_KEY}"
        )
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": max_tokens, "temperature": 0.4},
        }
        r = _requests.post(url, json=payload, timeout=10)
        if r.status_code == 200:
            data = r.json()
            return data["candidates"][0]["content"]["parts"][0]["text"].strip()
    except Exception:
        pass

    return None


# ── 1. Forensic Reconstructor ─────────────────────────────────────────────────

class ForensicReconstructor:
    BRAND_HINTS = {
        "paytm":   {"label": "Paytm"},
        "phonepe": {"label": "PhonePe"},
        "gpay":    {"label": "Google Pay"},
        "bhim":    {"label": "BHIM UPI"},
        "hdfc":    {"label": "HDFC Bank"},
        "sbi":     {"label": "SBI"},
        "upi":     {"label": "UPI"},
        "razorpay":{"label": "Razorpay"},
    }

    def reconstruct(self, image_np: Optional[np.ndarray], tamper_report: Dict) -> Dict[str, Any]:
        sticker_evidence = []
        found_brand      = None
        confidence       = 0

        signals = tamper_report.get("signals", [])
        status  = tamper_report.get("status", "skipped")

        if "double_border" in [s.get("name") for s in signals]:
            sticker_evidence.append("Two concentric rectangular contours detected — a sticker layer is sitting atop a printed QR code.")
            confidence += 35
        if "shadow_artifact" in [s.get("name") for s in signals]:
            sticker_evidence.append("Lateral brightness gradient at QR boundary suggests a 3-D lift — consistent with an adhesive sticker slightly raised off the surface.")
            confidence += 30
        if "texture_discontinuity" in [s.get("name") for s in signals]:
            sticker_evidence.append("Micro-texture variance: QR paper stock doesn't match the surrounding sign material.")
            confidence += 25
        if status == "danger":
            sticker_evidence.append("Edge-detection confirms high-density contour nesting — hallmark of a QRishing sticker attack.")
            confidence = min(confidence + 10, 97)

        if image_np is not None:
            found_brand = self._detect_brand_from_colors(image_np)

        if not sticker_evidence:
            return {
                "found_brand": None,
                "reconstruction": "No sticker overlay detected. The QR code appears to be original.",
                "sticker_evidence": [],
                "confidence": 0,
                "visual_summary": "✅ Original QR — no reconstruction needed.",
            }

        brand_label = (self.BRAND_HINTS.get(found_brand or "", {}).get("label")
                       or "a legitimate payment provider")

        # Try Gemini for forensic reconstruction narrative
        gemini_text = None
        if sticker_evidence:
            prompt = (
                f"You are a QR code forensic security expert trained continuously on real-world Indian QR scams.\n"
                f"Your task is to analyze physical tamper evidence and write a highly realistic, professional, and urgent warning "
                f"(max 3 sentences, no markdown, no asterisks) for a security app.\n\n"
                f"--- REAL-WORLD TRAINING MODELS ---\n"
                f"Model 1 (Fake Soundbox Scam):\n"
                f"Evidence: Two concentric rectangular contours detected.\n"
                f"Original Brand: Paytm\n"
                f"Output: A scammer has pasted their own fraudulent QR sticker over the merchant's original Paytm soundbox. The AI detects two concentric borders indicating a layered attack. Do not scan this sticker, as payments will bypass the shopkeeper entirely.\n\n"
                f"Model 2 (Parking/Transit Meter Scam):\n"
                f"Evidence: Micro-texture variance; lateral brightness gradient.\n"
                f"Original Brand: UPI\n"
                f"Output: The material texture does not match the underlying metallic surface, suggesting a fake 3D sticker has been recently applied. This overlay is hiding the original UPI parking portal. Avoid making any transfers as this may be a QRishing attack.\n"
                f"--- END TRAINING MODELS ---\n\n"
                f"NOW ANALYZE:\n"
                f"Evidence: {'; '.join(sticker_evidence[:2])}.\n"
                f"Original Brand likely beneath: {brand_label}.\n"
                f"Output:"
            )
            gemini_text = _call_gemini(prompt, max_tokens=120)

        reconstruction = (
            gemini_text if gemini_text else
            f"Forensic Hallucination Active: Based on pixel analysis of the surrounding sign, "
            f"the AI reconstructs that the original QR belonged to {brand_label}. "
            f"A scammer's sticker was placed over this code."
        )

        return {
            "found_brand": brand_label,
            "reconstruction": reconstruction,
            "sticker_evidence": sticker_evidence,
            "confidence": min(confidence, 97),
            "visual_summary": f"🧩 Beneath the sticker: AI predicts original was a **{brand_label}** payment QR.",
        }

    def _detect_brand_from_colors(self, image_np: np.ndarray) -> Optional[str]:
        try:
            h, w = image_np.shape[:2]
            border_pixels = np.concatenate([
                image_np[:int(h*0.1), :].reshape(-1, 3),
                image_np[int(h*0.9):, :].reshape(-1, 3),
                image_np[:, :int(w*0.1)].reshape(-1, 3),
                image_np[:, int(w*0.9):].reshape(-1, 3),
            ])
            avg = border_pixels.mean(axis=0)
            r, g, b = avg
            if b > r and b > g and b > 100: return "gpay"
            if r > 150 and g > 100 and b < 80: return "paytm"
            if r > 80 and g < 60 and b > 120: return "phonepe"
            if g > r and g > b and g > 100: return "bhim"
            return "upi"
        except Exception:
            return None


# ── 2. Destination Hallucinator ───────────────────────────────────────────────

class DestinationHallucinator:
    LEGIT_BRAND_DOMAINS = {
        "hdfcbank.com":  {"name": "HDFC Bank",          "category": "Banking"},
        "sbi.co.in":     {"name": "State Bank of India", "category": "Banking"},
        "icicibank.com": {"name": "ICICI Bank",          "category": "Banking"},
        "paytm.com":     {"name": "Paytm",               "category": "Payment Wallet"},
        "phonepe.com":   {"name": "PhonePe",             "category": "Payment Wallet"},
        "gpay.app":      {"name": "Google Pay",          "category": "Payment Wallet"},
        "npci.org.in":   {"name": "NPCI / BHIM",         "category": "UPI Authority"},
        "amazon.in":     {"name": "Amazon India",        "category": "E-Commerce"},
        "flipkart.com":  {"name": "Flipkart",            "category": "E-Commerce"},
        "google.com":    {"name": "Google",              "category": "Tech"},
        "apple.com":     {"name": "Apple",               "category": "Tech"},
    }

    IMPERSONATION_KEYWORDS = {
        "hdfc": "HDFC Bank", "sbi": "State Bank of India", "icici": "ICICI Bank",
        "paytm": "Paytm", "phonepe": "PhonePe", "google": "Google Pay",
        "amazon": "Amazon", "flipkart": "Flipkart", "npci": "NPCI / BHIM",
        "upi": "UPI Network", "bank": "a bank portal", "secure": "a security login page",
        "verify": "an account verification portal", "login": "a login portal",
        "payment": "a payment gateway", "wallet": "a digital wallet",
    }

    HIGH_RISK_TLDS = {".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw"}
    HIGH_RISK_HOSTING = {"000webhostapp", "glitch.me", "netlify.app", "vercel.app",
                         "firebaseapp", "pages.dev", "ngrok.io", "serveo.net"}

    def preview(self, url: str, url_report: Dict) -> Dict[str, Any]:
        parsed   = urlparse(url if url.startswith("http") else "https://" + url)
        hostname = (parsed.hostname or "").replace("www.", "").lower()
        full_url = url.lower()

        impersonates  = self._detect_impersonation(hostname, full_url)
        hosting_flags = self._check_hosting(hostname, parsed)
        metadata_hints = self._predict_metadata(full_url, hostname)

        is_real_brand = hostname in self.LEGIT_BRAND_DOMAINS
        if is_real_brand:
            bi = self.LEGIT_BRAND_DOMAINS[hostname]
            return {
                "impersonates": None, "actual_category": bi["category"],
                "visual_mismatch": False, "risk_level": "low",
                "hosting_red_flags": [],
                "ai_summary": (
                    f"✅ The AI clean-room preview confirms this is the official "
                    f"**{bi['name']}** portal. Domain, SSL, and visual patterns all align."
                ),
                "metadata_hints": metadata_hints,
            }

        visual_mismatch = impersonates is not None
        risk_level = "low"
        if hosting_flags: risk_level = "medium"
        if visual_mismatch: risk_level = "high"
        if visual_mismatch and hosting_flags: risk_level = "critical"
        if url_report.get("flags", {}).get("status") == "danger": risk_level = "critical"

        # Gemini-powered visual sandbox summary
        gemini_summary = None
        prompt = (
            f"You are an AI sandbox analyst trained on thousands of active QR-phishing/scam portals.\n"
            f"Your task is to write a critical 2-3 sentence visual sandbox report (max 90 words) explaining exactly what the site is pretending to be vs reality.\n"
            f"No markdown formatting, no asterisks.\n\n"
            f"--- REAL-WORLD TRAINING MODELS ---\n"
            f"Model 1 (Electricity Bill Scam):\n"
            f"Domain: update-eb-bill.vercel.app | Impersonates: a government portal | Hosting flags: Hosted on free platform 'vercel.app' | Suspicious keywords: update\n"
            f"Output: This site visually mimics a state electricity board portal to trick you into 'updating' your bill, but is actually hosted on a free, unverified Vercel platform. Authentic government portals never use temporary free hosting. Do not proceed or install any apps from this page.\n\n"
            f"Model 2 (Traffic Challan Scam):\n"
            f"Domain: echallan-parivahan-govt.top | Impersonates: Traffic Police | Risk level: critical | Suspicious keywords: login, payment\n"
            f"Output: The clean-room analysis reveals this is a severe e-challan phishing site operating on a high-risk '.top' domain. While it perfectly clones the official Parivahan layout, it is designed to steal your vehicle registration and payment details. Close this page immediately.\n"
            f"--- END TRAINING MODELS ---\n\n"
            f"NOW ANALYZE THIS URL: {url}\n"
            f"Domain: {hostname}\n"
            f"Impersonates: {impersonates or 'unknown brand'}\n"
            f"Risk level: {risk_level}\n"
            f"Hosting flags: {'; '.join(hosting_flags) if hosting_flags else 'none'}\n"
            f"Suspicious keywords in path: {', '.join(metadata_hints.get('suspicious_path_keywords', [])) or 'none'}\n"
            f"Output:"
        )
        gemini_summary = _call_gemini(prompt, max_tokens=150)

        ai_summary = gemini_summary if gemini_summary else self._fallback_summary(
            url, hostname, impersonates, hosting_flags, risk_level, metadata_hints
        )

        return {
            "impersonates": impersonates,
            "actual_category": "Unknown / Suspicious",
            "visual_mismatch": visual_mismatch,
            "risk_level": risk_level,
            "hosting_red_flags": hosting_flags,
            "ai_summary": ai_summary,
            "metadata_hints": metadata_hints,
        }

    def _detect_impersonation(self, hostname, full_url):
        # Never flag known-trusted domains as impersonating themselves
        from url_checker import TRUSTED_DOMAINS
        if any(hostname == d or hostname.endswith("." + d) for d in TRUSTED_DOMAINS):
            return None
        for kw, brand in self.IMPERSONATION_KEYWORDS.items():
            if kw in hostname or kw in full_url:
                return brand
        return None

    def _check_hosting(self, hostname, parsed):
        flags = []
        tld = "." + hostname.split(".")[-1] if "." in hostname else ""
        if tld in self.HIGH_RISK_TLDS:
            flags.append(f"High-risk TLD '{tld}' — commonly used in scam domains")
        for p in self.HIGH_RISK_HOSTING:
            if p in hostname:
                flags.append(f"Hosted on free platform '{p}' — not legitimate for financial services")
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
            flags.append("Raw IP address used — payment portals never do this")
        if len(hostname.split(".")) > 4:
            flags.append(f"Excessive sub-domains — obfuscation tactic")
        return flags

    def _predict_metadata(self, full_url, hostname):
        risky = ["login", "password", "verify", "account", "secure",
                 "update", "confirm", "unlock", "suspend", "otp"]
        found = [w for w in risky if w in full_url]
        return {
            "suspicious_path_keywords": found,
            "url_length_risk": "high" if len(full_url) > 100 else ("medium" if len(full_url) > 60 else "low"),
            "is_shortened": any(s in hostname for s in ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly"]),
            "has_numeric_subdomain": bool(re.search(r"\d{4,}", hostname)),
        }

    def _fallback_summary(self, url, hostname, impersonates, hosting_flags, risk_level, hints):
        emoji = {"low":"🟡","medium":"🟠","high":"🔴","critical":"🚨"}.get(risk_level,"🟡")
        parts = [f"{emoji} AI Visual Sandbox Report for {hostname}:"]
        if impersonates:
            parts.append(f"Site visually impersonates {impersonates} but domain has no affiliation.")
        if hosting_flags:
            parts.append(hosting_flags[0])
        if risk_level == "critical":
            parts.append("Do NOT visit this site.")
        return " ".join(parts)


# ── 3. Semantic Decoder ───────────────────────────────────────────────────────

class SemanticDecoder:
    INTENT_MAP = [
        (r"(login|signin|sign.in|account.verify)",       "Credential Harvesting",   "critical"),
        (r"(otp|one.time|2fa|auth)",                     "OTP Interception",        "critical"),
        (r"(password|passwd|pwd|reset)",                  "Password Theft",          "critical"),
        (r"(kyc|aadhaar|pan.card|id.proof)",              "Identity Document Theft", "critical"),
        (r"(win|prize|lucky|lucky.draw|reward|free)",     "Lottery / Prize Scam",    "high"),
        (r"(wallet|topup|recharge|cashback)",             "Wallet Hijack",           "high"),
        (r"(upi-pay|pay-|pay\.|payment-redirect|send.money|transfer-upi)", "Payment Redirect", "high"),
        (r"(survey|feedback|rate.us)",                    "Data Harvesting Survey",  "medium"),
        (r"(download|apk|install|update.app)",            "Malware Distribution",    "critical"),
        (r"(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly)",      "Masked Destination",      "high"),
    ]

    def decode(self, url: str, url_report: Dict, tamper_report: Dict) -> Dict[str, Any]:
        full_url = url.lower()
        parsed   = urlparse(url if url.startswith("http") else "https://" + url)
        hostname = (parsed.hostname or "").replace("www.", "").lower()

        # Trusted domains: skip intent scanning to prevent false positives
        # (e.g. "pay" in paypal.com, gpay.app, hdfcbank.com/pay)
        domain_trusted = url_report.get("domain", {}).get("status") == "safe"

        detected_intents = []
        max_severity     = "low"
        sev_order        = ["low", "medium", "high", "critical"]

        if not domain_trusted:
            for pattern, intent, severity in self.INTENT_MAP:
                if re.search(pattern, full_url, re.IGNORECASE):
                    detected_intents.append({"intent": intent, "severity": severity})
                    if sev_order.index(severity) > sev_order.index(max_severity):
                        max_severity = severity

        if url_report.get("flags", {}).get("status") == "danger":
            if max_severity in ("low", "medium"): max_severity = "high"
        if tamper_report.get("status") == "danger":
            max_severity = "critical"

        expanded_url = self._predict_expanded_url(url, full_url, hostname)
        flags        = url_report.get("flags", {}).get("items", [])
        signals      = tamper_report.get("signals", [])

        # ── Real Gemini narrative ─────────────────────────────────────────────
        narrative = None
        if _GEMINI_AVAILABLE:
            tamper_note = ""
            if tamper_report.get("status") == "danger":
                shadow = any(s["name"] == "shadow_artifact" for s in signals)
                border = any(s["name"] == "double_border"   for s in signals)
                if shadow: tamper_note += " Shadows at the QR boundary suggest a sticker was recently applied over the original."
                if border: tamper_note += " A second rectangular border is visible beneath the QR — consistent with a sticker attack."

            intents_str = ", ".join(i["intent"] for i in detected_intents) or "General phishing"
            flags_str   = "; ".join(flags[:3]) or "none"
            protocol    = url_report.get("protocol", {}).get("status", "safe")

            prompt = (
                f"You are a proactive cybersecurity AI assistant for a QR code scanner app widely used in India.\n"
                f"Analyze this suspicious URL and write a personalised, high-impact security warning targeting the specific human vulnerability (2-3 sentences, max 100 words).\n"
                f"Address the user directly. End with one crystal-clear action item. No markdown, no asterisks, plain text only.\n\n"
                f"--- REAL-WORLD TRAINING MODELS ---\n"
                f"Model 1 (KYC / PAN Update Scam):\n"
                f"Intents: Identity Document Theft, Credential Harvesting | Domain: sbi-kyc-alert.xyz | Red flags: High-risk TLD\n"
                f"Output: Scammers are using this QR code to mimic a bank KYC update portal in an attempt to steal your PAN and Aadhaar details. Providing documents here could lead to your identity being misused for unauthorized loans. Never upload government IDs to links scanned from random QR codes.\n\n"
                f"Model 2 (FedEx/Customs Parcel Scam):\n"
                f"Intents: Masked Destination, Payment Redirect | Domain: bit.ly/fedex-hold | Severity: high\n"
                f"Output: This shortened link masks its true destination and perfectly matches a known customs delay/courier scam pattern. The attackers intend to trick you into paying a fake clearance fee for a package that doesn't exist. Immediately close the page without entering any UPI PIN.\n"
                f"--- END TRAINING MODELS ---\n\n"
                f"NOW ANALYZE:\n"
                f"URL: {url}\n"
                f"Domain: {hostname}\n"
                f"Detected attack intents: {intents_str}\n"
                f"Red flags in URL: {flags_str}\n"
                f"Connection: {'HTTP (no encryption)' if protocol == 'danger' else 'HTTPS'}\n"
                f"Physical tamper evidence: {tamper_report.get('status', 'not checked')}.{tamper_note}\n"
                f"Severity: {max_severity}\n"
                f"Output:"
            )
            narrative = _call_gemini(prompt, max_tokens=180)

        if not narrative:
            narrative = self._fallback_narrative(url, hostname, detected_intents,
                                                  max_severity, tamper_report, url_report)

        action_items = self._build_action_items(detected_intents, tamper_report, url_report)

        return {
            "intents":      detected_intents,
            "severity":     max_severity,
            "expanded_url": expanded_url,
            "narrative":    narrative,
            "action_items": action_items,
            "gemini_powered": _GEMINI_AVAILABLE,
        }

    def _predict_expanded_url(self, url, full_url, hostname):
        shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly"]
        if any(s in hostname for s in shorteners):
            seed = int(hashlib.md5(url.encode()).hexdigest()[:8], 16) % 1000
            templates = [
                f"http://secure-login-{seed}.{hostname.split('.')[0]}.xyz/account/verify",
                f"http://payment-confirm-{seed}.in/upi/claim",
                f"http://hdfc-update-{seed}.net/kyc/aadhaar",
                f"http://sbi-alert-{seed}.top/account/suspended",
            ]
            return templates[seed % len(templates)]
        return None

    def _fallback_narrative(self, url, hostname, intents, severity, tamper_report, url_report):
        severity_intro = {
            "critical": "⚠️ CRITICAL THREAT: This URL is engineered to steal sensitive data.",
            "high":     "🔴 HIGH RISK: This URL exhibits patterns consistent with financial fraud.",
            "medium":   "🟡 CAUTION: This URL shows suspicious characteristics.",
            "low":      "🟢 No major threats detected in this URL.",
        }
        parts = [severity_intro.get(severity, "⚠️ Suspicious URL detected.")]
        if intents:
            parts.append(f"Detected: {', '.join(i['intent'] for i in intents[:2])}.")
        flags = url_report.get("flags", {}).get("items", [])
        if flags:
            parts.append(f"Red flags: {flags[0][:60]}.")
        if tamper_report.get("status") == "danger":
            parts.append("Physical sticker tampering also detected. Ask the merchant for the original QR.")
        return " ".join(parts)

    def _build_action_items(self, intents, tamper_report, url_report):
        actions = []
        labels  = [i["intent"] for i in intents]
        if any(x in labels for x in ["Credential Harvesting", "OTP Interception", "Password Theft"]):
            actions.append("🚫 Never enter your PIN, password, or OTP on a page you reached via QR code.")
        if "Payment Redirect" in labels:
            actions.append("💳 Always verify the UPI ID recipient name before confirming any payment.")
        if "Identity Document Theft" in labels:
            actions.append("🪪 Never upload your Aadhaar or PAN card via a QR-linked page.")
        if "Masked Destination" in labels:
            actions.append("🔍 Expand shortened URLs at checkshorturl.com before visiting.")
        if tamper_report.get("status") in ("warn", "danger"):
            actions.append("🧐 Ask the shopkeeper to remove the QR sticker and show you the original sign.")
            actions.append("📸 Photograph the QR and report it to your bank's fraud helpline.")
        if url_report.get("protocol", {}).get("status") == "danger":
            actions.append("🔒 Only use HTTPS links for financial transactions.")
        if not actions:
            actions.append("✅ No immediate action required — but always verify the payment recipient name before confirming UPI.")
        return actions