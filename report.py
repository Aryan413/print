"""
modules/report.py
──────────────────
Aggregates URL + tamper check results into one final report dict.
"""

from typing import Dict, Any
from datetime import datetime


RISK_SCORES = {"safe": 0, "warn": 1, "danger": 2, "skipped": 0}


def build_report(url: str, url_report: Dict, tamper_report: Dict) -> Dict[str, Any]:
    """
    Combines all sub-reports into one verdict.

    Overall logic:
      - Any single "danger" → overall DANGER
      - Two or more "warn"  → overall CAUTION
      - One "warn"          → CAUTION
      - All "safe"          → SAFE
    """
    scores = [
        RISK_SCORES.get(url_report["protocol"]["status"], 0),
        RISK_SCORES.get(url_report["domain"]["status"], 0),
        RISK_SCORES.get(url_report["flags"]["status"], 0),
        RISK_SCORES.get(tamper_report.get("status", "skipped"), 0),
    ]

    # Google Safe Browsing override
    sb = url_report.get("safe_browsing_result")
    if sb and sb.get("status") == "danger":
        scores.append(2)

    max_score = max(scores)
    warn_count = scores.count(1)

    if max_score == 2:
        overall = "DANGER"
    elif max_score == 1 or warn_count >= 1:
        overall = "CAUTION"
    else:
        overall = "SAFE"

    recommendation = _build_recommendation(overall, url_report, tamper_report)

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "url": url,
        "overall": overall,
        "recommendation": recommendation,
        "url_analysis": url_report,
        "tamper_analysis": tamper_report,
    }


def _build_recommendation(overall, url_report, tamper_report) -> str:
    parts = []

    if overall == "DANGER":
        parts.append("⛔ Do NOT proceed with this QR code.")
        flags = url_report["flags"].get("items", [])
        if flags:
            parts.append(f"Red flags detected: {', '.join(flags[:2])}.")
        if tamper_report.get("status") == "danger":
            parts.append("Physical sticker overlay detected — this is likely a fake QR pasted over a real one.")
        if url_report["protocol"]["status"] == "danger":
            parts.append("The link uses HTTP (no encryption).")
        parts.append("Report this to the business/merchant immediately.")

    elif overall == "CAUTION":
        parts.append("⚠️ Proceed with caution.")
        if url_report["domain"]["status"] == "warn":
            parts.append("The domain could not be verified as trusted.")
        if tamper_report.get("status") in ("warn", "danger"):
            parts.append("Possible physical tampering detected — inspect the QR code visually.")
        parts.append("Verify the URL with the merchant before making any payment.")

    else:
        parts.append("✅ This QR code appears safe to proceed.")
        parts.append(f"Domain '{url_report['domain']['value']}' is verified and connection is encrypted.")

    return " ".join(parts)
