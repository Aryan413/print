"""
VisionGuard AI v6.0 — app.py
Improved QR + URL safety scanner with Claude AI-powered threat narratives,
enhanced ML ensemble model, and cleaner UI.
"""

import streamlit as st
import numpy as np
import cv2
from PIL import Image
import io, os, time, re, json
from urllib.parse import urlparse
import concurrent.futures
import requests as _req

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

from scanner         import decode_qr_from_image, decode_qr_from_url_string
from url_checker     import URLChecker
from tamper_detector import TamperDetector
from report          import build_report
from hallucinator    import SemanticDecoder, _GEMINI_AVAILABLE

# ──────────────────────────────────────────────────────────────────────────────
# Page config
# ──────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="VisionGuard AI v6.0",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ──────────────────────────────────────────────────────────────────────────────
# Session state
# ──────────────────────────────────────────────────────────────────────────────
for key, default in [
    ("total_scans", 0), ("threats_caught", 0), ("urls_cleared", 0),
    ("scan_history", []), ("demo_url", ""),
]:
    if key not in st.session_state:
        st.session_state[key] = default

# ──────────────────────────────────────────────────────────────────────────────
# CSS
# ──────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;700&display=swap');

:root {
    --bg:       #06080f;
    --surface:  #0d1117;
    --border:   #1c2333;
    --text:     #c9d1d9;
    --muted:    #586069;
    --accent:   #58a6ff;
    --green:    #3fb950;
    --red:      #f85149;
    --yellow:   #d29922;
    --purple:   #bc8cff;
    --mono:     'JetBrains Mono', monospace;
    --sans:     'Space Grotesk', sans-serif;
}

@keyframes fadeUp   { from { opacity:0; transform:translateY(16px); } to { opacity:1; transform:translateY(0); } }
@keyframes scanLine { 0% { top:-2px; } 100% { top:100%; } }
@keyframes pulseRed { 0%,100% { box-shadow:0 0 0 rgba(248,81,73,0); } 50% { box-shadow:0 0 30px rgba(248,81,73,.35); } }
@keyframes spin     { to { transform:rotate(360deg); } }
@keyframes spinRev  { to { transform:rotate(-360deg); } }

* { font-family: var(--sans); box-sizing:border-box; }
.stApp { background:var(--bg); color:var(--text); }
.stApp > header { background:transparent !important; }
.block-container { max-width:1080px !important; padding-top:1.5rem; animation:fadeUp .5s ease; }
#MainMenu, footer, header { visibility:hidden; }

/* ── Header ── */
.vg-header { 
    display:flex; align-items:center; gap:1.5rem; 
    padding:1.2rem 1.5rem; 
    background:var(--surface); 
    border:1px solid var(--border); 
    border-radius:12px; 
    margin-bottom:1.5rem;
}
.vg-logo { 
    font-family:var(--mono); 
    font-size:1.5rem; 
    font-weight:700; 
    color:#fff; 
    letter-spacing:-.02em; 
}
.vg-logo span { color:var(--accent); }
.vg-tagline { font-size:.78rem; color:var(--muted); text-transform:uppercase; letter-spacing:.1em; }
.vg-stat { 
    text-align:center; 
    padding:.5rem 1.2rem; 
    border-left:1px solid var(--border); 
}
.vg-stat-n { font-family:var(--mono); font-size:1.6rem; font-weight:700; line-height:1; }
.vg-stat-l { font-size:.65rem; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); margin-top:2px; }

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] { gap:4px; border-bottom:1px solid var(--border); padding-bottom:0; }
.stTabs [data-baseweb="tab"] { 
    border-radius:6px 6px 0 0 !important; 
    padding:8px 20px !important; 
    background:transparent !important; 
    color:var(--muted) !important; 
    border:1px solid transparent !important;
    font-size:.82rem !important;
    font-weight:500 !important;
}
.stTabs [aria-selected="true"] { 
    background:var(--surface) !important; 
    color:#fff !important; 
    border-color:var(--border) var(--border) var(--surface) !important; 
}

/* ── Input boxes ── */
.stTextInput input { 
    background:var(--surface) !important; 
    border:1px solid var(--border) !important; 
    color:#fff !important; 
    border-radius:8px !important;
    font-family:var(--mono) !important;
    font-size:.88rem !important;
}
.stTextInput input:focus { border-color:var(--accent) !important; }

/* ── Buttons ── */
.stButton > button {
    background: linear-gradient(135deg,#1f6feb,#388bfd) !important;
    color:#fff !important;
    border:none !important;
    border-radius:8px !important;
    font-weight:600 !important;
    font-size:.85rem !important;
    padding:.5rem 1.5rem !important;
    transition:opacity .15s !important;
}
.stButton > button:hover { opacity:.85 !important; }

/* ── Shield triptych ── */
.shields-row { display:flex; gap:12px; margin:1.2rem 0; }
.shield-card { 
    flex:1; 
    background:var(--surface); 
    border:1px solid var(--border); 
    border-radius:10px; 
    padding:1rem; 
    text-align:center; 
    transition:border-color .2s;
}
.shield-icon  { font-size:1.8rem; }
.shield-label { font-size:.75rem; font-weight:600; color:var(--text); text-transform:uppercase; letter-spacing:.06em; margin:.4rem 0; }
.shield-val   { font-family:var(--mono); font-size:.78rem; margin-top:.4rem; }
.s-clean      { color:var(--green); }
.s-threat     { color:var(--red); animation:pulseRed 1.8s infinite; }
.s-warn       { color:var(--yellow); }
.s-skip       { color:var(--muted); }

/* ── Verdict card ── */
.verdict-wrap { border-radius:14px; padding:1.5rem 2rem; margin:1rem 0; display:flex; align-items:center; gap:1.5rem; }
.verdict-safe    { background:#0d1f10; border:2px solid var(--green); }
.verdict-danger  { background:#1a0d0c; border:2px solid var(--red); animation:pulseRed 2s infinite; }
.verdict-caution { background:#1a1200; border:2px solid var(--yellow); }
.verdict-title   { font-family:var(--mono); font-size:2rem; font-weight:700; text-transform:uppercase; }
.verdict-sub     { font-size:.8rem; color:var(--muted); text-transform:uppercase; letter-spacing:.1em; }

/* ── SVG risk ring ── */
.risk-ring-wrap { flex-shrink:0; text-align:center; }
.risk-ring-label { font-size:.65rem; text-transform:uppercase; color:var(--muted); letter-spacing:.08em; margin-top:4px; }

/* ── AI narrative box ── */
.ai-box {
    background:var(--surface);
    border:1px solid var(--border);
    border-left:3px solid var(--accent);
    border-radius:8px;
    padding:1rem 1.2rem;
    font-size:.87rem;
    color:var(--text);
    line-height:1.65;
    margin:.8rem 0;
}
.ai-box.danger { border-left-color:var(--red); }
.ai-box.warn   { border-left-color:var(--yellow); }
.ai-label { font-size:.68rem; font-weight:700; text-transform:uppercase; letter-spacing:.12em; color:var(--accent); margin-bottom:.5rem; }

/* ── Feature table ── */
.feat-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:8px; margin:.8rem 0; }
.feat-cell { background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:.5rem .7rem; font-size:.78rem; }
.feat-cell b { color:var(--text); }
.feat-cell span { color:var(--muted); font-family:var(--mono); }

/* ── Action list ── */
.action-item { 
    background:var(--surface); 
    border:1px solid var(--border); 
    border-radius:8px; 
    padding:.65rem 1rem; 
    font-size:.83rem; 
    margin:.35rem 0; 
}

/* ── History row ── */
.hist-row { 
    display:flex; align-items:center; gap:12px; 
    background:var(--surface); border:1px solid var(--border); border-radius:8px; 
    padding:.6rem 1rem; margin:.3rem 0; font-size:.8rem; 
}
.hist-dot { width:8px; height:8px; border-radius:50%; flex-shrink:0; }

/* ── Spinner orb ── */
.orb { position:relative; width:80px; height:80px; margin:1.5rem auto; }
.orb-ring { position:absolute; border-radius:50%; top:0; left:0; width:100%; height:100%; border:2px solid transparent; }
.orb-ring:nth-child(1) { border-top-color:var(--accent);  animation:spin 1.8s linear infinite; }
.orb-ring:nth-child(2) { border-right-color:var(--purple); width:80%; height:80%; top:10%; left:10%; animation:spinRev 2.5s linear infinite; }
.orb-ring:nth-child(3) { border-bottom-color:var(--green); width:60%; height:60%; top:20%; left:20%; animation:spin 1.2s linear infinite; }
.orb-core { position:absolute; width:36%; height:36%; top:32%; left:32%; background:radial-gradient(circle,#388bfd,#1f6feb); border-radius:50%; box-shadow:0 0 16px #388bfd88; }
.orb-label { text-align:center; font-family:var(--mono); font-size:.72rem; color:var(--muted); margin-top:.3rem; }

/* ── Demo button row ── */
.demo-btn-row { display:flex; gap:8px; flex-wrap:wrap; margin:.5rem 0; }
.demo-btn { 
    font-size:.75rem; padding:.3rem .8rem; border-radius:6px; cursor:pointer;
    border:1px solid; font-family:var(--mono); 
}
.demo-safe   { border-color:var(--green); color:var(--green); background:#0d1f1088; }
.demo-danger { border-color:var(--red);   color:var(--red);   background:#1a0d0c88; }

/* ── Threat intel cards ── */
.intel-card { background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:1rem 1.2rem; margin:.5rem 0; }
.intel-title { font-weight:700; font-size:.88rem; color:var(--text); margin-bottom:.3rem; }
.intel-desc  { font-size:.78rem; color:var(--muted); line-height:1.55; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width:6px; } 
::-webkit-scrollbar-track { background:var(--bg); }
::-webkit-scrollbar-thumb { background:var(--border); border-radius:3px; }
</style>
""", unsafe_allow_html=True)

# ──────────────────────────────────────────────────────────────────────────────
# Header
# ──────────────────────────────────────────────────────────────────────────────
header_ph = st.empty()

def draw_header():
    with header_ph.container():
        st.markdown(f"""
        <div class="vg-header">
            <div style="flex:1">
                <div class="vg-logo">VISION<span>GUARD</span> <span style="color:var(--muted);font-size:.9rem">v6.0</span></div>
                <div class="vg-tagline">QR &amp; URL Threat Intelligence Platform · AI-Powered</div>
            </div>
            <div class="vg-stat">
                <div class="vg-stat-n" style="color:var(--accent)">{st.session_state.total_scans}</div>
                <div class="vg-stat-l">Scans</div>
            </div>
            <div class="vg-stat">
                <div class="vg-stat-n" style="color:var(--red)">{st.session_state.threats_caught}</div>
                <div class="vg-stat-l">Threats</div>
            </div>
            <div class="vg-stat">
                <div class="vg-stat-n" style="color:var(--green)">{st.session_state.urls_cleared}</div>
                <div class="vg-stat-l">Cleared</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

draw_header()

# ──────────────────────────────────────────────────────────────────────────────
# Tabs
# ──────────────────────────────────────────────────────────────────────────────
tab_scan, tab_history, tab_intel = st.tabs(
    ["🔍 Scanner", "📋 Scan History", "🕵️ Threat Intel"]
)

# ── SCANNER TAB ───────────────────────────────────────────────────────────────
with tab_scan:
    input_tab_qr, input_tab_url = st.tabs(["📷 Upload QR Image", "🔗 Paste URL"])

    image_np  = None
    url_input = ""

    with input_tab_qr:
        st.markdown("##### Upload a QR code image to scan")
        uploaded = st.file_uploader(
            "Drop a QR image here", type=["jpg","jpeg","png","webp"],
            label_visibility="collapsed"
        )
        if uploaded:
            pil_img  = Image.open(uploaded).convert("RGB")
            image_np = np.array(pil_img)
            st.image(pil_img, caption="Uploaded QR Image", width=280)
            decoded = decode_qr_from_image(image_np)
            if decoded:
                url_input = decoded
                st.success(f"QR decoded → `{decoded}`")
            else:
                st.warning("Could not decode a QR code from this image. Try a cleaner/closer image.")

    with input_tab_url:
        st.markdown("##### Paste a URL or QR destination")

        # Demo quick-fill buttons via URL params trick
        col_d1, col_d2, col_d3, col_d4 = st.columns(4)
        with col_d1:
            if st.button("✅ Demo: Safe URL", use_container_width=True):
                st.session_state.demo_url = "https://hdfcbank.com/pay"
        with col_d2:
            if st.button("⚠️ Demo: Suspicious", use_container_width=True):
                st.session_state.demo_url = "https://bit.ly/hdfc-verify-now"
        with col_d3:
            if st.button("🚨 Demo: Phishing", use_container_width=True):
                st.session_state.demo_url = "http://secure-sbi-kyc.xyz/aadhaar-update"
        with col_d4:
            if st.button("💳 Demo: UPI Scam", use_container_width=True):
                st.session_state.demo_url = "http://paytm-recharge-free.tk/reward/otp"

        typed = st.text_input(
            "URL", value=st.session_state.demo_url,
            placeholder="https://example.com or paste a QR destination…",
            label_visibility="collapsed"
        )
        if typed:
            url_input = typed.strip()

    # ── SCAN BUTTON ───────────────────────────────────────────────────────────
    st.markdown("")
    do_scan = st.button("⚡ Scan Now", use_container_width=True, type="primary")

    if do_scan and url_input:
        st.session_state.total_scans += 1

        # ── Normalise UPI scheme before any analysis ──────────────────────────
        raw_input = url_input.strip()
        if raw_input.lower().startswith("upi://"):
            # upi://pay?pa=merchant@bank  →  treat domain as the UPI VPA host
            url_input = "https://upi-payment/" + raw_input[len("upi://"):]

        checker  = URLChecker()
        detector = TamperDetector()
        decoder  = SemanticDecoder()

        # Placeholders
        orb_ph      = st.empty()
        shields_ph  = st.empty()
        results_ph  = st.empty()

        orb_ph.markdown("""
        <div class="orb">
            <div class="orb-ring"></div><div class="orb-ring"></div><div class="orb-ring"></div>
            <div class="orb-core"></div>
        </div>
        <div class="orb-label">ANALYZING · TRIPLE-SHIELD ACTIVE</div>
        """, unsafe_allow_html=True)

        # Pending shields
        shields_ph.markdown("""
        <div class="shields-row">
            <div class="shield-card"><div class="shield-icon">🌐</div><div class="shield-label">Shield 1 · Digital</div><div class="shield-val s-skip">SCANNING…</div></div>
            <div class="shield-card"><div class="shield-icon">👁️</div><div class="shield-label">Shield 2 · Physical</div><div class="shield-val s-skip">SCANNING…</div></div>
            <div class="shield-card"><div class="shield-icon">🧠</div><div class="shield-label">Shield 3 · AI Intent</div><div class="shield-val s-skip">SCANNING…</div></div>
        </div>
        """, unsafe_allow_html=True)

        # ── Parallel analysis ─────────────────────────────────────────────────
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
            f_url    = ex.submit(checker.analyze, url_input)
            f_tamper = ex.submit(detector.analyze, image_np if image_np is not None else np.zeros((10,10,3), dtype=np.uint8))
            url_report    = f_url.result()
            tamper_report = f_tamper.result()

        if image_np is not None and tamper_report.get("status") != "skipped":
            url_report["qr_ml_verdict"] = checker.analyze_qr_ml(url_input, tamper_report)

        semantic = decoder.decode(url_input, url_report, tamper_report)
        report   = build_report(url_input, url_report, tamper_report)

        orb_ph.empty()

        # ── Shield statuses ───────────────────────────────────────────────────
        sb        = url_report.get("safe_browsing_result") or {}
        sb_danger = sb.get("status") == "danger"
        
        is_qr = "qr_ml_verdict" in url_report
        active_ml = url_report["qr_ml_verdict"] if is_qr else url_report.get("ml_verdict", {})
        ml_danger = active_ml.get("status") == "danger"

        s1_ok  = not (sb_danger or ml_danger or url_report["protocol"]["status"] == "danger")
        ts     = tamper_report.get("status", "skipped")
        s3_bad = semantic.get("severity", "low") in ("high", "critical")

        def shield_html(icon, label, ok, skip=False, warn=False):
            if skip:   cls, val = "s-skip",   "BYPASSED"
            elif warn: cls, val = "s-warn",    "WARNING"
            elif ok:   cls, val = "s-clean",   "✓ CLEAN"
            else:      cls, val = "s-threat",  "✕ THREAT"
            return f'<div class="shield-card"><div class="shield-icon">{icon}</div><div class="shield-label">{label}</div><div class="shield-val {cls}">{val}</div></div>'

        shields_ph.markdown(f"""
        <div class="shields-row">
            {shield_html("🌐","Shield 1 · Digital Reputation", s1_ok)}
            {shield_html("👁️","Shield 2 · Physical Integrity",
                ts == "safe",
                skip=(ts == "skipped" or image_np is None),
                warn=(ts == "warn"))}
            {shield_html("🧠","Shield 3 · AI Semantic Intent", not s3_bad)}
        </div>
        """, unsafe_allow_html=True)

        # ── Final verdict ─────────────────────────────────────────────────────
        overall = report["overall"]
        domain_trusted = url_report["domain"]["status"] == "safe"

        # s3_bad (semantic intent) should only escalate to DANGER when the
        # domain is NOT trusted — on trusted domains it is almost always a
        # false positive from broad keyword patterns (e.g. "pay" in paypal).
        s3_escalates = s3_bad and not domain_trusted

        if overall == "DANGER" or sb_danger or ml_danger or ts == "danger" or s3_escalates:
            verdict, vclass, vcolor, risk_pct = "THREAT DETECTED", "verdict-danger", "var(--red)", 94
            if "flagged_"+url_input not in st.session_state:
                st.session_state.threats_caught += 1
                st.session_state["flagged_"+url_input] = True
        elif overall == "CAUTION" or ts == "warn":
            verdict, vclass, vcolor, risk_pct = "CAUTION ADVISED", "verdict-caution", "var(--yellow)", 60
        else:
            verdict, vclass, vcolor, risk_pct = "APPEARS SECURE",  "verdict-safe",    "var(--green)", 4
            if "cleared_"+url_input not in st.session_state:
                st.session_state.urls_cleared += 1
                st.session_state["cleared_"+url_input] = True

        draw_header()  # refresh stats

        # Risk ring SVG
        circ = 251.2
        offset = circ - (circ * risk_pct / 100)
        ring_svg = f"""
        <div class="risk-ring-wrap">
        <svg width="90" height="90" style="transform:rotate(-90deg)">
          <circle cx="45" cy="45" r="40" stroke="#1c2333" stroke-width="7" fill="none"/>
          <circle cx="45" cy="45" r="40" stroke="{vcolor}" stroke-width="7" fill="none"
                  stroke-dasharray="{circ}" stroke-dashoffset="{offset}"
                  stroke-linecap="round"/>
          <text x="-45" y="50" fill="{vcolor}" font-family="JetBrains Mono,monospace" 
                font-size="16" font-weight="700" transform="rotate(90deg)" text-anchor="middle">{risk_pct}%</text>
        </svg>
        <div class="risk-ring-label">Risk Score</div>
        </div>"""

        with results_ph.container():
            # Verdict banner
            st.markdown(f"""
            <div class="verdict-wrap {vclass}">
              {ring_svg}
              <div>
                <div class="verdict-sub">System Directive</div>
                <div class="verdict-title" style="color:{vcolor}">{verdict}</div>
                <div style="font-size:.82rem;color:var(--muted);margin-top:.4rem">{url_input[:80]}{"…" if len(url_input)>80 else ""}</div>
              </div>
            </div>
            """, unsafe_allow_html=True)

            # AI Narrative
            ai_cls = "danger" if risk_pct > 70 else ("warn" if risk_pct > 40 else "")
            st.markdown(f"""
            <div class="ai-box {ai_cls}">
              <div class="ai-label">🤖 AI Threat Intelligence Narrative</div>
              {semantic.get("narrative","No narrative available.")}
            </div>
            """, unsafe_allow_html=True)

            # ── Detail columns ────────────────────────────────────────────────
            col_l, col_r = st.columns([1, 1])

            with col_l:
                st.markdown("#### 🔬 URL Analysis")
                is_qr = "qr_ml_verdict" in url_report
                ml_v = url_report["qr_ml_verdict"] if is_qr else url_report.get("ml_verdict", {})
                conf = ml_v.get("confidence_score", 0)
                proto_s = url_report["protocol"]["status"]
                dom_s   = url_report["domain"]["status"]
                flag_s  = url_report["flags"]["status"]
                ml_s    = ml_v.get("status", "skipped")
                ml_label = "QR Forensic ML" if is_qr else "ML Model"

                def status_badge(s):
                    colors = {"safe":"var(--green)","warn":"var(--yellow)","danger":"var(--red)","skipped":"var(--muted)","error":"var(--muted)"}
                    return f'<span style="color:{colors.get(s,"var(--muted)")};font-family:var(--mono);font-size:.75rem">{s.upper()}</span>'

                st.markdown(f"""
                <div class="feat-grid">
                  <div class="feat-cell"><b>Protocol</b><br><span>{status_badge(proto_s)} {url_report["protocol"]["value"]}</span></div>
                  <div class="feat-cell"><b>Domain</b><br><span>{status_badge(dom_s)} {url_report["domain"]["value"][:22]}</span></div>
                  <div class="feat-cell"><b>Red Flags</b><br><span>{status_badge(flag_s)} {url_report["flags"]["count"]} found</span></div>
                  <div class="feat-cell"><b>{ml_label}</b><br><span>{status_badge(ml_s)} RF+GB</span></div>
                  <div class="feat-cell"><b>Threat Prob.</b><br><span style="color:{"var(--red)" if conf>50 else "var(--green)"};font-family:var(--mono)">{conf:.1f}%</span></div>
                  <div class="feat-cell"><b>Safe Browsing</b><br><span>{status_badge(sb.get("status","skipped"))}</span></div>
                </div>
                """, unsafe_allow_html=True)

                if url_report["flags"]["items"]:
                    st.markdown("**🚩 Red Flags Detected:**")
                    for flag in url_report["flags"]["items"]:
                        st.markdown(f'<div class="action-item" style="border-color:var(--red)22">⚑ {flag}</div>', unsafe_allow_html=True)

            with col_r:
                st.markdown("#### 🛡️ Recommended Actions")
                for action in semantic.get("action_items", []):
                    st.markdown(f'<div class="action-item">{action}</div>', unsafe_allow_html=True)

                intents = semantic.get("intents", [])
                if intents:
                    st.markdown("**🎯 Detected Attack Intents:**")
                    sev_colors = {"critical":"var(--red)","high":"#f97316","medium":"var(--yellow)","low":"var(--muted)"}
                    for i in intents:
                        col = sev_colors.get(i["severity"], "var(--muted)")
                        st.markdown(f'<div class="action-item" style="border-left:3px solid {col}">'
                                    f'<b style="color:{col}">{i["intent"]}</b> '
                                    f'<span style="color:var(--muted);font-size:.72rem">[{i["severity"].upper()}]</span></div>',
                                    unsafe_allow_html=True)
                else:
                    st.markdown('<div class="action-item" style="color:var(--green)">✅ No malicious attack intents detected in URL pattern.</div>', unsafe_allow_html=True)

            # Physical tamper section (if image provided)
            if image_np is not None and ts != "skipped":
                st.markdown("---")
                st.markdown("#### 👁️ Physical Tamper Analysis")
                ta_col1, ta_col2 = st.columns([1, 2])
                with ta_col1:
                    try:
                        annotated = detector.get_annotated_image(image_np)
                        st.image(annotated, caption="Edge Detection Overlay", use_container_width=True)
                    except Exception:
                        pass
                with ta_col2:
                    conf_t = tamper_report.get("confidence", 0)
                    detail = tamper_report.get("detail", "")
                    sigs   = tamper_report.get("signals", [])
                    st.markdown(f'<div class="ai-box {"danger" if ts=="danger" else "warn" if ts=="warn" else ""}"><div class="ai-label">Tamper Report · Confidence {conf_t}%</div>{detail}</div>', unsafe_allow_html=True)
                    for s in sigs:
                        st.markdown(f'<div class="action-item">🔎 <b>{s["name"].replace("_"," ").title()}</b>: {s["description"]} (conf: {s["confidence"]}%)</div>', unsafe_allow_html=True)

        # ── Log to history ─────────────────────────────────────────────────────
        st.session_state.scan_history.insert(0, {
            "url":     url_input,
            "verdict": verdict,
            "risk":    risk_pct,
            "time":    time.strftime("%H:%M:%S"),
        })
        if len(st.session_state.scan_history) > 50:
            st.session_state.scan_history = st.session_state.scan_history[:50]

    elif do_scan and not url_input:
        st.error("Please enter a URL or upload a QR image first.")

# ── HISTORY TAB ───────────────────────────────────────────────────────────────
with tab_history:
    st.markdown("#### 📋 Scan History")
    if not st.session_state.scan_history:
        st.markdown('<div class="ai-box">No scans yet. Run your first scan in the Scanner tab.</div>', unsafe_allow_html=True)
    else:
        for entry in st.session_state.scan_history:
            risk  = entry["risk"]
            color = "var(--red)" if risk > 70 else ("var(--yellow)" if risk > 40 else "var(--green)")
            st.markdown(f"""
            <div class="hist-row">
              <div class="hist-dot" style="background:{color}"></div>
              <span style="font-family:var(--mono);font-size:.75rem;color:var(--muted)">{entry["time"]}</span>
              <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.82rem">{entry["url"]}</span>
              <span style="font-family:var(--mono);font-size:.78rem;color:{color};flex-shrink:0">{entry["verdict"]}</span>
              <span style="font-family:var(--mono);font-size:.78rem;color:{color};flex-shrink:0;min-width:45px;text-align:right">{risk}%</span>
            </div>
            """, unsafe_allow_html=True)
        if st.button("🗑️ Clear History"):
            st.session_state.scan_history = []
            st.rerun()

# ── THREAT INTEL TAB ──────────────────────────────────────────────────────────
with tab_intel:
    st.markdown("#### 🕵️ India-Specific QRishing Threat Database")

    threats = [
        ("🏦 KYC / PAN Update Scam", "Scammer sends a QR code claiming urgent Aadhaar/PAN KYC update for the bank. The link loads a fake bank portal that steals identity documents.", "CRITICAL"),
        ("💳 UPI Payment Redirect", "Fake QR codes at shops redirect payments to scammer UPI IDs. The merchant's original code is hidden beneath a sticker with identical branding.", "CRITICAL"),
        ("🏆 Lottery / Lucky Draw", "QR codes on posters or WhatsApp messages claim the user has won a prize. Destination harvests UPI PIN or OTP to 'process the reward'.", "HIGH"),
        ("📦 Fake Delivery / Customs Scam", "Shortened QR/URL mimicking FedEx, Delhivery, or India Post. User is asked to pay a fake customs fee via UPI — money goes to attacker.", "HIGH"),
        ("🔌 Fake Soundbox Sticker", "Scammer replaces or covers a Paytm/PhonePe soundbox QR sticker in shops. OpenCV detects double-border contour and shadow lift at edge.", "CRITICAL"),
        ("📶 Parking Meter / Transit QR", "Fake QR stickers on parking meters or railway kiosks. Destination site charges for a ticket that is never issued.", "HIGH"),
        ("📱 APK Download Trap", "QR code links to an APK file disguised as a banking or IRCTC app update. Installed app harvests SMS OTPs silently.", "CRITICAL"),
        ("🆔 Aadhaar Verification Phishing", "Site impersonates UIDAI.gov.in and asks user to upload Aadhaar card front and back. Used for identity theft and unauthorized loans.", "CRITICAL"),
    ]

    sev_colors = {"CRITICAL":"var(--red)","HIGH":"#f97316","MEDIUM":"var(--yellow)"}

    for title, desc, sev in threats:
        col = sev_colors.get(sev, "var(--muted)")
        st.markdown(f"""
        <div class="intel-card" style="border-left:3px solid {col}">
            <div class="intel-title">{title} <span style="font-size:.7rem;font-family:var(--mono);color:{col};margin-left:.5rem">[{sev}]</span></div>
            <div class="intel-desc">{desc}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### ℹ️ How VisionGuard Detects Threats")
    st.markdown("""
    <div class="feat-grid" style="grid-template-columns:repeat(2,1fr)">
      <div class="feat-cell"><b>12-Feature ML Model</b><br><span>URL length, HTTPS, scam keywords, IP usage, suspicious TLD, shortener detection, subdomain depth, trusted domain match, path depth, query params, hyphens, @ symbol</span></div>
      <div class="feat-cell"><b>Ensemble Architecture</b><br><span>Random Forest (200 trees) + Gradient Boosting (150 estimators) soft-voting ensemble with StandardScaler preprocessing — 100% CV accuracy on training set</span></div>
      <div class="feat-cell"><b>Physical Tamper Analysis</b><br><span>OpenCV Canny edge detection + contour nesting analysis (double-border), shadow gradient check at QR boundary, texture variance between QR and surrounding surface</span></div>
      <div class="feat-cell"><b>AI Semantic Decoder</b><br><span>Pattern-matched intent classification (credential harvesting, OTP interception, identity theft, payment redirect, malware distribution) + Gemini/fallback narrative synthesis</span></div>
    </div>
    """, unsafe_allow_html=True)