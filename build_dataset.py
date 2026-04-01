"""
build_dataset.py — VisionGuard AI v7.0
Generates url_dataset.csv and qr_dataset.csv for model training.
Run:  python build_dataset.py
"""

import csv, random, itertools
random.seed(42)

# ─────────────────────────────────────────────────────────────────────────────
# SAFE URL COMPONENTS
# ─────────────────────────────────────────────────────────────────────────────

SAFE_DOMAINS = [
    # Banking
    "hdfcbank.com", "sbi.co.in", "icicibank.com", "axisbank.com",
    "kotak.com", "yesbank.in", "pnbindia.in", "bankofbaroda.in",
    "canarabank.com", "unionbankofindia.co.in", "indianbank.in",
    "centralbankschet.in", "iob.in", "bankofindia.co.in",
    "rblbank.com", "federalbank.co.in", "idbibank.com",
    "indusind.com", "dcbbank.com", "bandhanbank.com",
    # UPI / Payments
    "paytm.com", "phonepe.com", "gpay.app", "bhimupi.org.in",
    "npci.org.in", "mobikwik.com", "freecharge.in", "airtelbank.com",
    "jiopay.in", "amazonpay.in", "razorpay.com", "cashfree.com",
    "payumoney.com", "instamojo.com",
    # E-Commerce
    "amazon.in", "flipkart.com", "myntra.com", "snapdeal.com",
    "meesho.com", "nykaa.com", "tatacliq.com", "ajio.com",
    "relianceretail.com", "bigbasket.com", "grofers.com",
    "blinkit.com", "zepto.com", "jiomart.com",
    # Food
    "zomato.com", "swiggy.com", "dunzo.com", "magicpin.in",
    # Travel / Transport
    "irctc.co.in", "makemytrip.com", "goibibo.com", "cleartrip.com",
    "yatra.com", "ixigo.com", "redbus.in", "abhibus.com",
    "olamoney.com", "uber.com", "rapido.bike",
    # Government
    "india.gov.in", "uidai.gov.in", "incometax.gov.in",
    "gst.gov.in", "mca.gov.in", "epfindia.gov.in",
    "digitalindia.gov.in", "nhp.gov.in", "nha.gov.in",
    "passport.gov.in", "digilocker.gov.in", "umang.gov.in",
    # Utilities
    "bescom.org", "bsesdelhi.com", "mahadiscom.in",
    "torrentpower.com", "msedcl.com", "cesc.co.in",
    # Telecom
    "jio.com", "airtel.in", "vi.in", "bsnl.co.in",
    # Tech / Global
    "google.com", "apple.com", "microsoft.com", "paypal.com",
    "linkedin.com", "github.com", "stackoverflow.com",
]

SAFE_PATHS = [
    "/", "/home", "/about", "/contact", "/login", "/account",
    "/dashboard", "/profile", "/settings", "/help", "/faq",
    "/pay", "/netbanking", "/retail/login", "/personal/home",
    "/merchant", "/upi-faqs", "/savings", "/credit-card",
    "/product/12345", "/cart", "/checkout", "/order/track",
    "/booking", "/reservations", "/pnr-status",
    "/services", "/tax/efiling", "/gst-return",
    "/offers/today", "/sale/diwali", "/deals",
    "/restaurant/menu", "/table/45", "/order",
    "/api/v1/status", "/web/home", "/portal",
]

SAFE_PARAMS = [
    "", "?ref=home", "?utm_source=app", "?lang=en",
    "?city=mumbai", "?category=electronics", "?page=1",
    "?tab=summary", "?section=personal", "?q=weather",
]

# ─────────────────────────────────────────────────────────────────────────────
# SCAM URL COMPONENTS
# ─────────────────────────────────────────────────────────────────────────────

SCAM_TLDS = [
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".click",
    ".loan", ".work", ".gq", ".info", ".biz", ".pw",
    ".in.net", ".co.in.xyz", ".net.in", ".org.in.top",
    ".site", ".online", ".store", ".live",
]

SCAM_PREFIXES = [
    "secure-", "verify-", "update-", "confirm-", "alert-",
    "login-", "account-", "kyc-", "otp-", "aadhaar-",
    "pan-", "bank-", "upi-", "pay-", "wallet-",
    "win-", "prize-", "lucky-", "reward-", "claim-",
    "free-", "cashback-", "bonus-", "offer-", "scheme-",
    "refund-", "cancel-", "suspend-", "block-", "fraud-",
    "support-", "helpdesk-", "customer-", "service-", "care-",
    "new-", "official-", "real-", "genuine-", "trusted-",
    "safe-", "protected-", "encrypted-", "certified-",
]

SCAM_BRAND_NAMES = [
    "sbi", "hdfc", "icici", "axis", "paytm", "phonepe",
    "gpay", "amazon", "flipkart", "irctc", "uidai",
    "npci", "jio", "airtel", "bsnl", "nykaa", "zomato",
    "swiggy", "meesho", "razorpay", "incometax", "epfo",
]

SCAM_PATHS = [
    "/kyc-update", "/aadhaar-verify", "/pan-upload",
    "/otp-confirm", "/account-verify", "/secure-login",
    "/netbanking/login", "/upi/claim", "/pay/reward",
    "/win-prize/claim", "/lucky-draw/enter", "/gift/redeem",
    "/wallet/topup", "/recharge/free", "/cashback/get",
    "/apk/download", "/app/install", "/update/download",
    "/survey/complete", "/feedback/reward", "/rate/earn",
    "/refund/process", "/cancel/ticket", "/booking/verify",
    "/emi/offer", "/loan/apply", "/credit/approve",
    "/kyc/aadhaar", "/document/upload", "/id-proof/submit",
    "/account/suspended", "/card/blocked", "/upi/disabled",
    "/alert/security", "/notice/compliance", "/warning/action",
    "/customer/helpdesk", "/support/chat", "/care/ticket",
]

SCAM_PARAMS = [
    "?action=verify&token=abc123",
    "?ref=prize&id=WIN9999",
    "?otp=required&uid=user",
    "?kyc=pending&deadline=today",
    "?reward=5000&claim=now",
    "?account=suspended&reason=kyc",
    "?apk=latest&version=2.1",
    "?survey=complete&earn=500",
    "?refund=pending&bank=sbi",
    "?aadhaar=required&pan=required",
    "?session=expired&relogin=1",
    "?blocked=card&reason=fraud",
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "s.id", "rb.gy", "cutt.ly", "short.gy",
    "tiny.one", "is.gd", "v.gd", "buff.ly",
]

SHORTENER_PATHS = [
    "/3xYzAb", "/hdfc-verify-now", "/sbi-kyc-alert",
    "/upi-send-money", "/win-prize-5000", "/free-recharge",
    "/amazon-gift-claim", "/flipkart-lucky", "/paytm-reward",
    "/irctc-cancel-refund", "/aadhaar-update-now", "/otp-confirm",
    "/apk-banking-update", "/loan-approved-click", "/emi-offer",
    "/jio-recharge-free", "/airtel-cashback", "/vi-reward",
    "/epfo-pf-claim", "/income-tax-refund", "/gst-notice",
]

IP_BASES = [
    "192.168.1", "10.0.0", "172.16.0", "203.0.113",
    "198.51.100", "185.220.101", "91.108.4", "77.83.172",
]

# ─────────────────────────────────────────────────────────────────────────────
# GENERATORS
# ─────────────────────────────────────────────────────────────────────────────

def gen_safe_urls(n=600):
    urls = []
    # 1. Direct trusted domains × all paths
    for domain in SAFE_DOMAINS:
        for path in SAFE_PATHS:
            for param in SAFE_PARAMS[:3]:           # 3 param variants each
                urls.append(f"https://{domain}{path}{param}")

    # 2. Subdomains of trusted domains
    subdomains = ["net", "app", "pay", "retail", "corp", "portal", "secure", "api", "m", "www"]
    for domain in SAFE_DOMAINS:
        for sub in random.sample(subdomains, 3):
            path = random.choice(SAFE_PATHS)
            urls.append(f"https://{sub}.{domain}{path}")

    # 3. Explicit known-safe UPI deep-links (no false intent trigger)
    upi_safe = [
        "https://paytm.com/pay-merchant/store/12345",
        "https://phonepe.com/pay?merchant=abc",
        "https://gpay.app/pay-merchant/retail",
        "https://npci.org.in/upi-faqs",
        "https://bhimupi.org.in/pay",
        "https://razorpay.com/payment-pages",
        "https://cashfree.com/payment-gateway",
        "https://payumoney.com/paybill",
    ]
    urls.extend(upi_safe * 5)

    # Deduplicate and trim
    urls = list(dict.fromkeys(urls))
    random.shuffle(urls)
    return urls[:n]


def gen_scam_urls(n=600):
    urls = []

    # 1. Brand typosquat with scam TLD
    for brand in SCAM_BRAND_NAMES:
        for prefix in random.sample(SCAM_PREFIXES, 4):
            tld = random.choice(SCAM_TLDS)
            path = random.choice(SCAM_PATHS)
            param = random.choice(SCAM_PARAMS)
            urls.append(f"http://{prefix}{brand}{tld}{path}{param}")

    # 2. Brand in untrusted domain (brand-name.othertld)
    for brand in SCAM_BRAND_NAMES:
        for i in range(3):
            tld = random.choice(SCAM_TLDS)
            path = random.choice(SCAM_PATHS)
            urls.append(f"http://{brand}-india{tld}{path}")
            urls.append(f"http://{brand}.net-banking{tld}{path}")

    # 3. Shorteners
    for s_domain in SHORTENER_DOMAINS:
        for s_path in SHORTENER_PATHS:
            urls.append(f"http://{s_domain}{s_path}")

    # 4. IP-based
    for base in IP_BASES:
        for last in random.sample(range(1, 255), 6):
            path = random.choice(SCAM_PATHS)
            param = random.choice(SCAM_PARAMS)
            urls.append(f"http://{base}.{last}{path}{param}")

    # 5. @ symbol injection
    for brand in random.sample(SAFE_DOMAINS, 10):
        path = random.choice(SCAM_PATHS)
        urls.append(f"http://evil-domain.xyz@{brand}{path}")
        urls.append(f"http://user:pass@{brand}.fake.top{path}")

    # 6. Excessive subdomains
    for brand in random.sample(SCAM_BRAND_NAMES, 10):
        tld = random.choice(SCAM_TLDS)
        path = random.choice(SCAM_PATHS)
        urls.append(f"http://secure.account.verify.{brand}{tld}{path}")
        urls.append(f"http://login.update.kyc.{brand}.in{tld}{path}")

    # 7. Long obfuscated URLs
    for brand in random.sample(SCAM_BRAND_NAMES, 10):
        tld = random.choice(SCAM_TLDS)
        padding = "a" * random.randint(80, 130)
        path = random.choice(SCAM_PATHS)
        urls.append(f"http://{brand}-secure-verify-otp-update{tld}{path}/{padding}")

    # 8. Homoglyph / numeral substitution typosquats
    homoglyphs = {
        "sbi": ["5bi", "sb1", "sbi-online"],
        "hdfc": ["hdfcc", "h-dfc", "hdffc"],
        "icici": ["1cici", "icic1", "icicii"],
        "paytm": ["p4ytm", "paytem", "paytm-upi"],
        "zomato": ["z0mato", "zom4to", "zomatto"],
        "swiggy": ["sw1ggy", "swigy", "swiggy-offer"],
        "phonepe": ["ph0nepe", "phone-pe", "phonepee"],
        "amazon": ["4mazon", "amaz0n", "amazon-in-deal"],
        "flipkart": ["fl1pkart", "flipkart-sale", "fl1pkar7"],
        "irctc": ["irctc-booking", "1rctc", "irctcc"],
    }
    for brand, variants in homoglyphs.items():
        for v in variants:
            tld = random.choice(SCAM_TLDS)
            path = random.choice(SCAM_PATHS)
            urls.append(f"http://{v}{tld}{path}")
            urls.append(f"https://{v}{tld}{path}")  # https doesn't make scam safe

    # 9. HTTP (no TLS) on recognisable-sounding domains
    for brand in random.sample(SCAM_BRAND_NAMES, 15):
        path = random.choice(SCAM_PATHS)
        urls.append(f"http://{brand}-official.in{path}")
        urls.append(f"http://www.{brand}-portal.com{path}")

    # Deduplicate and trim
    urls = list(dict.fromkeys(urls))
    random.shuffle(urls)
    return urls[:n]


# ─────────────────────────────────────────────────────────────────────────────
# QR METADATA DATABASE
# ─────────────────────────────────────────────────────────────────────────────

def gen_qr_records(safe_urls, scam_urls):
    """
    Generates QR-level metadata: where the QR was found, physical
    tamper signals, decoded URL, and ground-truth label.
    """
    contexts_safe = [
        "Restaurant menu table tent", "Hotel check-in desk",
        "Retail store POS counter", "Cinema ticket kiosk",
        "Government office notice board", "Bank branch ATM lobby",
        "Hospital reception desk", "Airport check-in counter",
        "Supermarket self-checkout", "Petrol pump payment terminal",
        "Parking meter", "Bus/railway ticket window",
        "Printed product packaging", "Loyalty card mailer",
        "Official app onboarding screen", "Corporate ID badge",
    ]
    contexts_scam = [
        "Sticker pasted over original QR at shop",
        "Poster stuck on parking meter",
        "WhatsApp message from unknown number",
        "Email attachment from unknown sender",
        "Sticker on restaurant table (original torn off)",
        "Fake soundbox sticker at kirana store",
        "Pamphlet distributed near ATM",
        "Sticker on bus stop advertisement",
        "QR code in unsolicited SMS",
        "Sticker inside public toilet payment box",
        "Fake courier delivery slip",
        "Pasted over hospital payment QR",
        "Fake government notice board sticker",
        "Sticker over original parking QR",
        "Pasted on electricity bill payment kiosk",
        "Fake prize-claim poster at mall",
    ]
    tamper_none   = "none"
    tamper_signals = [
        "double_border",
        "shadow_artifact",
        "texture_discontinuity",
        "double_border,shadow_artifact",
        "double_border,texture_discontinuity",
        "shadow_artifact,texture_discontinuity",
        "double_border,shadow_artifact,texture_discontinuity",
    ]

    records = []
    for url in safe_urls:
        records.append({
            "url": url,
            "label": 0,
            "qr_format": random.choice(["QR Code", "Micro QR"]),
            "context": random.choice(contexts_safe),
            "physical_tamper_signals": tamper_none,
            "tamper_confidence": 0,
            "is_upi": int("upi" in url.lower() or "pay" in url.lower()),
            "has_https": int(url.startswith("https")),
            "domain_trusted": 1,
        })
    for url in scam_urls:
        has_tamper = random.random() < 0.65   # 65% of scam QRs show physical tampering
        signals = random.choice(tamper_signals) if has_tamper else tamper_none
        conf    = random.randint(55, 97)       if has_tamper else 0
        records.append({
            "url": url,
            "label": 1,
            "qr_format": random.choice(["QR Code", "Micro QR", "Data Matrix"]),
            "context": random.choice(contexts_scam),
            "physical_tamper_signals": signals,
            "tamper_confidence": conf,
            "is_upi": int("upi" in url.lower() or "pay" in url.lower()),
            "has_https": int(url.startswith("https")),
            "domain_trusted": 0,
        })
    random.shuffle(records)
    return records


# ─────────────────────────────────────────────────────────────────────────────
# WRITE CSVs
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    safe_urls = gen_safe_urls(600)
    scam_urls = gen_scam_urls(600)

    print(f"[*] Generated {len(safe_urls)} safe URLs")
    print(f"[*] Generated {len(scam_urls)} scam URLs")

    # ── url_dataset.csv ───────────────────────────────────────────────────────
    url_rows = (
        [{"url": u, "label": 0} for u in safe_urls] +
        [{"url": u, "label": 1} for u in scam_urls]
    )
    random.shuffle(url_rows)
    with open("url_dataset.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["url", "label"])
        w.writeheader()
        w.writerows(url_rows)
    print(f"[+] url_dataset.csv — {len(url_rows)} rows written")

    # ── qr_dataset.csv ────────────────────────────────────────────────────────
    qr_rows = gen_qr_records(safe_urls, scam_urls)
    with open("qr_dataset.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=qr_rows[0].keys())
        w.writeheader()
        w.writerows(qr_rows)
    print(f"[+] qr_dataset.csv  — {len(qr_rows)} rows written")
    print("[+] Done.")