"""
train_model.py  —  VisionGuard AI v7.0
Trains on url_dataset.csv (1200 URLs) + qr_dataset.csv (1200 QR records).
Uses a 12-feature URL ensemble + an extended 16-feature QR ensemble.
Saves → url_classifier.joblib  and  qr_classifier.joblib
"""

import csv
import re
import numpy as np
from urllib.parse import urlparse
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report
import joblib

print("🛡️  VisionGuard AI v7.0 — Dataset-Driven Ensemble Trainer")
print("=" * 58)

# ─────────────────────────────────────────────────────────────────────────────
# Constants (must match url_checker.py)
# ─────────────────────────────────────────────────────────────────────────────

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

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "s.id", "rb.gy", "cutt.ly", "short.gy", "tiny.one",
    "is.gd", "v.gd", "buff.ly",
]


# ─────────────────────────────────────────────────────────────────────────────
# Feature extraction — URL (12 features, matches url_checker.py)
# ─────────────────────────────────────────────────────────────────────────────

def extract_url_features(url: str) -> list:
    if not url.startswith("http"):
        url = "https://" + url
    parsed   = urlparse(url)
    hostname = (parsed.hostname or "").replace("www.", "").lower()
    full_url = url.lower()
    path     = (parsed.path or "").lower()

    return [
        len(full_url),                                                                  # 1
        1 if parsed.scheme == "https" else 0,                                           # 2
        sum(1 for k in SCAM_KEYWORDS if k in full_url),                                # 3
        1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0,                   # 4
        1 if "@" in full_url else 0,                                                    # 5
        hostname.count("-"),                                                            # 6
        max(0, len(hostname.split(".")) - 2),                                           # 7
        1 if any(hostname.endswith(t) for t in SUSPICIOUS_TLDS) else 0,               # 8
        1 if any(s in hostname for s in SHORTENERS) else 0,                            # 9
        1 if any(hostname == d or hostname.endswith("." + d)
                 for d in TRUSTED_DOMAINS) else 0,                                     # 10
        path.count("/"),                                                                # 11
        1 if parsed.query else 0,                                                       # 12
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Feature extraction — QR record (16 features = 12 URL + 4 QR-specific)
# ─────────────────────────────────────────────────────────────────────────────

TAMPER_SIGNAL_WEIGHT = {
    "none": 0,
    "double_border": 1,
    "shadow_artifact": 1,
    "texture_discontinuity": 1,
    "double_border,shadow_artifact": 2,
    "double_border,texture_discontinuity": 2,
    "shadow_artifact,texture_discontinuity": 2,
    "double_border,shadow_artifact,texture_discontinuity": 3,
}


def extract_qr_features(row: dict) -> list:
    url_feats = extract_url_features(row["url"])
    signals   = row.get("physical_tamper_signals", "none")
    conf      = float(row.get("tamper_confidence", 0)) / 100.0
    weight    = TAMPER_SIGNAL_WEIGHT.get(signals, 0)
    is_upi    = int(row.get("is_upi", 0))
    # QR-specific features (4 extra)
    qr_extra  = [
        weight,                             # 13: tamper signal count (0-3)
        conf,                               # 14: tamper detector confidence (0-1)
        is_upi,                             # 15: UPI payment link flag
        1 if signals != "none" else 0,      # 16: any physical tampering at all
    ]
    return url_feats + qr_extra


# ─────────────────────────────────────────────────────────────────────────────
# Build ensemble pipeline
# ─────────────────────────────────────────────────────────────────────────────

def build_pipeline():
    rf = RandomForestClassifier(
        n_estimators=300, max_depth=10, min_samples_leaf=2,
        class_weight="balanced", random_state=42, n_jobs=-1,
    )
    gb = GradientBoostingClassifier(
        n_estimators=200, max_depth=6, learning_rate=0.04,
        subsample=0.8, random_state=42,
    )
    ensemble = VotingClassifier(
        estimators=[("rf", rf), ("gb", gb)],
        voting="soft", weights=[1, 1.5],
    )
    return Pipeline([("scaler", StandardScaler()), ("model", ensemble)])


# ─────────────────────────────────────────────────────────────────────────────
# Load datasets
# ─────────────────────────────────────────────────────────────────────────────

def load_url_dataset(path="url_dataset.csv"):
    X, y = [], []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                feats = extract_url_features(row["url"])
                X.append(feats)
                y.append(int(row["label"]))
            except Exception as e:
                print(f"  [warn] Skipping row: {e}")
    return np.array(X, dtype=float), np.array(y)


def load_qr_dataset(path="qr_dataset.csv"):
    X, y = [], []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                feats = extract_qr_features(row)
                X.append(feats)
                y.append(int(row["label"]))
            except Exception as e:
                print(f"  [warn] Skipping row: {e}")
    return np.array(X, dtype=float), np.array(y)


# ─────────────────────────────────────────────────────────────────────────────
# Train
# ─────────────────────────────────────────────────────────────────────────────

def train_and_save(X, y, label, output_path):
    print(f"\n[*] Training {label} model — {len(X)} samples, {X.shape[1]} features")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    pipe = build_pipeline()
    scores = cross_val_score(pipe, X, y, cv=cv, scoring="accuracy")
    print(f"    5-fold CV accuracy : {scores.mean()*100:.2f}% ± {scores.std()*100:.2f}%")

    f1_scores = cross_val_score(pipe, X, y, cv=cv, scoring="f1")
    print(f"    5-fold CV F1       : {f1_scores.mean():.4f} ± {f1_scores.std():.4f}")

    pipe.fit(X, y)
    train_acc = pipe.score(X, y)
    print(f"    Training accuracy  : {train_acc*100:.2f}%")

    # Full classification report on training set (informational)
    y_pred = pipe.predict(X)
    print("\n" + classification_report(y, y_pred, target_names=["Safe", "Scam"]))

    joblib.dump(pipe, output_path)
    print(f"[+] Saved → {output_path}")
    return pipe


if __name__ == "__main__":
    # ── URL Model ─────────────────────────────────────────────────────────────
    print("\n── URL Classifier ───────────────────────────────────────")
    X_url, y_url = load_url_dataset("url_dataset.csv")
    train_and_save(X_url, y_url, "URL", "url_classifier.joblib")

    # ── QR Model ──────────────────────────────────────────────────────────────
    print("\n── QR Classifier (URL + Physical Tamper features) ───────")
    X_qr, y_qr = load_qr_dataset("qr_dataset.csv")
    train_and_save(X_qr, y_qr, "QR", "qr_classifier.joblib")

    print("\n[+] VisionGuard AI v7.0 training complete!")
    print("    Models saved: url_classifier.joblib  qr_classifier.joblib")