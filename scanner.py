"""
modules/scanner.py
──────────────────
Decodes QR codes from images using pyzbar + OpenCV.
Falls back to cv2.QRCodeDetector if pyzbar is unavailable.
"""

import cv2
import numpy as np
from typing import Optional

try:
    from pyzbar import pyzbar
    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False


def decode_qr_from_image(image_np: np.ndarray) -> Optional[str]:
    """
    Given a numpy BGR/RGB image, return the decoded URL string
    from the first QR code found, or None if not found.
    """
    # Ensure BGR for OpenCV
    if image_np.shape[2] == 3:
        bgr = cv2.cvtColor(image_np, cv2.COLOR_RGB2BGR)
    else:
        bgr = image_np

    # ── Method 1: pyzbar (more reliable) ────────────────────────────────────
    if PYZBAR_AVAILABLE:
        gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
        codes = pyzbar.decode(gray)
        for code in codes:
            if code.type == "QRCODE":
                return code.data.decode("utf-8")

    # ── Method 2: OpenCV built-in ────────────────────────────────────────────
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(gray)
    if data:
        return data

    # ── Method 3: Try with preprocessing (blur + threshold) ─────────────────
    blurred = cv2.GaussianBlur(gray, (5, 5), 0)
    _, thresh = cv2.threshold(blurred, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    data, _, _ = detector.detectAndDecode(thresh)
    if data:
        return data

    # ── Method 4: Inversion fallback (dark-background / inverted QRs) ────────
    inverted = cv2.bitwise_not(gray)
    if PYZBAR_AVAILABLE:
        codes = pyzbar.decode(inverted)
        for code in codes:
            if code.type == "QRCODE":
                return code.data.decode("utf-8")
    data, _, _ = detector.detectAndDecode(inverted)
    if data:
        return data

    # ── Method 5: Inverted + threshold ───────────────────────────────────────
    _, thresh_inv = cv2.threshold(inverted, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    data, _, _ = detector.detectAndDecode(thresh_inv)
    return data if data else None


def decode_qr_from_url_string(raw: str) -> str:
    """Normalise a manually pasted URL string."""
    raw = raw.strip()
    if not raw.startswith("http"):
        raw = "https://" + raw
    return raw


def locate_qr_bbox(image_np: np.ndarray):
    """
    Returns the bounding box (x, y, w, h) of the first QR code in the image,
    or None. Used by the tamper detector.
    """
    bgr = cv2.cvtColor(image_np, cv2.COLOR_RGB2BGR)
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)

    if PYZBAR_AVAILABLE:
        codes = pyzbar.decode(gray)
        for code in codes:
            if code.type == "QRCODE":
                rect = code.rect
                return (rect.left, rect.top, rect.width, rect.height)

    detector = cv2.QRCodeDetector()
    _, points, _ = detector.detectAndDecode(gray)
    if points is not None and len(points) > 0:
        pts = points[0]
        x_min = int(pts[:, 0].min())
        y_min = int(pts[:, 1].min())
        x_max = int(pts[:, 0].max())
        y_max = int(pts[:, 1].max())
        return (x_min, y_min, x_max - x_min, y_max - y_min)

    return None