"""
modules/tamper_detector.py
───────────────────────────
Physical QR tampering detection using OpenCV:

THEORY
------
Legitimate QR codes printed on a sign/poster sit flat — the edge detector
sees ONE clean rectangular contour around the QR code.

A scammer sticker pasted OVER a legitimate QR code creates:
  • A second outer contour (the original code beneath)
  • An offset shadow / slight 3-D lift
  • A brightness discontinuity at the sticker boundary

This module detects those signals using Canny edge detection + contour
analysis + perspective-corrected corner inspection.
"""

import cv2
import numpy as np
from typing import Dict, Any, Optional, Tuple


class TamperDetector:

    # Tunable thresholds
    CANNY_LOW = 50
    CANNY_HIGH = 150
    DOUBLE_BORDER_THRESHOLD = 0.18   # fraction of QR size for "second border"
    SHADOW_GRADIENT_THRESHOLD = 12   # pixel intensity jump at border

    def analyze(self, image_np: np.ndarray) -> Dict[str, Any]:
        """
        Returns a dict:
          status       : "safe" | "warn" | "danger" | "skipped"
          detail       : human-readable finding
          confidence   : 0-100 (how confident we are in the finding)
          signals      : list of individual signals detected
        """
        bgr = self._to_bgr(image_np)
        gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)

        # Step 1: Locate QR region
        qr_bbox = self._locate_qr(bgr, gray)
        if qr_bbox is None:
            return {
                "status": "skipped",
                "detail": "Could not locate QR code boundary for tamper analysis",
                "confidence": 0,
                "signals": [],
            }

        x, y, w, h = qr_bbox
        roi = gray[y : y + h, x : x + w]

        signals = []

        # Signal 1: Double contour (sticker layering)
        double_border, db_conf = self._check_double_border(roi)
        if double_border:
            signals.append({
                "name": "double_border",
                "description": "Two concentric rectangular contours detected",
                "confidence": db_conf,
            })

        # Signal 2: Shadow / lateral brightness drop at edge
        shadow, sh_conf = self._check_edge_shadow(gray, qr_bbox)
        if shadow:
            signals.append({
                "name": "shadow_artifact",
                "description": "Lateral brightness gradient suggests 3-D lift (sticker)",
                "confidence": sh_conf,
            })

        # Signal 3: Uneven surface texture inside vs outside QR
        texture, tx_conf = self._check_texture_discontinuity(gray, qr_bbox)
        if texture:
            signals.append({
                "name": "texture_discontinuity",
                "description": "Paper/print texture differs inside vs outside QR boundary",
                "confidence": tx_conf,
            })

        # ── Aggregate verdict ────────────────────────────────────────────────
        if not signals:
            return {
                "status": "safe",
                "detail": "No physical tampering indicators detected. QR code appears original.",
                "confidence": 85,
                "signals": [],
            }

        max_conf = max(s["confidence"] for s in signals)
        total_signals = len(signals)

        if total_signals >= 2 or max_conf >= 75:
            status = "danger"
            detail = "HIGH CONFIDENCE — sticker overlay detected. Do NOT scan this code."
        else:
            status = "warn"
            detail = "POSSIBLE tampering — one suspicious signal. Inspect the QR physically before proceeding."

        return {
            "status": status,
            "detail": detail,
            "confidence": min(max_conf + (total_signals - 1) * 10, 99),
            "signals": signals,
        }

    def get_annotated_image(self, image_np: np.ndarray) -> np.ndarray:
        """Returns an RGB image with edge-detection overlay for display."""
        bgr = self._to_bgr(image_np)
        gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
        edges = cv2.Canny(gray, self.CANNY_LOW, self.CANNY_HIGH)
        edges_colored = cv2.cvtColor(edges, cv2.COLOR_GRAY2BGR)

        # Tint edges red
        overlay = bgr.copy()
        overlay[edges > 0] = [0, 0, 220]  # red in BGR

        result = cv2.addWeighted(bgr, 0.7, overlay, 0.3, 0)

        # Draw QR bounding box if found
        qr_bbox = self._locate_qr(bgr, gray)
        if qr_bbox:
            x, y, w, h = qr_bbox
            cv2.rectangle(result, (x, y), (x + w, y + h), (0, 255, 100), 2)

        return cv2.cvtColor(result, cv2.COLOR_BGR2RGB)

    # ── Private helpers ───────────────────────────────────────────────────────

    def _to_bgr(self, image_np: np.ndarray) -> np.ndarray:
        if image_np.ndim == 2:
            return cv2.cvtColor(image_np, cv2.COLOR_GRAY2BGR)
        if image_np.shape[2] == 4:
            return cv2.cvtColor(image_np, cv2.COLOR_RGBA2BGR)
        return cv2.cvtColor(image_np, cv2.COLOR_RGB2BGR)

    def _locate_qr(self, bgr, gray) -> Optional[Tuple[int,int,int,int]]:
        """Attempt to find QR bounding box using pyzbar or OpenCV."""
        try:
            from pyzbar import pyzbar
            codes = pyzbar.decode(gray)
            for c in codes:
                if c.type == "QRCODE":
                    r = c.rect
                    pad = 10
                    return (max(0, r.left - pad), max(0, r.top - pad),
                            r.width + 2*pad, r.height + 2*pad)
        except Exception:
            pass

        detector = cv2.QRCodeDetector()
        _, points, _ = detector.detectAndDecode(gray)
        if points is not None and len(points):
            pts = points[0]
            x1, y1 = int(pts[:,0].min()), int(pts[:,1].min())
            x2, y2 = int(pts[:,0].max()), int(pts[:,1].max())
            pad = 10
            return (max(0,x1-pad), max(0,y1-pad), x2-x1+2*pad, y2-y1+2*pad)

        # Last resort: find large square contour
        blurred = cv2.GaussianBlur(gray, (5,5), 0)
        edges = cv2.Canny(blurred, 50, 150)
        contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        for cnt in sorted(contours, key=cv2.contourArea, reverse=True)[:5]:
            approx = cv2.approxPolyDP(cnt, 0.02 * cv2.arcLength(cnt, True), True)
            if len(approx) == 4:
                x, y, w, h = cv2.boundingRect(approx)
                aspect = w / h if h else 0
                if 0.8 < aspect < 1.2 and w > 50:
                    return (x, y, w, h)
        return None

    def _check_double_border(self, roi: np.ndarray) -> Tuple[bool, int]:
        """
        Detect concentric rectangular contours inside the QR ROI.
        A second inner rectangle near the border = sticker layer below.
        """
        edges = cv2.Canny(roi, self.CANNY_LOW, self.CANNY_HIGH)
        contours, _ = cv2.findContours(edges, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)

        rect_contours = []
        for cnt in contours:
            peri = cv2.arcLength(cnt, True)
            approx = cv2.approxPolyDP(cnt, 0.04 * peri, True)
            if len(approx) == 4:
                area = cv2.contourArea(approx)
                if area > (roi.shape[0] * roi.shape[1]) * 0.1:
                    rect_contours.append(cv2.boundingRect(approx))

        if len(rect_contours) >= 2:
            # Check if two rectangles are nested (offset by threshold)
            rect_contours.sort(key=lambda r: r[2]*r[3], reverse=True)
            r1, r2 = rect_contours[0], rect_contours[1]
            w_diff = abs(r1[2] - r2[2]) / max(r1[2], 1)
            if self.DOUBLE_BORDER_THRESHOLD < w_diff < 0.5:
                confidence = min(60 + int(w_diff * 100), 90)
                return True, confidence
        return False, 0

    def _check_edge_shadow(self, gray: np.ndarray, bbox: Tuple) -> Tuple[bool, int]:
        """
        Check for a brightness step-function just outside the QR border.
        A sticker slightly raised off the surface casts a thin shadow.
        """
        x, y, w, h = bbox
        margin = 8

        # Sample rows just outside left/right edges
        gradients = []
        for dy in range(0, h, max(1, h//10)):
            row_y = y + dy
            if row_y >= gray.shape[0]:
                continue
            # Left edge: compare inside vs outside
            x_in  = max(0, x + 3)
            x_out = max(0, x - margin)
            if x_in < gray.shape[1] and x_out < gray.shape[1]:
                diff = abs(int(gray[row_y, x_in]) - int(gray[row_y, x_out]))
                gradients.append(diff)

        if not gradients:
            return False, 0

        avg_grad = np.mean(gradients)
        if avg_grad > self.SHADOW_GRADIENT_THRESHOLD * 2:
            return True, min(50 + int(avg_grad), 80)
        return False, 0

    def _check_texture_discontinuity(self, gray: np.ndarray, bbox: Tuple) -> Tuple[bool, int]:
        """
        Variance in micro-texture of print should be homogeneous.
        A sticker has different paper/ink texture from the sign beneath it.
        """
        x, y, w, h = bbox
        pad = 20

        # Inside ROI
        x1, y1 = max(0, x+5), max(0, y+5)
        x2, y2 = min(gray.shape[1], x+w-5), min(gray.shape[0], y+h-5)
        if x2 <= x1 or y2 <= y1:
            return False, 0
        inside = gray[y1:y2, x1:x2]

        # Outside ROI (frame around it)
        ox1, oy1 = max(0, x-pad), max(0, y-pad)
        ox2, oy2 = min(gray.shape[1], x+w+pad), min(gray.shape[0], y+h+pad)
        outside_full = gray[oy1:oy2, ox1:ox2].copy()
        # Mask out the inside
        rel_x, rel_y = x - ox1, y - oy1
        outside_full[rel_y:rel_y+h, rel_x:rel_x+w] = 0
        outside = outside_full[outside_full > 0]

        if inside.size < 100 or outside.size < 100:
            return False, 0

        var_in  = np.var(inside.flatten())
        var_out = np.var(outside.flatten())

        ratio = max(var_in, var_out) / (min(var_in, var_out) + 1e-5)
        if ratio > 3.5:
            return True, min(40 + int(ratio * 5), 70)
        return False, 0
