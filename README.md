# VisionGuard AI
> Protecting the Physical-to-Digital Leap.

**VisionGuard AI** is a holistic QR Safety Net. Traditional QR scanners are "blind." They open links without checking if the URL is a scam or if the physical QR code is a sticker pasted over a real one.

VisionGuard AI solves this by acting as a Vision Assistant that uses **Multi-Layered AI** to verify the digital reputation, physical integrity, and "hallucinated" intent of a QR code *before* the user clicks.

**Key Innovation:** Uses Adversarial Hallucination to predict scammer intent based on micro-patterns in the physical world.
 
---

## The "Triple-Shield" Architecture

### 🛡️ Shield 1: Digital Reputation (The "Brain")
* **Feature:** Real-time URL reputation checking.
* **Implementation:** Connects to the Google Safe Browsing API.
* **Function:** It flags "typosquatting" (e.g., `pay-tm.com`), evaluates domain age signals, and checks against malware site databases.

### 🛡️ Shield 2: Physical Integrity (The "Eyes")
* **Feature:** Micro-pattern and Layer Analysis.
* **Implementation:** Uses OpenCV (Computer Vision).
* **Function:** It looks for "shadows", "texture mismatches", or "raised edges" around the QR code. If the code looks like a sticker pasted onto a real sign, the AI immediately flags a "Physical Tamper Warning."

### 🛡️ Shield 3: Semantic Hallucination (The "Innovation")
* **Feature:** Context-Destination Matching.
* **Implementation:** Uses a Large Language Model (Gemini 2.0 Flash) through few-shot Adversarial Hallucination.
* **Function:** The AI "hallucinates" what the scammer's destination actually is versus what it pretends to be. If the link points to a "Gift Card Claim" site instead of the physically implied portal, it detects a critical Context Mismatch.

---

## Technical Stack

| Layer | Tool / API | Why? |
| --- | --- | --- |
| **Frontend** | Streamlit | Easiest way to build a high-fidelity web dashboard with Python. |
| **Scanner** | OpenCV + Pyzbar | Standard industry tools for image processing and structural edge detection. |
| **Cloud AI** | Google Gemini SDK | High-accuracy Large Language Model integration to drive the Semantic logic. |
| **Security** | Google Safe Browsing API | Checks the link against millions of flagged malware targets in real-time. |

---

## Step-by-Step Implementation Guide

### Step 1: The "Sandbox" Scanner
When VisionGuard encounters a QR code or URL, it pauses. Instead of opening the link, it loads a highly polished Streamlit sandbox dashboard, displaying a "Wait: Analyzing Safety" status.

### Step 2: The Metadata Analysis
Extracts the URL and sends it into the validation pipeline:
* **Check 1:** Is it using `https` encryption?
* **Check 2:** Is the domain trusted, or is it a malicious typosquat?
* **Check 3:** Does the URL contain suspicious words like `win`, `prize`, or `verify`?

### Step 3: The Hallucination Output
Uses Gemini to generate triple "Safety Summaries". It hallucinates the intent of the site and delivers a verdict. 
> *Example AI Output: "I have clean-room evaluated the intent of this site. It claims to be an electricity bill portal, but it is hosted on a high-risk free domain. Proceed with extreme caution."*

---

## How to present this for a 10/10 Grade

1. **Live Demo:** Show a "Real" QR code (Green Light) vs. a "Scam" QR code (Red Light). There are handy demo buttons right in the "Paste URL" tab in the UI.
2. **The "Sticker" Test:** Upload an image of a QR code with a sticker over it. Show how our AI (Shield 2) detects the physical edges and shadows that standard tools like Google Lens completely miss.
3. **The Pitch:** 
> "Most tools protect the phone; we protect the user. By combining physical vision with digital hallucination, we've built a system that thinks like a security expert, not just a barcode reader."

---

## Setup & Run Locally

```bash
# Clone the repository
git clone https://github.com/yourname/visionguard-ai
cd visionguard-ai

# Install dependencies (requires Python 3.10+)
pip install -r requirements.txt

# Start the VisionGuard AI Dashboard
streamlit run app.py
```
