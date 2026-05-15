# Enhanced Email Verifier — Setup Guide

## 3-Layer Verification:
  Layer 1: SMTP RCPT TO (port 25 → STARTTLS port 587 fallback)
  Layer 2: ZeroBounce API (risky/timeout emails)
  Layer 3: Kickbox API (ZeroBounce fail হলে)

Expected accuracy: ~85-90% (vs old tool: ~40-50%)

---

## Install Dependencies

Open Terminal in this folder:

  pip install flask flask-cors dnspython requests

---

## Run

Terminal 1 (backend):
  python verify-app.py

Terminal 2 (frontend):
  python -m http.server 3000

Open browser:
  http://localhost:3000/index.html

---

## What's New vs Old Version

- STARTTLS fallback (port 587) — catches servers that block port 25
- 100+ disposable domains (was 3)
- 60+ role-based prefixes (was 5)
- Typo detection — gmial.com → gmail.com suggestion in output
- ZeroBounce API fallback (100 credits/month)
- Kickbox API fallback (100 credits/month)
- SQLite persistence — job history survives server restart
- Real-time stats — valid/risky/invalid count live
- Past Jobs history panel in UI
- Output CSV has 'typo_suggestion' column

---

## API Keys (already in verify-app.py)

  ZeroBounce : c458132aaf934750923584f3fa06afc7     (100/month)
  Kickbox    : live_41103aad87ce619d...              (100/month)

---

## CSV Format Required

Your CSV must have a column named exactly: Email
Other columns (Name, Company, etc.) pass through unchanged.

Output adds 3 columns: status | reason | typo_suggestion
Status values: valid / risky / invalid
