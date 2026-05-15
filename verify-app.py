# verify-app.py — Enhanced Email Verifier
# Adds: STARTTLS, expanded lists, typo detection, ZeroBounce/Kickbox API fallback, SQLite persistence

import csv
import io
import os
import re
import time
import uuid
import sqlite3
import threading
import requests
import dns.resolver
import smtplib
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from tempfile import NamedTemporaryFile
from datetime import datetime

app = Flask(__name__)
CORS(app)

print("🔥 ENHANCED VERIFIER RUNNING — Multi-layer: SMTP + ZeroBounce + Kickbox 🔥")

# ==================== API KEYS (set via environment variables) ====================
ZEROBOUNCE_KEY = os.environ.get("ZEROBOUNCE_KEY", "")
KICKBOX_KEY    = os.environ.get("KICKBOX_KEY", "")

SMTP_HELO    = "mail.verifycheck.io"
SMTP_FROM    = "verify@verifycheck.io"
SMTP_TIMEOUT = 10
SMTP_DELAY   = 0.5  # seconds between checks to avoid IP blocks

# ==================== FILTER LISTS ====================
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

DISPOSABLE_DOMAINS = {
    "mailinator.com","10minutemail.com","guerrillamail.com","tempmail.com",
    "yopmail.com","throwaway.email","fakeinbox.com","trashmail.com",
    "dispostable.com","spamgourmet.com","mailnull.com","spamex.com",
    "dodgit.com","maildrop.cc","sharklasers.com","guerrillamail.info",
    "guerrillamail.biz","guerrillamail.de","guerrillamail.net","guerrillamail.org",
    "spam4.me","trashmail.at","trashmail.io","trashmail.me","trashmail.net",
    "discard.email","tempinbox.com","mailtemp.info","temp-mail.org",
    "tmpmail.net","tmpmail.org","temp-mail.io","getairmail.com",
    "filzmail.com","throwam.com","33mail.com","fakemailgenerator.com",
    "getnada.com","mailnesia.com","mintemail.com","mytrashmail.com",
    "ownmail.net","shredmail.com","spamfree24.org","tempalias.com",
    "tempe-mail.com","tempemail.net","tempmail.eu","tempmail2.com",
    "tempomail.fr","temporaryemail.net","temporaryinbox.com","thinmail.com",
    "trickmail.net","turual.com","venompen.com","viditag.com",
    "drdrb.com","mt2015.com","nospam.ze.tc","nowmymail.com",
    "mailexpire.com","jetable.fr.nf","jetable.net","jetable.org",
    "netzidiot.de","noblepioneer.com","notsharingmy.info","nowhere.org",
    "nwldx.com","objectmail.com","obobbo.com","odaymail.com","odnorazovoe.ru",
    "oneoffmail.com","onewaymail.com","online.ms","oopi.org","outlawspam.com",
    "pepbot.com","pookmail.com","proxymail.eu","putthisinyourspamdatabase.com",
    "qisoa.com","quickinbox.com","rcpt.at","recode.me","recursor.net",
    "rejectmail.com","rmqkr.net","rtrtr.com","s0ny.net","safe-mail.net",
    "safetymail.info","safetypost.de","sandelf.de","saynotospams.com",
    "sibmail.com","sneakemail.com","sofimail.com","spamavert.com",
    "spambob.com","spambob.net","spambob.org","spambog.com","spambog.de",
    "spambog.ru","spambox.info","spambox.us","spamcannon.com","spamcannon.net",
    "spamcero.com","spamcon.org","spamevader.com","spamex.com","spamfree24.de",
    "spamfree24.eu","spamfree24.info","spamfree24.net","spamgap.com",
    "spamgoes.in","spamherelots.com","spamhereplease.com","spamhole.com",
    "spamify.com","spaminator.de","spamkill.info","spaml.de","spamlot.net",
    "spammotel.com","spamoff.de","spamsalad.in","spamspot.com",
    "spamthis.co.uk","spamthisplease.com","spamtrail.com","speed.1s.fr",
}

ROLE_BASED_PREFIXES = {
    "info","support","admin","sales","contact","noreply","no-reply",
    "newsletter","marketing","hello","team","help","office","enquiries",
    "enquiry","webmaster","postmaster","abuse","spam","security",
    "privacy","legal","billing","accounts","accounting","hr",
    "recruitment","careers","jobs","press","media","pr","events",
    "feedback","complaints","unsubscribe","reply","bounce","mailer",
    "daemon","root","hostmaster","usenet","news","uucp","ftp",
    "www","service","services","donotreply","do-not-reply","mail",
    "email","notifications","alerts","updates","report","reports",
    "operations","ops","devops","sys","sysadmin","it","tech","helpdesk",
    "desk","reception","orders","order","invoice","invoices","payments",
    "payment","finance","payroll","purchase","purchasing","vendor",
    "suppliers","supply","procurement","general","enquire","ask",
    "getinfo","info-team","sales-team","support-team",
}

TYPO_MAP = {
    "gmial.com":"gmail.com","gmaill.com":"gmail.com","gmail.co":"gmail.com",
    "gamil.com":"gmail.com","gmai.com":"gmail.com","gmali.com":"gmail.com",
    "gmal.com":"gmail.com","gmail.con":"gmail.com","gmail.cpm":"gmail.com",
    "yaho.com":"yahoo.com","yahoo.co":"yahoo.com","yahooo.com":"yahoo.com",
    "yaho.co":"yahoo.com","ymail.co":"yahoo.com",
    "hotmial.com":"hotmail.com","hotmali.com":"hotmail.com","hotail.com":"hotmail.com",
    "hotmal.com":"hotmail.com","hotmil.com":"hotmail.com",
    "outlok.com":"outlook.com","outloook.com":"outlook.com","outllook.com":"outlook.com",
    "outlookk.com":"outlook.com","outook.com":"outlook.com",
    "aol.co":"aol.com","iclod.com":"icloud.com","icluod.com":"icloud.com",
    "protonmial.com":"protonmail.com","protonmal.com":"protonmail.com",
    "gmx.co":"gmx.com",
}

# ==================== SQLite ====================
DB_PATH = "verifier_jobs.db"
results_store = {}

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS jobs (
            job_id     TEXT PRIMARY KEY,
            filename   TEXT,
            total      INTEGER,
            progress   INTEGER DEFAULT 0,
            row_num    INTEGER DEFAULT 0,
            log        TEXT DEFAULT '',
            canceled   INTEGER DEFAULT 0,
            done       INTEGER DEFAULT 0,
            created_at TEXT,
            cnt_valid  INTEGER DEFAULT 0,
            cnt_risky  INTEGER DEFAULT 0,
            cnt_invalid INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

init_db()

def get_job(job_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None

def update_job(job_id, **kwargs):
    if not kwargs:
        return
    cols = ", ".join(f"{k}=?" for k in kwargs)
    vals = list(kwargs.values()) + [job_id]
    conn = sqlite3.connect(DB_PATH)
    conn.execute(f"UPDATE jobs SET {cols} WHERE job_id=?", vals)
    conn.commit()
    conn.close()

# ==================== API CHECKERS ====================

def zerobounce_check(email):
    try:
        url = (f"https://api.zerobounce.net/v2/validate"
               f"?api_key={ZEROBOUNCE_KEY}&email={email}&ip_address=")
        r = requests.get(url, timeout=12)
        d = r.json()
        s = d.get("status", "").lower()
        sub = d.get("sub_status", "") or ""
        if s == "valid":
            return "valid", "zb_valid"
        elif s == "invalid":
            return "invalid", f"zb_{sub or 'invalid'}"
        elif s == "catch-all":
            return "risky", "zb_catch_all"
        elif s == "spamtrap":
            return "invalid", "zb_spamtrap"
        elif s == "abuse":
            return "risky", "zb_abuse"
        elif s == "do_not_mail":
            return "invalid", f"zb_do_not_mail_{sub}"
        else:
            return "risky", f"zb_{s or 'unknown'}"
    except Exception:
        return None, "zb_error"

def kickbox_check(email):
    try:
        url = (f"https://api.kickbox.com/v2/verify"
               f"?email={email}&apikey={KICKBOX_KEY}&timeout=6000")
        r = requests.get(url, timeout=14)
        d = r.json()
        result = d.get("result", "")
        reason = d.get("reason", "") or ""
        if result == "deliverable":
            return "valid", "kb_deliverable"
        elif result == "undeliverable":
            return "invalid", f"kb_{reason}"
        elif result == "risky":
            return "risky", f"kb_{reason}"
        elif result == "unknown":
            return "risky", "kb_unknown"
        else:
            return None, "kb_error"
    except Exception:
        return None, "kb_error"

# ==================== SMTP ====================

def smtp_connect(mx, port, use_starttls=False):
    try:
        server = smtplib.SMTP(timeout=SMTP_TIMEOUT)
        server.connect(mx, port)
        if use_starttls:
            server.ehlo(SMTP_HELO)
            server.starttls()
            server.ehlo(SMTP_HELO)
        else:
            server.helo(SMTP_HELO)
        return server
    except Exception:
        return None

def smtp_probe(mx, email):
    for port, tls in [(25, False), (587, True)]:
        server = smtp_connect(mx, port, tls)
        if server is None:
            continue
        try:
            server.mail(SMTP_FROM)
            code, _ = server.rcpt(email)
            server.quit()
            return code
        except Exception:
            pass
    return None

# ==================== MAIN CHECK ====================

def check_email(email):
    """Returns (status, reason, typo_suggestion)"""

    if not EMAIL_REGEX.match(email):
        return "invalid", "bad_syntax", None

    domain = email.split('@')[1].lower()
    local  = email.split('@')[0].lower()
    typo   = TYPO_MAP.get(domain)

    if domain in DISPOSABLE_DOMAINS:
        return "invalid", "disposable_domain", typo

    if local in ROLE_BASED_PREFIXES:
        return "invalid", "role_based", typo

    # MX lookup
    try:
        records = dns.resolver.resolve(domain, 'MX')
        mx = str(sorted(records, key=lambda r: r.preference)[0].exchange).rstrip('.')
    except Exception:
        return "invalid", "no_mx", typo

    # Catch-all detection
    try:
        s = smtp_connect(mx, 25, False)
        if s:
            s.mail(SMTP_FROM)
            rand = f"xkj29fz7nqrand9182@{domain}"
            code, _ = s.rcpt(rand)
            s.quit()
            if code == 250:
                zb_s, zb_r = zerobounce_check(email)
                if zb_s:
                    return zb_s, f"catchall+{zb_r}", typo
                return "risky", "domain_accepts_all", typo
    except Exception:
        pass

    # SMTP verify
    time.sleep(SMTP_DELAY)
    code = smtp_probe(mx, email)

    if code in [421, 450, 451, 452, 503]:
        time.sleep(5)
        code = smtp_probe(mx, email)

    if code == 250:
        return "valid", "smtp_ok", typo
    elif code == 550:
        return "invalid", "smtp_reject", typo
    else:
        # SMTP uncertain — escalate to ZeroBounce
        zb_s, zb_r = zerobounce_check(email)
        if zb_s:
            return zb_s, zb_r, typo
        # ZeroBounce failed — try Kickbox
        kb_s, kb_r = kickbox_check(email)
        if kb_s:
            return kb_s, kb_r, typo
        return "risky", "smtp_timeout_api_fail", typo

# ==================== ROUTES ====================

@app.route('/verify', methods=['POST'])
def verify():
    job_id = str(uuid.uuid4())
    file   = request.files['file']
    content = file.read().decode('utf-8')
    reader  = list(csv.DictReader(io.StringIO(content)))
    total   = len(reader)
    email_field = next((f for f in reader[0].keys() if f.lower().strip() == 'email'), None)

    output    = io.StringIO()
    fieldnames = list(reader[0].keys()) + ['status', 'reason', 'typo_suggestion']
    writer    = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    results_store[job_id] = {
        "output": output, "writer": writer,
        "records": reader, "email_field": email_field,
        "filename": file.filename,
    }

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO jobs (job_id, filename, total, created_at) VALUES (?,?,?,?)",
        (job_id, file.filename, total, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

    def run():
        store  = results_store[job_id]
        cnt    = {"valid": 0, "risky": 0, "invalid": 0}
        for i, row in enumerate(store['records'], start=1):
            if get_job(job_id).get('canceled'):
                update_job(job_id, log=f"❌ Canceled at row {i}")
                break

            email = (row.get(store['email_field']) or '').strip()
            if not email:
                status, reason, typo = 'invalid', 'empty_email', None
            else:
                status, reason, typo = check_email(email)

            row['status']          = status
            row['reason']          = reason
            row['typo_suggestion'] = typo or ''
            store['writer'].writerow(row)
            cnt[status] = cnt.get(status, 0) + 1

            icon = "✅" if status == "valid" else "⚠️" if status == "risky" else "❌"
            update_job(job_id,
                progress=int((i / total) * 100),
                row_num=i,
                log=f"{icon} {email} → {status} ({reason})" + (f" → try: {typo}" if typo else ""),
                cnt_valid=cnt['valid'],
                cnt_risky=cnt['risky'],
                cnt_invalid=cnt['invalid'],
            )

        store['output'].seek(0)
        tmp = NamedTemporaryFile(delete=False, suffix=".csv", mode='w+')
        tmp.write(store['output'].read())
        tmp.flush()
        update_job(job_id, done=1)

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"job_id": job_id})


@app.route('/progress')
def progress():
    job = get_job(request.args.get("job_id"))
    if not job:
        return jsonify({"percent": 0, "row": 0, "total": 0, "valid": 0, "risky": 0, "invalid": 0})
    return jsonify({
        "percent": job['progress'], "row": job['row_num'], "total": job['total'],
        "valid": job['cnt_valid'], "risky": job['cnt_risky'], "invalid": job['cnt_invalid'],
    })


@app.route('/log')
def log():
    job = get_job(request.args.get("job_id"))
    return Response(job['log'] if job else "", mimetype='text/plain')


@app.route('/cancel', methods=['POST'])
def cancel():
    update_job(request.args.get("job_id"), canceled=1)
    return '', 204


@app.route('/jobs')
def list_jobs():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("""
        SELECT job_id, filename, total, progress, done, created_at,
               cnt_valid, cnt_risky, cnt_invalid
        FROM jobs ORDER BY created_at DESC LIMIT 30
    """)
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify(rows)


@app.route('/download')
def download():
    job_id      = request.args.get("job_id")
    filter_type = request.args.get("type", "all")
    store       = results_store.get(job_id)
    if not store:
        return "Job not in memory. Restart server and re-verify.", 404

    store['output'].seek(0)
    reader = list(csv.DictReader(store['output']))

    if filter_type == "valid":
        filtered = [r for r in reader if r['status'] == 'valid']
    elif filter_type == "risky":
        filtered = [r for r in reader if r['status'] == 'risky']
    elif filter_type == "risky_invalid":
        filtered = [r for r in reader if r['status'] in ('risky', 'invalid')]
    else:
        filtered = reader

    out = io.StringIO()
    if filtered:
        w = csv.DictWriter(out, fieldnames=list(filtered[0].keys()))
        w.writeheader()
        w.writerows(filtered)

    out.seek(0)
    return Response(
        out.getvalue(),
        mimetype='text/csv',
        headers={"Content-Disposition": f"attachment; filename={filter_type}-verified-{store['filename']}"}
    )


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5050))
    app.run(host='0.0.0.0', port=port)
