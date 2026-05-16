# verify-app.py — Email Verifier v3
# 5-layer verify | Parallel 5x | Disposable auto-update | Sheets write-back | Column mapper | Re-verify

import csv, io, os, re, time, uuid, json, sqlite3, threading, base64
import requests, smtplib, dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)
print("🔥 VERIFIER v3 — 5-layer | Parallel | Auto-disposable | Sheets write-back 🔥")

# ── KEYS ─────────────────────────────────────────────────────────────────────
ZEROBOUNCE_KEY  = os.environ.get("ZEROBOUNCE_KEY",  "")
KICKBOX_KEY     = os.environ.get("KICKBOX_KEY",     "")
NEVERBOUNCE_KEY = os.environ.get("NEVERBOUNCE_KEY", "private_fc4ee1a232b1525ccc987930852e8eab")
ABSTRACT_KEY    = os.environ.get("ABSTRACT_KEY",    "1d2232d41b2f43859429c11581f354b2")
APP_PASSWORD    = os.environ.get("APP_PASSWORD",    "")   # optional lock
GOOGLE_SA_KEY   = os.environ.get("GOOGLE_SA_KEY",  "")   # base64 SA JSON

SMTP_HELO    = "mail.verifycheck.io"
SMTP_FROM    = "verify@verifycheck.io"
SMTP_TIMEOUT = 10
MAX_WORKERS  = 5

# ── SESSIONS (password protect) ───────────────────────────────────────────────
import secrets
SESSIONS = set()

# ── DISPOSABLE AUTO-UPDATE ────────────────────────────────────────────────────
DISPOSABLE_BUILTIN = {
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
    "spamgap.com","spamhole.com","spamify.com","spamoff.de",
    "trashmail.de","trashmail.org","mailscrap.com","spamthis.co.uk",
    "gnail.com","gail.com","yahooo.com","hotmial.com","outlok.com",
}

DISPOSABLE     = set(DISPOSABLE_BUILTIN)
_disp_lock     = threading.Lock()
DISP_LIST_URL  = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"
_disp_count    = [len(DISPOSABLE_BUILTIN)]

def _refresh_disposable():
    global DISPOSABLE
    try:
        r = requests.get(DISP_LIST_URL, timeout=20)
        if r.status_code == 200:
            lines = {l.strip() for l in r.text.splitlines() if l.strip() and not l.startswith('#')}
            with _disp_lock:
                DISPOSABLE = lines | DISPOSABLE_BUILTIN
                _disp_count[0] = len(DISPOSABLE)
            print(f"✅ Disposable list: {_disp_count[0]:,} domains")
    except Exception as e:
        print(f"⚠️ Disposable refresh failed: {e}")

def _disposable_loop():
    _refresh_disposable()
    while True:
        time.sleep(86400)
        _refresh_disposable()

threading.Thread(target=_disposable_loop, daemon=True).start()

# ── ROLE + TYPO ───────────────────────────────────────────────────────────────
ROLE_PREFIXES = {
    "info","support","admin","sales","contact","noreply","no-reply",
    "newsletter","marketing","hello","team","help","office","enquiries",
    "enquiry","webmaster","postmaster","abuse","spam","security","privacy",
    "legal","billing","accounts","accounting","hr","recruitment","careers",
    "jobs","press","media","pr","events","feedback","complaints","unsubscribe",
    "reply","bounce","mailer","daemon","root","hostmaster","news","ftp","www",
    "service","services","donotreply","do-not-reply","mail","email",
    "notifications","alerts","updates","reports","operations","ops","devops",
    "sysadmin","it","tech","helpdesk","reception","orders","invoice","invoices",
    "payments","payment","finance","payroll","purchasing","procurement","general",
}

TYPO_MAP = {
    "gmial.com":"gmail.com","gmaill.com":"gmail.com","gmail.co":"gmail.com",
    "gamil.com":"gmail.com","gmai.com":"gmail.com","gmali.com":"gmail.com",
    "gmal.com":"gmail.com","gmail.con":"gmail.com","gmail.cpm":"gmail.com",
    "gnail.com":"gmail.com","gail.com":"gmail.com",
    "yaho.com":"yahoo.com","yahoo.co":"yahoo.com","yahooo.com":"yahoo.com",
    "hotmial.com":"hotmail.com","hotmali.com":"hotmail.com","hotail.com":"hotmail.com",
    "hotmal.com":"hotmail.com","hotmil.com":"hotmail.com",
    "outlok.com":"outlook.com","outloook.com":"outlook.com",
    "outlookk.com":"outlook.com","outook.com":"outlook.com",
    "aol.co":"aol.com","iclod.com":"icloud.com","icluod.com":"icloud.com",
    "protonmial.com":"protonmail.com","protonmal.com":"protonmail.com",
}

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
RBL_LIST    = ["zen.spamhaus.org","bl.spamcop.net"]

# ── DOMAIN CACHE (thread-safe, dedup) ────────────────────────────────────────
_dcache   = {}
_dpending = {}
_dlock    = threading.Lock()

def domain_info(domain):
    with _dlock:
        if domain in _dcache:   return _dcache[domain]
        if domain in _dpending:
            ev = _dpending[domain]; wait = True
        else:
            ev = threading.Event()
            _dpending[domain] = ev; wait = False

    if wait:
        ev.wait(timeout=30)
        with _dlock: return _dcache.get(domain, {"mx":None,"catch_all":False,"blacklisted":False})

    info = {"mx":None,"catch_all":False,"blacklisted":False}
    try:
        recs = dns.resolver.resolve(domain,'MX')
        mx   = str(sorted(recs,key=lambda r:r.preference)[0].exchange).rstrip('.')
        info["mx"] = mx
        # Catch-all
        try:
            s = _smtp_connect(mx,25)
            if s:
                s.mail(SMTP_FROM)
                code,_ = s.rcpt(f"zzrndtest8812@{domain}")
                s.quit(); info["catch_all"] = (code==250)
        except: pass
        # RBL
        try:
            ip  = str(dns.resolver.resolve(mx,'A')[0])
            rev = '.'.join(reversed(ip.split('.')))
            for rbl in RBL_LIST:
                try: dns.resolver.resolve(f"{rev}.{rbl}",'A'); info["blacklisted"]=True; break
                except: pass
        except: pass
    except: pass

    with _dlock:
        _dcache[domain] = info
        _dpending.pop(domain,None)
    ev.set()
    return info

# ── SQLITE ────────────────────────────────────────────────────────────────────
DB_PATH       = "verifier_jobs.db"
results_store = {}

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS jobs (
            job_id           TEXT PRIMARY KEY,
            filename         TEXT,
            total            INTEGER,
            progress         INTEGER DEFAULT 0,
            row_num          INTEGER DEFAULT 0,
            log              TEXT DEFAULT '',
            canceled         INTEGER DEFAULT 0,
            done             INTEGER DEFAULT 0,
            created_at       TEXT,
            cnt_valid        INTEGER DEFAULT 0,
            cnt_risky        INTEGER DEFAULT 0,
            cnt_invalid      INTEGER DEFAULT 0,
            layer_smtp       INTEGER DEFAULT 0,
            layer_zb         INTEGER DEFAULT 0,
            layer_kb         INTEGER DEFAULT 0,
            layer_nb         INTEGER DEFAULT 0,
            layer_ab         INTEGER DEFAULT 0,
            health_grade     TEXT DEFAULT '',
            health_score     REAL DEFAULT 0,
            predicted_bounce REAL DEFAULT 0,
            trap_high        INTEGER DEFAULT 0,
            trap_medium      INTEGER DEFAULT 0,
            trap_low         INTEGER DEFAULT 0,
            domain_stats     TEXT DEFAULT '{}',
            speed            REAL DEFAULT 0.5,
            dupes_removed    INTEGER DEFAULT 0,
            email_field      TEXT DEFAULT 'Email'
        )
    """)
    conn.commit(); conn.close()

init_db()

def get_job(job_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM jobs WHERE job_id=?",(job_id,))
    row = c.fetchone(); conn.close()
    return dict(row) if row else None

def update_job(job_id,**kw):
    if not kw: return
    cols = ", ".join(f"{k}=?" for k in kw)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(f"UPDATE jobs SET {cols} WHERE job_id=?",list(kw.values())+[job_id])
    conn.commit(); conn.close()

# ── AUTH ──────────────────────────────────────────────────────────────────────
def check_auth():
    if not APP_PASSWORD: return True
    tok = request.headers.get('X-Token') or request.args.get('token')
    return tok in SESSIONS

@app.route('/auth',methods=['POST'])
def auth():
    pwd = (request.json or {}).get('password','')
    if pwd == APP_PASSWORD:
        tok = secrets.token_hex(32); SESSIONS.add(tok)
        return jsonify({"token":tok})
    return jsonify({"error":"Wrong password"}), 401

@app.route('/auth-status')
def auth_status():
    return jsonify({"protected": bool(APP_PASSWORD), "ok": check_auth()})

# ── 5-LAYER CHECKS ────────────────────────────────────────────────────────────
def zerobounce_check(email):
    if not ZEROBOUNCE_KEY: return None,"zb_no_key"
    try:
        d = requests.get(f"https://api.zerobounce.net/v2/validate?api_key={ZEROBOUNCE_KEY}&email={email}&ip_address=",timeout=12).json()
        s = d.get("status","").lower(); sb = d.get("sub_status","") or ""
        if s=="valid":       return "valid",  "zb_valid"
        if s=="invalid":     return "invalid",f"zb_{sb or 'invalid'}"
        if s=="catch-all":   return "risky",  "zb_catch_all"
        if s=="spamtrap":    return "invalid","zb_spamtrap"
        if s=="abuse":       return "risky",  "zb_abuse"
        if s=="do_not_mail": return "invalid","zb_do_not_mail"
        return "risky",f"zb_{s or 'unknown'}"
    except: return None,"zb_error"

def kickbox_check(email):
    if not KICKBOX_KEY: return None,"kb_no_key"
    try:
        d = requests.get(f"https://api.kickbox.com/v2/verify?email={email}&apikey={KICKBOX_KEY}&timeout=6000",timeout=14).json()
        rs = d.get("result",""); rn = d.get("reason","") or ""
        if rs=="deliverable":   return "valid",  "kb_deliverable"
        if rs=="undeliverable": return "invalid",f"kb_{rn}"
        if rs=="risky":         return "risky",  f"kb_{rn}"
        return None,"kb_unknown"
    except: return None,"kb_error"

def neverbounce_check(email):
    if not NEVERBOUNCE_KEY: return None,"nb_no_key"
    try:
        d = requests.get(f"https://api.neverbounce.com/v4/single/check?key={NEVERBOUNCE_KEY}&email={email}",timeout=12).json()
        rs = d.get("result","")
        if rs=="valid":       return "valid",  "nb_valid"
        if rs=="invalid":     return "invalid","nb_invalid"
        if rs=="disposable":  return "invalid","nb_disposable"
        if rs=="catchall":    return "risky",  "nb_catchall"
        return "risky",f"nb_{rs or 'unknown'}"
    except: return None,"nb_error"

def abstract_check(email):
    if not ABSTRACT_KEY: return None,"ab_no_key"
    try:
        d = requests.get(f"https://emailvalidation.abstractapi.com/v1/?api_key={ABSTRACT_KEY}&email={email}",timeout=12).json()
        dv = d.get("deliverability","").upper()
        if dv=="DELIVERABLE":   return "valid",  "ab_deliverable"
        if dv=="UNDELIVERABLE": return "invalid","ab_undeliverable"
        if dv=="RISKY":         return "risky",  "ab_risky"
        return None,"ab_unknown"
    except: return None,"ab_error"

# ── SMTP ──────────────────────────────────────────────────────────────────────
def _smtp_connect(mx,port,tls=False):
    try:
        s = smtplib.SMTP(timeout=SMTP_TIMEOUT)
        s.connect(mx,port)
        if tls: s.ehlo(SMTP_HELO); s.starttls(); s.ehlo(SMTP_HELO)
        else:   s.helo(SMTP_HELO)
        return s
    except: return None

def smtp_probe(mx,email):
    for port,tls in [(25,False),(587,True)]:
        s = _smtp_connect(mx,port,tls)
        if not s: continue
        try:
            s.mail(SMTP_FROM); code,_ = s.rcpt(email); s.quit(); return code
        except: pass
    return None

# ── HELPERS ───────────────────────────────────────────────────────────────────
def trap_risk(email,status,reason):
    domain = email.split('@')[1].lower(); local = email.split('@')[0].lower()
    score  = 0
    if domain in TYPO_MAP:            score+=3
    if local  in ROLE_PREFIXES:       score+=2
    if "spamtrap"    in reason:       score+=5
    if "do_not_mail" in reason:       score+=3
    if "disposable"  in reason:       score+=3
    if re.match(r'^[a-z]{1,3}\d{4,}@',email): score+=2
    if status=="invalid" and "reject" in reason: score+=1
    return "high" if score>=4 else "medium" if score>=2 else "low"

def health_grade(results):
    n = len(results)
    if not n: return "N/A",0
    valid = sum(1 for r in results if r.get("status")=="valid")
    risky = sum(1 for r in results if r.get("status")=="risky")
    traps = sum(1 for r in results if r.get("trap")=="high")
    score = (valid/n*100)-(traps/n*20)-(risky/n*10)
    score = max(0,min(100,score))
    grade = "A" if score>=90 else "B" if score>=75 else "C" if score>=60 else "D" if score>=45 else "F"
    return grade,round(score,1)

def bounce_est(results):
    n = len(results)
    if not n: return 0
    inv   = sum(1 for r in results if r.get("status")=="invalid")
    risky = sum(1 for r in results if r.get("status")=="risky")
    return round(((inv*0.95)+(risky*0.30))/n*100,1)

def col_letter(n):
    r=''; n+=1
    while n>0: n,rem=divmod(n-1,26); r=chr(65+rem)+r
    return r

def get_google_sa():
    if GOOGLE_SA_KEY:
        try: return json.loads(base64.b64decode(GOOGLE_SA_KEY).decode())
        except: pass
    for path in [
        "Skills/google_key.json","../Skills/google_key.json","google_key.json",
        r"C:\Users\Arion Abhro\Documents\MEGA\Apple_Graphic_Automation\Skills\google_key.json",
    ]:
        if os.path.exists(path):
            with open(path) as f: return json.load(f)
    return None

# ── KNOWN PROVIDERS (skip SMTP — they block it anyway) ───────────────────────
SMTP_SKIP_DOMAINS = {
    "gmail.com","googlemail.com","yahoo.com","yahoo.co.uk","yahoo.co.in",
    "yahoo.fr","yahoo.de","yahoo.es","yahoo.it","yahoo.ca","yahoo.com.br",
    "hotmail.com","hotmail.co.uk","hotmail.fr","hotmail.de","hotmail.es",
    "hotmail.it","hotmail.com.br","outlook.com","outlook.co.uk","outlook.fr",
    "live.com","live.co.uk","live.fr","msn.com","icloud.com","me.com",
    "mac.com","aol.com","protonmail.com","protonmail.ch","pm.me",
    "zoho.com","zohomail.com","mail.com","gmx.com","gmx.net","gmx.de",
    "yandex.com","yandex.ru","rambler.ru","qq.com","163.com","126.com",
}

# ── MAIN CHECK (5 layers) ─────────────────────────────────────────────────────
def check_email(email,delay=0.5):
    res = {"status":"invalid","reason":"","typo":None,"layer":"syntax","trap":"low","blacklisted":False}

    if not EMAIL_REGEX.match(email):
        res["reason"]="bad_syntax"; return res

    domain = email.split('@')[1].lower()
    local  = email.split('@')[0].lower()
    res["typo"] = TYPO_MAP.get(domain)

    with _disp_lock: is_disp = domain in DISPOSABLE
    if is_disp:
        res.update({"reason":"disposable_domain","layer":"filter","trap":"high","status":"invalid"}); return res

    if local in ROLE_PREFIXES:
        res.update({"reason":"role_based","layer":"filter","trap":"high","status":"invalid"}); return res

    # Skip SMTP for known providers — they block port 25/587 from cloud IPs
    if domain in SMTP_SKIP_DOMAINS:
        for fn,lbl in [(zerobounce_check,"zerobounce"),(kickbox_check,"kickbox"),
                       (neverbounce_check,"neverbounce"),(abstract_check,"abstract")]:
            s,r = fn(email)
            if s:
                res.update({"status":s,"reason":r,"layer":lbl,"trap":trap_risk(email,s,r)}); return res
        # APIs exhausted — mark risky (mailbox existence unconfirmed but domain valid)
        res.update({"status":"risky","reason":"provider_no_smtp","layer":"api_fallback","trap":"low"}); return res

    dinfo = domain_info(domain)
    res["blacklisted"] = dinfo["blacklisted"]

    if not dinfo["mx"]:
        res.update({"reason":"no_mx","layer":"dns"}); return res

    mx = dinfo["mx"]

    if dinfo["catch_all"]:
        for fn,lbl in [(zerobounce_check,"zerobounce"),(kickbox_check,"kickbox"),
                       (neverbounce_check,"neverbounce"),(abstract_check,"abstract")]:
            s,r = fn(email)
            if s:
                res.update({"status":s,"reason":f"catchall+{r}","layer":lbl,"trap":trap_risk(email,s,r)}); return res
        res.update({"status":"risky","reason":"domain_accepts_all","layer":"smtp","trap":"medium"}); return res

    time.sleep(delay)
    code = smtp_probe(mx,email)
    if code in [421,450,451,452,503]: time.sleep(5); code=smtp_probe(mx,email)

    if code==250:
        res.update({"status":"valid","reason":"smtp_ok","layer":"smtp","trap":trap_risk(email,"valid","smtp_ok")}); return res
    if code==550:
        res.update({"status":"invalid","reason":"smtp_reject","layer":"smtp","trap":trap_risk(email,"invalid","smtp_reject")}); return res

    # SMTP uncertain → escalate through APIs
    for fn,lbl in [(zerobounce_check,"zerobounce"),(kickbox_check,"kickbox"),
                   (neverbounce_check,"neverbounce"),(abstract_check,"abstract")]:
        s,r = fn(email)
        if s:
            res.update({"status":s,"reason":r,"layer":lbl,"trap":trap_risk(email,s,r)}); return res

    res.update({"status":"risky","reason":"all_5_layers_timeout","layer":"all_fail","trap":"medium"}); return res

# ── ROUTES ────────────────────────────────────────────────────────────────────
@app.route('/ping')
def ping():
    return jsonify({"ok":True,"time":datetime.now().isoformat(),"disp_domains":_disp_count[0]})

@app.route('/wake')
def wake():
    return jsonify({"status":"awake","time":datetime.now().isoformat(),"disp_domains":_disp_count[0]})

@app.route('/credits')
def credits():
    out = {}
    try: out["zerobounce"]=requests.get(f"https://api.zerobounce.net/v2/getcredits?api_key={ZEROBOUNCE_KEY}",timeout=8).json().get("Credits","?")
    except: out["zerobounce"]="?"
    try: out["kickbox"]=requests.get(f"https://api.kickbox.com/v2/balance?apikey={KICKBOX_KEY}",timeout=8).json().get("balance","?")
    except: out["kickbox"]="?"
    try:
        d = requests.get(f"https://api.neverbounce.com/v4/account/info?key={NEVERBOUNCE_KEY}",timeout=8).json()
        out["neverbounce"] = d.get("credits_info",{}).get("free_credits_remaining","?")
    except: out["neverbounce"]="?"
    out["abstract"] = "100/mo"
    out["disp_domains"] = _disp_count[0]
    return jsonify(out)

@app.route('/detect-columns',methods=['POST'])
def detect_columns():
    file    = request.files['file']
    content = file.read().decode('utf-8')
    reader  = csv.DictReader(io.StringIO(content))
    cols    = reader.fieldnames or []
    guess   = next((c for c in cols if 'email' in c.lower()), None)
    if not guess and len(cols)==1: guess=cols[0]
    return jsonify({"columns":cols,"guess":guess,"total":sum(1 for _ in csv.DictReader(io.StringIO(content)))})

@app.route('/sheet-import')
def sheet_import():
    sid = request.args.get("sheet_id",""); gid = request.args.get("gid","0")
    if not sid: return jsonify({"error":"No sheet_id"}),400
    try:
        url = f"https://docs.google.com/spreadsheets/d/{sid}/export?format=csv&gid={gid}"
        r   = requests.get(url,timeout=15,allow_redirects=True)
        if r.status_code==200: return Response(r.content,mimetype="text/csv")
        return jsonify({"error":f"Sheet returned {r.status_code}. Make it publicly viewable."}),400
    except Exception as e: return jsonify({"error":str(e)}),500

@app.route('/verify',methods=['POST'])
def verify():
    if not check_auth(): return jsonify({"error":"Unauthorized"}),401
    job_id  = str(uuid.uuid4())
    file    = request.files['file']
    delay   = float(request.form.get('delay',0.5))
    ef_hint = request.form.get('email_column','')
    content = file.read().decode('utf-8')
    rows    = list(csv.DictReader(io.StringIO(content)))
    if not rows: return jsonify({"error":"Empty CSV"}),400

    email_field = (ef_hint if ef_hint in rows[0] else None) or \
                  next((f for f in rows[0].keys() if 'email' in f.lower()),None) or \
                  list(rows[0].keys())[0]

    seen,unique,dupes = set(),[],0
    for row in rows:
        em = (row.get(email_field) or '').strip().lower()
        if em in seen: dupes+=1
        else: seen.add(em); unique.append(row)
    rows=unique; total=len(rows)

    fieldnames = list(rows[0].keys())+['status','reason','typo_suggestion','layer','spam_trap_risk','blacklisted']
    output=io.StringIO(); writer=csv.DictWriter(output,fieldnames=fieldnames); writer.writeheader()

    results_store[job_id] = {
        "output":output,"writer":writer,"records":rows,
        "email_field":email_field,"filename":file.filename,
        "results":[],"log_buf":[],"dupes":dupes,
    }

    conn=sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO jobs (job_id,filename,total,created_at,speed,dupes_removed,email_field) VALUES (?,?,?,?,?,?,?)",
        (job_id,file.filename,total,datetime.now().isoformat(),delay,dupes,email_field)
    ); conn.commit(); conn.close()

    def run():
        store    = results_store[job_id]
        wlock    = threading.Lock()
        cnt      = {"valid":0,"risky":0,"invalid":0}
        layers   = {"smtp":0,"zerobounce":0,"kickbox":0,"neverbounce":0,"abstract":0,"filter":0,"dns":0,"syntax":0,"all_fail":0}
        traps    = {"high":0,"medium":0,"low":0}
        dstats   = {}
        all_r    = []
        done_n   = [0]

        def process_one(args):
            i,row = args
            email = (row.get(store['email_field']) or '').strip()
            if not email:
                r={"status":"invalid","reason":"empty_email","typo":None,"layer":"filter","trap":"low","blacklisted":False}
            else:
                r=check_email(email,delay)
            return i,row,email,r

        tasks = list(enumerate(store['records']))
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = [ex.submit(process_one,t) for t in tasks]
            for fut in as_completed(futs):
                if (get_job(job_id) or {}).get('canceled'): break
                try: i,row,email,r = fut.result()
                except: continue
                with wlock:
                    row['status']         = r['status']
                    row['reason']         = r['reason']
                    row['typo_suggestion']= r['typo'] or ''
                    row['layer']          = r['layer']
                    row['spam_trap_risk'] = r['trap']
                    row['blacklisted']    = str(r['blacklisted'])
                    store['writer'].writerow(row)
                    cnt[r['status']]   = cnt.get(r['status'],0)+1
                    lk = r['layer'] if r['layer'] in layers else 'smtp'
                    layers[lk]         = layers.get(lk,0)+1
                    traps[r['trap']]  += 1
                    if email:
                        dom = email.split('@')[1].lower()
                        if dom not in dstats: dstats[dom]={"valid":0,"risky":0,"invalid":0}
                        dstats[dom][r['status']]+=1
                    all_r.append({"status":r['status'],"trap":r['trap']})
                    done_n[0]+=1
                    icon="✅" if r['status']=="valid" else "⚠️" if r['status']=="risky" else "❌"
                    entry=f"{icon} {email} → {r['status']} ({r['reason']})"+( f"  →  try: {r['typo']}" if r['typo'] else "")
                    store['log_buf'].append(entry)
                    store['log_buf']=store['log_buf'][-8:]
                    update_job(job_id,
                        progress=int(done_n[0]/total*100),row_num=done_n[0],
                        log="\n".join(store['log_buf']),
                        cnt_valid=cnt['valid'],cnt_risky=cnt['risky'],cnt_invalid=cnt['invalid'],
                        layer_smtp=layers['smtp'],layer_zb=layers['zerobounce'],
                        layer_kb=layers['kickbox'],layer_nb=layers.get('neverbounce',0),
                        layer_ab=layers.get('abstract',0),
                        trap_high=traps['high'],trap_medium=traps['medium'],trap_low=traps['low'],
                        domain_stats=json.dumps(dstats),
                    )

        grade,score = health_grade(all_r)
        bounce      = bounce_est(all_r)
        update_job(job_id,done=1,health_grade=grade,health_score=score,predicted_bounce=bounce)
        store['results']=all_r; store['output'].seek(0)

    threading.Thread(target=run,daemon=True).start()
    return jsonify({"job_id":job_id,"total":total,"dupes_removed":dupes})


@app.route('/progress')
def progress():
    j = get_job(request.args.get("job_id"))
    if not j:
        return jsonify({"percent":0,"row":0,"total":0,"valid":0,"risky":0,"invalid":0,
                        "layer_smtp":0,"layer_zb":0,"layer_kb":0,"layer_nb":0,"layer_ab":0,
                        "trap_high":0,"trap_medium":0,"trap_low":0,
                        "health_grade":"","health_score":0,"predicted_bounce":0,"domain_stats":{},"done":0})
    return jsonify({
        "percent":j['progress'],"row":j['row_num'],"total":j['total'],
        "valid":j['cnt_valid'],"risky":j['cnt_risky'],"invalid":j['cnt_invalid'],
        "layer_smtp":j['layer_smtp'],"layer_zb":j['layer_zb'],"layer_kb":j['layer_kb'],
        "layer_nb":j.get('layer_nb',0),"layer_ab":j.get('layer_ab',0),
        "trap_high":j['trap_high'],"trap_medium":j['trap_medium'],"trap_low":j['trap_low'],
        "health_grade":j['health_grade'],"health_score":j['health_score'],
        "predicted_bounce":j['predicted_bounce'],
        "domain_stats":json.loads(j['domain_stats'] or '{}'),"done":j['done'],
    })


@app.route('/log')
def log():
    j = get_job(request.args.get("job_id"))
    return Response(j['log'] if j else "",mimetype='text/plain')

@app.route('/cancel',methods=['POST'])
def cancel():
    update_job(request.args.get("job_id"),canceled=1); return '',204

@app.route('/emails')
def emails():
    store = results_store.get(request.args.get("job_id"))
    if not store: return jsonify([])
    store['output'].seek(0)
    reader = list(csv.DictReader(store['output']))
    ef     = store['email_field']
    st     = request.args.get("status","valid")
    return jsonify([r.get(ef,'') for r in reader if r.get('status')==st and r.get(ef,'')])

@app.route('/jobs')
def list_jobs():
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row; c=conn.cursor()
    c.execute("""SELECT job_id,filename,total,progress,done,created_at,
                        cnt_valid,cnt_risky,cnt_invalid,health_grade,predicted_bounce
               FROM jobs ORDER BY created_at DESC LIMIT 30""")
    rows=[dict(r) for r in c.fetchall()]; conn.close(); return jsonify(rows)

@app.route('/download')
def download():
    job_id = request.args.get("job_id")
    ftype  = request.args.get("type","all")
    fmt    = request.args.get("fmt","csv")
    store  = results_store.get(job_id)
    if not store: return "Job not in memory. Re-verify.",404
    store['output'].seek(0)
    reader = list(csv.DictReader(store['output']))
    if ftype=="valid":         filtered=[r for r in reader if r['status']=='valid']
    elif ftype=="risky":       filtered=[r for r in reader if r['status']=='risky']
    elif ftype=="risky_invalid":filtered=[r for r in reader if r['status'] in('risky','invalid')]
    else:                      filtered=reader
    fname=store['filename']
    if fmt=="json":
        return Response(json.dumps(filtered,indent=2),mimetype='application/json',
            headers={"Content-Disposition":f"attachment; filename={ftype}-{fname.replace('.csv','')}.json"})
    if fmt=="txt":
        ef=store['email_field']
        return Response('\n'.join(r.get(ef,'') for r in filtered if r.get(ef,'')),mimetype='text/plain',
            headers={"Content-Disposition":f"attachment; filename={ftype}-emails.txt"})
    out=io.StringIO()
    if filtered: w=csv.DictWriter(out,fieldnames=list(filtered[0].keys())); w.writeheader(); w.writerows(filtered)
    out.seek(0)
    return Response(out.getvalue(),mimetype='text/csv',
        headers={"Content-Disposition":f"attachment; filename={ftype}-verified-{fname}"})

@app.route('/sheets-write',methods=['POST'])
def sheets_write():
    data     = request.json or {}
    job_id   = data.get('job_id')
    sheet_id = data.get('sheet_id','')
    tab_name = data.get('tab_name','Sheet1')
    store    = results_store.get(job_id)
    if not store: return jsonify({"error":"Job not in memory"}),404
    sa = get_google_sa()
    if not sa: return jsonify({"error":"Google service account not configured. Set GOOGLE_SA_KEY env var on Render."}),400
    try:
        from google.oauth2.service_account import Credentials
        from googleapiclient.discovery import build
        creds   = Credentials.from_service_account_info(sa,scopes=['https://www.googleapis.com/auth/spreadsheets'])
        svc     = build('sheets','v4',credentials=creds)
        sheets  = svc.spreadsheets()
        # Get existing headers
        res     = sheets.values().get(spreadsheetId=sheet_id,range=f"'{tab_name}'!1:1").execute()
        headers = (res.get('values') or [[]])[0]
        # Find or add Status/Reason columns
        st_idx  = next((i for i,h in enumerate(headers) if 'status' in h.lower()),None)
        rn_idx  = next((i for i,h in enumerate(headers) if 'reason' in h.lower() and 'verify' in h.lower()),None)
        if st_idx is None:
            st_idx=len(headers); rn_idx=st_idx+1
            sheets.values().update(spreadsheetId=sheet_id,range=f"'{tab_name}'!{col_letter(st_idx)}1",
                valueInputOption='RAW',body={'values':[['Verified_Status','Verify_Reason']]}).execute()
        store['output'].seek(0)
        reader  = list(csv.DictReader(store['output']))
        values  = [[r.get('status',''),r.get('reason','')] for r in reader]
        sheets.values().update(spreadsheetId=sheet_id,
            range=f"'{tab_name}'!{col_letter(st_idx)}2",
            valueInputOption='RAW',body={'values':values}).execute()
        return jsonify({"success":True,"rows_written":len(values)})
    except Exception as e:
        return jsonify({"error":str(e)}),500


if __name__=='__main__':
    port=int(os.environ.get("PORT",5050))
    app.run(host='0.0.0.0',port=port)
