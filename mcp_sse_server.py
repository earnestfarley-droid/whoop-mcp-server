import os
import json
import httpx
import secrets
from contextlib import asynccontextmanager
from urllib.parse import urlencode
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, HTMLResponse
import uvicorn

load_dotenv()

CLIENT_ID = os.environ.get('WHOOP_CLIENT_ID', '')
CLIENT_SECRET = os.environ.get('WHOOP_CLIENT_SECRET', '')
REDIRECT_URI = os.environ.get('WHOOP_REDIRECT_URI', '')
AUTH_URL = os.environ.get('WHOOP_AUTH_URL', 'https://api.prod.whoop.com/oauth/oauth2/auth')
TOKEN_URL = os.environ.get('WHOOP_TOKEN_URL', 'https://api.prod.whoop.com/oauth/oauth2/token')
SCOPES = os.environ.get('WHOOP_SCOPES', 'offline read:recovery read:sleep read:cycles read:workout read:profile read:body_measurement')
WHOOP_API_BASE = 'https://api.prod.whoop.com/developer/v1'

token_store = {}
pending_auth = {}
code_store = {}

mcp = FastMCP('whoop-mce', stateless_http=True)

def get_headers():
    token = token_store.get('access_token')
    if not token:
        raise ValueError('Not authenticated.')
    return {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

@mcp.tool()
def get_auth_status() -> str:
    """Check WHOOP authentication status"""
    return f'Authenticated: {bool(token_store.get("access_token"))}'

@mcp.tool()
def get_today_recovery() -> str:
    """Get recovery score, HRV, and RHR for today"""
    headers = get_headers()
    resp = httpx.get(f'{WHOOP_API_BASE}/recovery', headers=headers)
    return json.dumps(resp.json(), indent=2)

@mcp.tool()
def get_latest_cycle() -> str:
    """Get the latest WHOOP cycle data"""
    headers = get_headers()
    resp = httpx.get(f'{WHOOP_API_BASE}/cycle', headers=headers, params={'limit': 1})
    return json.dumps(resp.json(), indent=2)

@mcp.tool()
def get_recovery_range(start_date: str, end_date: str) -> str:
    """Get recovery data for a date range (YYYY-MM-DD format)"""
    headers = get_headers()
    params = {'start': start_date + 'T00:00:00.000Z', 'end': end_date + 'T23:59:59.999Z'}
    resp = httpx.get(f'{WHOOP_API_BASE}/recovery', headers=headers, params=params)
    return json.dumps(resp.json(), indent=2)

@mcp.tool()
def get_sleep_range(start_date: str, end_date: str) -> str:
    """Get sleep data for a date range (YYYY-MM-DD format)"""
    headers = get_headers()
    params = {'start': start_date + 'T00:00:00.000Z', 'end': end_date + 'T23:59:59.999Z'}
    resp = httpx.get(f'{WHOOP_API_BASE}/activity/sleep', headers=headers, params=params)
    return json.dumps(resp.json(), indent=2)

@mcp.tool()
def get_profile() -> str:
    """Get WHOOP user profile"""
    headers = get_headers()
    resp = httpx.get(f'{WHOOP_API_BASE}/user/profile/basic', headers=headers)
    return json.dumps(resp.json(), indent=2)

async def health(request: Request):
    return JSONResponse({'status': 'ok', 'service': 'whoop-mce'})

async def oauth_metadata(request: Request):
    base = str(request.base_url).rstrip('/')
    return JSONResponse({
        'issuer': base,
        'authorization_endpoint': f'{base}/authorize',
        'token_endpoint': f'{base}/token',
        'response_types_supported': ['code'],
        'grant_types_supported': ['authorization_code', 'refresh_token'],
        'code_challenge_methods_supported': ['S256'],
    })

async def authorize(request: Request):
    claude_redirect_uri = request.query_params.get('redirect_uri', '')
    code_challenge = request.query_params.get('code_challenge', '')
    code_challenge_method = request.query_params.get('code_challenge_method', 'S256')
    claude_state = request.query_params.get('state', '')
    server_state = secrets.token_urlsafe(32)
    pending_auth[server_state] = {
        'claude_redirect_uri': claude_redirect_uri,
        'claude_state': claude_state,
        'code_challenge': code_challenge,
        'code_challenge_method': code_challenge_method,
    }
    params = {
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'scope': SCOPES,
        'state': server_state,
    }
    return RedirectResponse(url=AUTH_URL + '?' + urlencode(params))

async def whoop_callback(request: Request):
    code = request.query_params.get('code', '')
    server_state = request.query_params.get('state', '')
    error = request.query_params.get('error', '')
    if error:
        return HTMLResponse(f'<h1>Auth Error: {error}</h1>', status_code=400)
    pending = pending_auth.pop(server_state, None)
    if not pending:
        return HTMLResponse('<h1>Invalid or expired state</h1>', status_code=400)
    resp = httpx.post(TOKEN_URL, data={
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
    })
    if resp.status_code != 200:
        return HTMLResponse(f'<h1>Token error: {resp.text}</h1>', status_code=400)
    tokens = resp.json()
    token_store['access_token'] = tokens.get('access_token', '')
    token_store['refresh_token'] = tokens.get('refresh_token', '')
    internal_code = secrets.token_urlsafe(32)
    code_store[internal_code] = tokens
    redirect_params = urlencode({'code': internal_code, 'state': pending['claude_state']})
    return RedirectResponse(url=f"{pending['claude_redirect_uri']}?{redirect_params}")

async def token_endpoint(request: Request):
    form = await request.form()
    grant_type = form.get('grant_type', '')
    if grant_type == 'authorization_code':
        internal_code = form.get('code', '')
        tokens = code_store.pop(internal_code, None)
        if not tokens:
            return JSONResponse({'error': 'invalid_grant'}, status_code=400)
        return JSONResponse({
            'access_token': tokens.get('access_token', ''),
            'token_type': 'bearer',
            'refresh_token': tokens.get('refresh_token', ''),
            'expires_in': tokens.get('expires_in', 3600),
        })
    elif grant_type == 'refresh_token':
        rt = form.get('refresh_token', '')
        resp = httpx.post(TOKEN_URL, data={
            'grant_type': 'refresh_token',
            'refresh_token': rt,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
        })
        if resp.status_code != 200:
            return JSONResponse({'error': 'invalid_grant'}, status_code=400)
        data = resp.json()
        token_store['access_token'] = data.get('access_token', '')
        token_store['refresh_token'] = data.get('refresh_token', rt)
        return JSONResponse({
            'access_token': data.get('access_token', ''),
            'token_type': 'bearer',
            'refresh_token': data.get('refresh_token', rt),
            'expires_in': data.get('expires_in', 3600),
        })
    return JSONResponse({'error': 'unsupported_grant_type'}, status_code=400)

@asynccontextmanager
async def lifespan(app):
    async with mcp.session_manager.run():
        yield

mcp_app = mcp.streamable_http_app()

app = Starlette(
    lifespan=lifespan,
    routes=[
        Route('/health', health),
        Route('/.well-known/oauth-authorization-server', oauth_metadata),
        Route('/.well-known/oauth-protected-resource', oauth_metadata),
        Route('/authorize', authorize),
        Route('/token', token_endpoint, methods=['POST']),
        Route('/callback', whoop_callback),
        Route('/auth', authorize),
        Mount('/', app=mcp_app),
    ]
)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    uvicorn.run(app, host='0.0.0.0', port=port)
