import os
import json
import httpx
import secrets
from datetime import datetime, timedelta
from urllib.parse import urlencode, urlparse, parse_qs
from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent
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

# In-memory stores
token_store = {}
# Maps state -> {redirect_uri, code_challenge, code_challenge_method}
pending_auth = {}
# Maps internal_code -> whoop_tokens
code_store = {}

app_server = Server('whoop-mce')

def get_headers():
    token = token_store.get('access_token')
    if not token:
        raise ValueError('Not authenticated. Visit /auth to connect WHOOP.')
    return {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

def refresh_tokens():
    refresh_token = token_store.get('refresh_token')
    if not refresh_token:
        raise ValueError('No refresh token available.')
    resp = httpx.post(TOKEN_URL, data={
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
    })
    data = resp.json()
    token_store['access_token'] = data['access_token']
    if 'refresh_token' in data:
        token_store['refresh_token'] = data['refresh_token']

@app_server.list_tools()
async def list_tools():
    return [
        Tool(name='get_today_recovery', description='Get recovery score, HRV, and RHR for today', inputSchema={'type': 'object', 'properties': {}}),
        Tool(name='get_latest_cycle', description='Get the latest WHOOP cycle data', inputSchema={'type': 'object', 'properties': {}}),
        Tool(name='get_recovery_range', description='Get recovery data for a date range', inputSchema={'type': 'object', 'properties': {'start_date': {'type': 'string', 'description': 'Start date YYYY-MM-DD'}, 'end_date': {'type': 'string', 'description': 'End date YYYY-MM-DD'}}, 'required': ['start_date', 'end_date']}),
        Tool(name='get_sleep_range', description='Get sleep data for a date range', inputSchema={'type': 'object', 'properties': {'start_date': {'type': 'string'}, 'end_date': {'type': 'string'}}, 'required': ['start_date', 'end_date']}),
        Tool(name='get_strain_range', description='Get strain data for a date range', inputSchema={'type': 'object', 'properties': {'start_date': {'type': 'string'}, 'end_date': {'type': 'string'}}, 'required': ['start_date', 'end_date']}),
        Tool(name='get_profile', description='Get WHOOP user profile', inputSchema={'type': 'object', 'properties': {}}),
        Tool(name='get_auth_status', description='Check WHOOP authentication status', inputSchema={'type': 'object', 'properties': {}}),
    ]

@app_server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == 'get_auth_status':
        has_token = bool(token_store.get('access_token'))
        return [TextContent(type='text', text=f'Authenticated: {has_token}')]
    try:
        headers = get_headers()
    except ValueError as e:
        return [TextContent(type='text', text=str(e))]
    if name == 'get_today_recovery':
        resp = httpx.get(f'{WHOOP_API_BASE}/recovery', headers=headers)
        return [TextContent(type='text', text=json.dumps(resp.json(), indent=2))]
    elif name == 'get_latest_cycle':
        resp = httpx.get(f'{WHOOP_API_BASE}/cycle', headers=headers, params={'limit': 1})
        return [TextContent(type='text', text=json.dumps(resp.json(), indent=2))]
    elif name == 'get_recovery_range':
        params = {'start': arguments['start_date'] + 'T00:00:00.000Z', 'end': arguments['end_date'] + 'T23:59:59.999Z'}
        resp = httpx.get(f'{WHOOP_API_BASE}/recovery', headers=headers, params=params)
        return [TextContent(type='text', text=json.dumps(resp.json(), indent=2))]
    elif name == 'get_sleep_range':
        params = {'start': arguments['start_date'] + 'T00:00:00.000Z', 'end': arguments['end_date'] + 'T23:59:59.999Z'}
        resp = httpx.get(f'{WHOOP_API_BASE}/activity/sleep', headers=headers, params=params)
        return [TextContent(type='text', text=json.dumps(resp.json(), indent=2))]
    elif name == 'get_strain_range':
        params = {'start': arguments['start_date'] + 'T00:00:00.000Z', 'end': arguments['end_date'] + 'T23:59:59.999Z'}
        resp = httpx.get(f'{WHOOP_API_BASE}/cycle', headers=headers, params=params)
        return [TextContent(type='text', text=json.dumps(resp.json(), indent=2))]
    elif name == 'get_profile':
        resp = httpx.get(f'{WHOOP_API_BASE}/user/profile/basic', headers=headers)
        return [TextContent(type='text', text=json.dumps(resp.json(), indent=2))]
    return [TextContent(type='text', text=f'Unknown tool: {name}')]

async def health(request: Request):
    return JSONResponse({'status': 'ok', 'service': 'whoop-mce'})

async def oauth_metadata(request: Request):
    base = str(request.base_url).rstrip('/')
    return JSONResponse({
        'issuer': base,
        'authorization_endpoint': f'{base}/authorize',
        'token_endpoint': f'{base}/token',
        'response_types_supported': ['code'],
        'code_challenge_methods_supported': ['S256'],
        'grant_types_supported': ['authorization_code', 'refresh_token'],
    })

async def authorize(request: Request):
    # Claude sends us a PKCE auth request; we proxy it to WHOOP
    claude_redirect_uri = request.query_params.get('redirect_uri', '')
    code_challenge = request.query_params.get('code_challenge', '')
    code_challenge_method = request.query_params.get('code_challenge_method', 'S256')
    claude_state = request.query_params.get('state', '')
    # Store Claude's params keyed by a server-side state we send to WHOOP
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
    whoop_auth_url = AUTH_URL + '?' + urlencode(params)
    return RedirectResponse(url=whoop_auth_url)

async def whoop_callback(request: Request):
    # WHOOP redirects here with a code
    code = request.query_params.get('code', '')
    server_state = request.query_params.get('state', '')
    error = request.query_params.get('error', '')
    if error:
        return HTMLResponse(f'<h1>Auth Error</h1><p>{error}</p>', status_code=400)
    pending = pending_auth.pop(server_state, None)
    if not pending:
        return HTMLResponse('<h1>Invalid state</h1>', status_code=400)
    # Exchange WHOOP code for tokens
    resp = httpx.post(TOKEN_URL, data={
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
    })
    if resp.status_code != 200:
        return HTMLResponse(f'<h1>Token exchange failed</h1><p>{resp.text}</p>', status_code=400)
    tokens = resp.json()
    token_store['access_token'] = tokens.get('access_token', '')
    token_store['refresh_token'] = tokens.get('refresh_token', '')
    # Generate an internal code to give back to Claude
    internal_code = secrets.token_urlsafe(32)
    code_store[internal_code] = tokens
    # Redirect back to Claude with the internal code
    claude_redirect_uri = pending['claude_redirect_uri']
    claude_state = pending['claude_state']
    redirect_params = urlencode({'code': internal_code, 'state': claude_state})
    return RedirectResponse(url=f'{claude_redirect_uri}?{redirect_params}')

async def token_endpoint(request: Request):
    # Claude calls us to exchange our internal code for a token
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
            'scope': SCOPES,
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
            'scope': SCOPES,
        })
    return JSONResponse({'error': 'unsupported_grant_type'}, status_code=400)

async def handle_sse(request: Request):
    sse = SseServerTransport('/messages/')
    async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
        await app_server.run(streams[0], streams[1], app_server.create_initialization_options())

async def handle_messages(scope, receive, send):
    sse = SseServerTransport('/messages/')
    await sse.handle_post_message(scope, receive, send)

app = Starlette(routes=[
    Route('/', health),
    Route('/health', health),
    Route('/.well-known/oauth-authorization-server', oauth_metadata),
    Route('/authorize', authorize),
    Route('/token', token_endpoint, methods=['POST']),
    Route('/callback', whoop_callback),
    Route('/auth', authorize),
    Route('/sse', handle_sse),
    Mount('/messages', app=handle_messages),
])

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    uvicorn.run(app, host='0.0.0.0', port=port)
