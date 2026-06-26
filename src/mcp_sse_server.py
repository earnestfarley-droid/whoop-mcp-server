import os
import json
import httpx
from datetime import datetime, timedelta
from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.responses import JSONResponse
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
    try:
        headers = get_headers()
    except ValueError as e:
        return [TextContent(type='text', text=str(e))]

    try:
        if name == 'get_auth_status':
            return [TextContent(type='text', text='Authenticated with WHOOP.')]

        elif name == 'get_profile':
            r = httpx.get(f'{WHOOP_API_BASE}/user/profile/basic', headers=headers)
            return [TextContent(type='text', text=json.dumps(r.json(), indent=2))]

        elif name == 'get_today_recovery':
            today = datetime.utcnow().strftime('%Y-%m-%dT00:00:00.000Z')
            r = httpx.get(f'{WHOOP_API_BASE}/recovery', params={'start': today, 'limit': 1}, headers=headers)
            return [TextContent(type='text', text=json.dumps(r.json(), indent=2))]

        elif name == 'get_latest_cycle':
            r = httpx.get(f'{WHOOP_API_BASE}/cycle', params={'limit': 1}, headers=headers)
            return [TextContent(type='text', text=json.dumps(r.json(), indent=2))]

        elif name == 'get_recovery_range':
            start = arguments['start_date'] + 'T00:00:00.000Z'
            end = arguments['end_date'] + 'T23:59:59.000Z'
            r = httpx.get(f'{WHOOP_API_BASE}/recovery', params={'start': start, 'end': end, 'limit': 25}, headers=headers)
            return [TextContent(type='text', text=json.dumps(r.json(), indent=2))]

        elif name == 'get_sleep_range':
            start = arguments['start_date'] + 'T00:00:00.000Z'
            end = arguments['end_date'] + 'T23:59:59.000Z'
            r = httpx.get(f'{WHOOP_API_BASE}/activity/sleep', params={'start': start, 'end': end, 'limit': 25}, headers=headers)
            return [TextContent(type='text', text=json.dumps(r.json(), indent=2))]

        elif name == 'get_strain_range':
            start = arguments['start_date'] + 'T00:00:00.000Z'
            end = arguments['end_date'] + 'T23:59:59.000Z'
            r = httpx.get(f'{WHOOP_API_BASE}/cycle', params={'start': start, 'end': end, 'limit': 25}, headers=headers)
            return [TextContent(type='text', text=json.dumps(r.json(), indent=2))]

        else:
            return [TextContent(type='text', text=f'Unknown tool: {name}')]

    except Exception as e:
        return [TextContent(type='text', text=f'Error: {str(e)}')]

sse = SseServerTransport('/messages/')

async def handle_sse(request: Request):
    async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
        await app_server.run(streams[0], streams[1], app_server.create_initialization_options())

async def handle_messages(request: Request):
    await sse.handle_post_message(request.scope, request.receive, request._send)

async def auth_start(request: Request):
    from urllib.parse import urlencode
    params = {'client_id': CLIENT_ID, 'redirect_uri': REDIRECT_URI, 'response_type': 'code', 'scope': SCOPES, 'state': 'whoop-mce'}
    url = AUTH_URL + '?' + urlencode(params)
    from starlette.responses import RedirectResponse
    return RedirectResponse(url)

async def auth_callback(request: Request):
    code = request.query_params.get('code')
    if not code:
        return JSONResponse({'error': 'No code received'}, status_code=400)
    resp = httpx.post(TOKEN_URL, data={'grant_type': 'authorization_code', 'code': code, 'redirect_uri': REDIRECT_URI, 'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET})
    data = resp.json()
    token_store['access_token'] = data.get('access_token')
    token_store['refresh_token'] = data.get('refresh_token')
    return JSONResponse({'status': 'Authenticated with WHOOP successfully! You can now use the MCP connector in Claude.'})

async def health(request: Request):
    return JSONResponse({'status': 'ok', 'service': 'WHOOP MCE MCP Server', 'authenticated': bool(token_store.get('access_token'))})

app = Starlette(routes=[
    Route('/', health),
    Route('/health', health),
    Route('/auth', auth_start),
    Route('/callback', auth_callback),
    Route('/sse', handle_sse),
    Mount('/messages', app=handle_messages),
])

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    uvicorn.run(app, host='0.0.0.0', port=port)
