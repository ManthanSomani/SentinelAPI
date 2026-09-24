import asyncio
import json
import re
import time
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request, APIRouter
from fastapi.responses import HTMLResponse, JSONResponse
import httpx
from pydantic import BaseModel

PORT = 8080

# =====================================================================
# 1. MOCK TARGET API (Intentionally Vulnerable Sandboxed Target for Demo)
# =====================================================================
# Fix: Using APIRouter instead of a separate FastAPI instance prevents 404 routing conflicts
mock_target = APIRouter()

MOCK_DATABASE = {
    "101": {
        "id": "101",
        "owner": "alice",
        "email": "alice@corp.com",
        "ssn_last4": "9876",
        "internal_db_hash": "$2b$12$eImiTXuWVxfM37uY4JANjO",
        "balance": 50000.00,
        "is_admin": False,
    },
    "102": {
        "id": "102",
        "owner": "bob",
        "email": "bob@corp.com",
        "ssn_last4": "1234",
        "internal_db_hash": "$2b$12$K892uWVxfM37uY4JANjO33",
        "balance": 150.00,
        "is_admin": False,
    },
}

MOCK_TOKENS = {"token-alice-123": "101", "token-bob-456": "102"}


@mock_target.get(
    "/target/api/v1/users/{user_id}",
    summary="User Profile (VULNERABLE TO BOLA & EXCESSIVE DATA EXPOSURE)",
)
async def get_user_profile(user_id: str, request: Request):
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "") if "Bearer " in auth_header else None

    if not token or token not in MOCK_TOKENS:
        return JSONResponse(
            status_code=401, content={"error": "Unauthorized access"}
        )

    if user_id in MOCK_DATABASE:
        return MOCK_DATABASE[user_id]
    return JSONResponse(status_code=404, content={"error": "User not found"})


@mock_target.get(
    "/target/api/v1/secure-documents/{doc_id}",
    summary="Secure Documents (SECURE ENDPOINT)",
)
async def get_document(doc_id: str, request: Request):
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "") if "Bearer " in auth_header else None

    if not token or token not in MOCK_TOKENS:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})

    current_user_id = MOCK_TOKENS[token]
    if doc_id != current_user_id:
        return JSONResponse(
            status_code=403,
            content={"error": "Forbidden: You do not own this document"},
        )

    return {"doc_id": doc_id, "content": f"Confidential report for user {current_user_id}"}


@mock_target.get(
    "/target/api/v1/system/config",
    summary="System Config (UNAUTHENTICATED & EXCESSIVE EXPOSURE)",
)
async def get_system_config():
    return {
        "status": "healthy",
        "database_uri": "postgres://admin:P@ssw0rd2026@db.internal:5432/prod_db",
        "aws_secret_access_key": "AKIAIOSFODNN7EXAMPLE",
        "debug_mode": True,
        "internal_services": ["auth-service:8080", "billing-service:8081"],
    }


@mock_target.get("/target/api/v1/ping", summary="Ping (NO RATE LIMITING)")
async def ping_endpoint():
    return {"message": "pong", "timestamp": time.time()}


# =====================================================================
# 2. SENTINEL API SCANNER ENGINE
# =====================================================================
class ScanRequest(BaseModel):
    spec_url: Optional[str] = f"http://127.0.0.1:{PORT}/target/openapi.json"
    spec_json: Optional[Dict[str, Any]] = None
    token_a: str = "token-alice-123"
    object_id_a: str = "101"
    token_b: str = "token-bob-456"
    object_id_b: str = "102"
    base_url_override: Optional[str] = f"http://127.0.0.1:{PORT}"


class SentinelScanner:
    SENSITIVE_FIELD_PATTERNS = [
        r"password",
        r"hash",
        r"secret",
        r"ssn",
        r"token",
        r"database_uri",
        r"aws_",
        r"private_key",
        r"credit_card",
    ]

    def __init__(self, request_data: ScanRequest):
        self.config = request_data
        self.findings: List[Dict[str, Any]] = []

    async def run_scan(self) -> List[Dict[str, Any]]:
        spec = await self._fetch_spec()
        base_url = self.config.base_url_override or self._extract_base_url(spec)
        paths = spec.get("paths", {})

        async with httpx.AsyncClient(timeout=10.0) as client:
            for path_pattern, path_item in paths.items():
                for method, operation in path_item.items():
                    if method.lower() not in ["get", "post", "put", "delete"]:
                        continue

                    full_url_pattern = f"{base_url.rstrip('/')}{path_pattern}"
                    
                    if "{" in path_pattern and "}" in path_pattern:
                        await self._test_bola(client, full_url_pattern, method.upper())

                    await self._test_exposure_and_auth(client, full_url_pattern, method.upper())
                    await self._test_rate_limiting(client, full_url_pattern, method.upper())

        return self.findings

    async def _fetch_spec(self) -> Dict[str, Any]:
        if self.config.spec_json:
            return self.config.spec_json
        async with httpx.AsyncClient(timeout=5.0) as client:
            res = await client.get(self.config.spec_url)
            if res.status_code != 200:
                raise HTTPException(
                    status_code=400, detail="Unable to fetch OpenAPI specification."
                )
            return res.json()

    def _extract_base_url(self, spec: Dict[str, Any]) -> str:
        servers = spec.get("servers", [])
        if servers:
            return servers[0].get("url", f"http://127.0.0.1:{PORT}")
        return f"http://127.0.0.1:{PORT}"

    def _substitute_path(self, url_pattern: str, val: str) -> str:
        return re.sub(r"\{[^}]+\}", val, url_pattern)

    async def _test_bola(self, client: httpx.AsyncClient, url_pattern: str, method: str):
        url_a = self._substitute_path(url_pattern, self.config.object_id_a)
        
        headers_a = {"Authorization": f"Bearer {self.config.token_a}"}
        headers_b = {"Authorization": f"Bearer {self.config.token_b}"}

        res_a = await client.request(method, url_a, headers=headers_a)
        if res_a.status_code != 200:
            return

        res_b = await client.request(method, url_a, headers=headers_b)

        if res_b.status_code == 200:
            poc_curl = f"curl -X {method} '{url_a}' -H 'Authorization: Bearer {self.config.token_b}'"
            self.findings.append(
                {
                    "title": "Broken Object Level Authorization (BOLA / IDOR)",
                    "severity": "CRITICAL",
                    "cwe": "CWE-639",
                    "endpoint": url_a,
                    "method": method,
                    "description": (
                        f"User B (Token: `{self.config.token_b[:8]}...`) successfully accessed "
                        f"User A's object (`{self.config.object_id_a}`). The server failed to validate object authorization."
                    ),
                    "reproduction_poc": poc_curl,
                    "remediation": "Implement object-level ownership verification middleware before returning resource data.",
                }
            )

    async def _test_exposure_and_auth(
        self, client: httpx.AsyncClient, url_pattern: str, method: str
    ):
        test_url = self._substitute_path(url_pattern, self.config.object_id_a)
        res_unauth = await client.request(method, test_url)

        if res_unauth.status_code == 200:
            try:
                data = res_unauth.json()
                exposed_sensitive_keys = self._scan_sensitive_keys(data)

                if exposed_sensitive_keys:
                    poc_curl = f"curl -X {method} '{test_url}'"
                    self.findings.append(
                        {
                            "title": "Excessive Sensitive Data Exposure",
                            "severity": "HIGH",
                            "cwe": "CWE-200",
                            "endpoint": test_url,
                            "method": method,
                            "description": (
                                f"Endpoint returned unauthenticated response containing sensitive fields: "
                                f"`{', '.join(exposed_sensitive_keys)}`."
                            ),
                            "reproduction_poc": poc_curl,
                            "remediation": "Filter outbound response DTOs/schemas to strip internal database hashes, credentials, and sensitive PII.",
                        }
                    )
            except Exception:
                pass

    async def _test_rate_limiting(
        self, client: httpx.AsyncClient, url_pattern: str, method: str
    ):
        test_url = self._substitute_path(url_pattern, self.config.object_id_a)
        
        tasks = [client.request(method, test_url) for _ in range(15)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        status_codes = [r.status_code for r in responses if isinstance(r, httpx.Response)]
        
        if status_codes and 429 not in status_codes:
            poc_curl = f"for i in {{1..15}}; do curl -X {method} '{test_url}'; done"
            self.findings.append(
                {
                    "title": "Missing or Weak Rate Limiting",
                    "severity": "MEDIUM",
                    "cwe": "CWE-770",
                    "endpoint": test_url,
                    "method": method,
                    "description": "Executed 15 rapid concurrent requests without triggering HTTP 429 (Too Many Requests).",
                    "reproduction_poc": poc_curl,
                    "remediation": "Enforce API Gateway or application-level rate limiting using token bucket / leaky bucket algorithms.",
                }
            )

    def _scan_sensitive_keys(self, data: Any) -> List[str]:
        found = []
        if isinstance(data, dict):
            for k, v in data.items():
                for pattern in self.SENSITIVE_FIELD_PATTERNS:
                    if re.search(pattern, k, re.IGNORECASE):
                        found.append(k)
                found.extend(self._scan_sensitive_keys(v))
        elif isinstance(data, list):
            for item in data:
                found.extend(self._scan_sensitive_keys(item))
        return list(set(found))


# =====================================================================
# 3. SCANNER DASHBOARD & API CONTROLLER
# =====================================================================
app = FastAPI(title="SentinelAPI Scanner Platform", version="1.0.0")

# Fix: Include the router cleanly instead of mounting to avoid 404s
app.include_router(mock_target)


@app.post("/api/scanner/run")
async def trigger_scan(scan_req: ScanRequest):
    scanner = SentinelScanner(scan_req)
    findings = await scanner.run_scan()
    return {"status": "completed", "total_findings": len(findings), "findings": findings}


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    # Fix: Removed the 'f' string prefix entirely. We do a standard string replace for the port at the end.
    # This prevents the Python interpreter from getting confused by JavaScript literal brackets ${}.
    html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelAPI | Zero-Trust API Scanner</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Plus+Jakarta+Sans:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Plus Jakarta Sans', sans-serif; }
        code, pre { font-family: 'JetBrains Mono', monospace; }
    </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen">
    <header class="border-b border-slate-800 bg-slate-900/50 backdrop-blur sticky top-0 z-50">
        <div class="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
            <div class="flex items-center space-x-3">
                <div class="h-8 w-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-bold">
                    🛡️
                </div>
                <div>
                    <h1 class="text-lg font-bold tracking-tight text-white">SentinelAPI</h1>
                    <p class="text-xs text-slate-400">Zero-Trust Vulnerability Scanner</p>
                </div>
            </div>
            <div class="flex items-center space-x-2">
                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    Engine Active (Port __PORT__)
                </span>
            </div>
        </div>
    </header>

    <main class="max-w-7xl mx-auto px-6 py-8 grid grid-cols-1 lg:grid-cols-12 gap-8">
        <!-- Configuration Form -->
        <section class="lg:col-span-4 bg-slate-900 border border-slate-800 rounded-xl p-6 h-fit">
            <h2 class="text-md font-semibold text-white mb-4 flex items-center gap-2">
                <span>⚙️</span> Scan Parameters
            </h2>
            <form id="scanForm" class="space-y-4">
                <div>
                    <label class="block text-xs font-medium text-slate-400 mb-1">OpenAPI Spec URL</label>
                    <input type="text" id="specUrl" value="http://127.0.0.1:__PORT__/target/openapi.json" class="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-emerald-500">
                </div>

                <div class="border-t border-slate-800 pt-3">
                    <span class="text-xs font-semibold text-emerald-400 uppercase tracking-wider block mb-2">User A Session (Victim)</span>
                    <div class="space-y-2">
                        <div>
                            <label class="block text-xs text-slate-400">Bearer Token</label>
                            <input type="text" id="tokenA" value="token-alice-123" class="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200">
                        </div>
                        <div>
                            <label class="block text-xs text-slate-400">Sample Object ID</label>
                            <input type="text" id="objA" value="101" class="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200">
                        </div>
                    </div>
                </div>

                <div class="border-t border-slate-800 pt-3">
                    <span class="text-xs font-semibold text-amber-400 uppercase tracking-wider block mb-2">User B Session (Attacker)</span>
                    <div class="space-y-2">
                        <div>
                            <label class="block text-xs text-slate-400">Bearer Token</label>
                            <input type="text" id="tokenB" value="token-bob-456" class="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200">
                        </div>
                        <div>
                            <label class="block text-xs text-slate-400">Sample Object ID</label>
                            <input type="text" id="objB" value="102" class="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200">
                        </div>
                    </div>
                </div>

                <button type="submit" id="btnRun" class="w-full bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold py-2.5 rounded-lg transition duration-200 mt-4 flex items-center justify-center space-x-2">
                    <span>🚀 Launch Zero-Trust Scan</span>
                </button>
            </form>
        </section>

        <!-- Findings & Results -->
        <section class="lg:col-span-8 space-y-6">
            <div id="statsBanner" class="grid grid-cols-3 gap-4 hidden">
                <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
                    <span class="text-xs text-slate-400 block">Total Findings</span>
                    <span id="statTotal" class="text-2xl font-bold text-white">0</span>
                </div>
                <div class="bg-slate-900 border border-rose-500/20 rounded-xl p-4">
                    <span class="text-xs text-rose-400 block">Critical BOLA Flaws</span>
                    <span id="statCritical" class="text-2xl font-bold text-rose-500">0</span>
                </div>
                <div class="bg-slate-900 border border-amber-500/20 rounded-xl p-4">
                    <span class="text-xs text-amber-400 block">Data Exposure Risks</span>
                    <span id="statHigh" class="text-2xl font-bold text-amber-500">0</span>
                </div>
            </div>

            <div id="resultsContainer" class="space-y-4">
                <div class="bg-slate-900/50 border border-slate-800 border-dashed rounded-xl p-12 text-center text-slate-500">
                    <p class="text-sm">Click "Launch Zero-Trust Scan" to initiate target analysis.</p>
                </div>
            </div>
        </section>
    </main>

    <script>
        document.getElementById('scanForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('btnRun');
            const container = document.getElementById('resultsContainer');
            
            btn.disabled = true;
            btn.innerHTML = `<span>⏳ Scanning Surface Area...</span>`;
            container.innerHTML = `<div class="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-400 animate-pulse">Running authorization and parameter manipulation tests...</div>`;

            try {
                const res = await fetch('/api/scanner/run', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        spec_url: document.getElementById('specUrl').value,
                        token_a: document.getElementById('tokenA').value,
                        object_id_a: document.getElementById('objA').value,
                        token_b: document.getElementById('tokenB').value,
                        object_id_b: document.getElementById('objB').value,
                        base_url_override: "http://127.0.0.1:__PORT__"
                    })
                });

                const data = await res.json();
                btn.disabled = false;
                btn.innerHTML = `<span>🚀 Launch Zero-Trust Scan</span>`;

                document.getElementById('statsBanner').classList.remove('hidden');
                document.getElementById('statTotal').innerText = data.total_findings;
                document.getElementById('statCritical').innerText = data.findings.filter(f => f.severity === 'CRITICAL').length;
                document.getElementById('statHigh').innerText = data.findings.filter(f => f.severity === 'HIGH').length;

                if (data.findings.length === 0) {
                    container.innerHTML = `<div class="bg-emerald-950/30 border border-emerald-500/30 rounded-xl p-6 text-emerald-400 text-sm">No vulnerability findings detected. API endpoints passed zero-trust checks.</div>`;
                    return;
                }

                container.innerHTML = data.findings.map(f => {
                    const badgeColor = f.severity === 'CRITICAL' ? 'bg-rose-500/10 text-rose-400 border-rose-500/30' :
                                       f.severity === 'HIGH' ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' :
                                       'bg-blue-500/10 text-blue-400 border-blue-500/30';
                    return `
                        <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-2">
                                    <span class="px-2 py-0.5 rounded text-xs font-bold border ${badgeColor}">${f.severity}</span>
                                    <span class="text-xs font-mono text-slate-400">${f.cwe}</span>
                                    <h3 class="text-sm font-bold text-white">${f.title}</h3>
                                </div>
                                <span class="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">${f.method} ${f.endpoint}</span>
                            </div>
                            <p class="text-xs text-slate-300 leading-relaxed">${f.description}</p>
                            
                            <div>
                                <span class="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block mb-1">Reproducible PoC Request</span>
                                <pre class="bg-slate-950 border border-slate-800/80 rounded border-l-2 border-l-emerald-500 p-2.5 text-xs text-emerald-400 overflow-x-auto">${f.reproduction_poc}</pre>
                            </div>

                            <div class="pt-1">
                                <span class="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block mb-0.5">Remediation Guidance</span>
                                <p class="text-xs text-slate-400">${f.remediation}</p>
                            </div>
                        </div>
                    `;
                }).join('');

            } catch (err) {
                btn.disabled = false;
                btn.innerHTML = `<span>🚀 Launch Zero-Trust Scan</span>`;
                container.innerHTML = `<div class="bg-rose-950/30 border border-rose-500/30 rounded-xl p-6 text-rose-400 text-sm">Scan failed: ${err.message}</div>`;
            }
        });
    </script>
</body>
</html>
    """
    return html_content.replace("__PORT__", str(PORT))


if __name__ == "__main__":
    import uvicorn
    print("=========================================================")
    print("🚀 SentinelAPI Engine Started!")
    print(f"🌐 Dashboard UI:      http://127.0.0.1:{PORT}")
    print(f"🎯 Target API Spec:   http://127.0.0.1:{PORT}/target/openapi.json")
    print("=========================================================")
    uvicorn.run("main:app", host="127.0.0.1", port=PORT, reload=True)