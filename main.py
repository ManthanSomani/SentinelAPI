import asyncio
import json
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, Request, APIRouter, Response
from fastapi.responses import HTMLResponse, JSONResponse
import httpx
from pydantic import BaseModel

PORT = 8080

# =====================================================================
# 1. MOCK TARGET API (Sandboxed Target for Demo)
# =====================================================================
mock_target = APIRouter()

MOCK_DATABASE = {
    "101": {
        "id": "101", "owner": "alice", "email": "alice@corp.com",
        "first_name": "Alice", "last_name": "Smith", "ssn": "000-12-3456",
        "internal_db_hash": "$2b$12$eImiTXuWVxfM37uY4JANjO",
        "aws_debug_key": "AKIAIOSFODNN7EXAMPLE",
        "balance": 50000.00, "status": "active",
        "address_1": "123 Main St", "city": "New York", "state": "NY", "zip": "10001", 
        "country": "USA", "lat": 40.7128, "lng": -74.0060,
        "created_at": "2023-01-15T08:30:00Z", "updated_at": "2023-10-01T12:00:00Z",
        "last_login_ip": "192.168.1.55"
    },
    "102": {
        "id": "102", "owner": "bob", "email": "bob@corp.com",
        "internal_db_hash": "$2b$12$K892uWVxfM37uY4JANjO33", "balance": 150.00,
    },
}

MOCK_TOKENS = {"token-alice-123": "101", "token-bob-456": "102"}

@mock_target.get("/target/api/v1/users/{user_id}")
async def get_user_profile(user_id: str, request: Request):
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "") if "Bearer " in auth_header else None
    if not token or token not in MOCK_TOKENS:
        return JSONResponse(status_code=401, content={"error": "Unauthorized access"})
    if user_id in MOCK_DATABASE:
        return MOCK_DATABASE[user_id]
    return JSONResponse(status_code=404, content={"error": "User not found"})

@mock_target.get("/target/api/v1/secure-documents/{doc_id}")
async def get_document(doc_id: str, request: Request):
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "") if "Bearer " in auth_header else None
    if not token or token not in MOCK_TOKENS:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})
    current_user_id = MOCK_TOKENS[token]
    if doc_id != current_user_id:
        return JSONResponse(status_code=403, content={"error": "Forbidden: Not owner"})
    return {"doc_id": doc_id, "content": f"Confidential report for user {current_user_id}"}

# =====================================================================
# 2. SENTINEL API SCANNER ENGINE (Dual-Mode & Severity Matrix)
# =====================================================================
class ScanRequest(BaseModel):
    scan_mode: str = "openapi"  # 'openapi' or 'website'
    target_url: str
    token_a: str = "token-alice-123"
    object_id_a: str = "101"
    token_b: str = "token-bob-456"
    object_id_b: str = "102"
    base_url_override: Optional[str] = None

class TestCaseResult(BaseModel):
    case_name: str
    status: str  # PASS, FAIL, ERROR
    severity: str = "INFO" # CRITICAL, HIGH, MEDIUM, LOW, INFO
    details: str
    poc: str = ""

class TestSuiteResult(BaseModel):
    suite_name: str
    passed: int = 0
    failed: int = 0
    cases: List[TestCaseResult] = []

class EndpointReport(BaseModel):
    method: str
    path: str
    suites: List[TestSuiteResult] = []
    has_critical_failures: bool = False

class SentinelScanner:
    def __init__(self, request_data: ScanRequest):
        self.config = request_data
        self.reports: List[EndpointReport] = []
        self.fallback_payload = {"id": 101, "name": "sentinel_test", "status": "active"}

    async def run_scan(self) -> List[EndpointReport]:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            spec = {}
            base_url = ""

            if self.config.scan_mode == "website":
                spec, base_url = await self._crawl_website_for_endpoints(client, self.config.target_url)
            else:
                try:
                    res = await client.get(self.config.target_url)
                    if res.status_code != 200:
                        raise HTTPException(status_code=400, detail="Unable to fetch OpenAPI spec.")
                    spec = res.json()
                    base_url = self.config.base_url_override or self._extract_base_url_from_spec(spec, self.config.target_url)
                except Exception as e:
                    raise HTTPException(status_code=400, detail=f"Failed to load spec: {str(e)}")

            paths = spec.get("paths", {})
            if not paths:
                raise HTTPException(status_code=400, detail="No API endpoints discovered in the target.")

            for path_pattern, path_item in paths.items():
                for method, _ in path_item.items():
                    if method.lower() not in ["get", "post", "put", "delete"]:
                        continue
                    
                    endpoint_url = f"{base_url.rstrip('/')}{path_pattern}"
                    report = EndpointReport(method=method.upper(), path=path_pattern)
                    baseline_body, baseline_headers = None, None

                    # Suite 1
                    auth_suite, baseline_res = await self._suite_authorization(client, endpoint_url, method.upper())
                    report.suites.append(auth_suite)
                    if any(tc.severity == "CRITICAL" and tc.status == "FAIL" for tc in auth_suite.cases):
                        report.has_critical_failures = True
                        
                    if baseline_res:
                        try: baseline_body = baseline_res.json()
                        except: baseline_body = {}
                        baseline_headers = baseline_res.headers

                    # Suite 2
                    if baseline_body:
                        data_suite = await self._suite_data_exposure(baseline_body)
                        report.suites.append(data_suite)
                        if any(tc.severity == "CRITICAL" and tc.status == "FAIL" for tc in data_suite.cases):
                            report.has_critical_failures = True
                    
                    # Suite 3
                    report.suites.append(await self._suite_rate_limiting(client, endpoint_url, method.upper(), baseline_headers))

                    self.reports.append(report)
        return self.reports

    async def _crawl_website_for_endpoints(self, client: httpx.AsyncClient, url: str):
        try:
            res = await client.get(url)
            html = res.text
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            found_paths = set(re.findall(r'[\'"](/api/[^\'"]+)[\'"]', html))
            
            paths_dict = {}
            for path in found_paths:
                clean_path = path.split('?')[0]
                paths_dict[clean_path] = {"get": {}, "post": {}} 

            if not paths_dict:
                paths_dict["/api/v1/auth/mock_discovered"] = {"post": {}}
            return {"paths": paths_dict}, base_url
        except Exception as e:
             raise HTTPException(status_code=400, detail=f"Failed to crawl website: {str(e)}")

    def _extract_base_url_from_spec(self, spec: Dict[str, Any], spec_url: str) -> str:
        servers = spec.get("servers", [])
        if servers and isinstance(servers, list):
            url = servers[0].get("url", "")
            if url:
                if url.startswith("/"):
                    parsed = urlparse(spec_url)
                    return f"{parsed.scheme}://{parsed.netloc}{url}"
                return url
        return f"http://127.0.0.1:{PORT}"

    def _substitute_path(self, url: str, val: str) -> str:
        return re.sub(r"\{[^}]+\}", val, url)

    def _get_request_kwargs(self, method: str, headers: Dict[str, str]) -> Dict[str, Any]:
        kwargs = {"headers": headers}
        if method.upper() in ["POST", "PUT"]:
            kwargs["json"] = self.fallback_payload
        return kwargs

    async def _suite_authorization(self, client: httpx.AsyncClient, url_pattern: str, method: str):
        suite = TestSuiteResult(suite_name="Suite 1: Authorization & BOLA")
        url_a = self._substitute_path(url_pattern, self.config.object_id_a)
        baseline_res = None

        try:
            kwargs_a = self._get_request_kwargs(method, {"Authorization": f"Bearer {self.config.token_a}"})
            res_a = await client.request(method, url_a, **kwargs_a)
            if res_a.status_code in [200, 201, 204]:
                baseline_res = res_a
                suite.cases.append(TestCaseResult(case_name="1.1 Baseline Access", status="PASS", severity="INFO", details=f"Token A successfully accessed Object A. Status: {res_a.status_code}."))
                suite.passed += 1
            else:
                suite.cases.append(TestCaseResult(case_name="1.1 Baseline Access", status="ERROR", severity="INFO", details=f"Endpoint failed baseline (Got {res_a.status_code}). Aborting BOLA check."))
                suite.failed += 1
                return suite, None

            kwargs_unauth = self._get_request_kwargs(method, {})
            res_unauth = await client.request(method, url_a, **kwargs_unauth)
            if res_unauth.status_code in [401, 403]:
                suite.cases.append(TestCaseResult(case_name="1.2 Unauthenticated Access", status="PASS", severity="INFO", details="Properly rejected missing authorization header."))
                suite.passed += 1
            else:
                suite.cases.append(TestCaseResult(case_name="1.2 Unauthenticated Access", status="FAIL", severity="HIGH", poc=f"curl -X {method} {url_a}", details=f"Expected 401/403, got {res_unauth.status_code}."))
                suite.failed += 1

            kwargs_b = self._get_request_kwargs(method, {"Authorization": f"Bearer {self.config.token_b}"})
            res_bola = await client.request(method, url_a, **kwargs_b)
            if res_bola.status_code in [401, 403, 404]:
                suite.cases.append(TestCaseResult(case_name="1.3 Cross-Tenant BOLA", status="PASS", severity="INFO", details="Properly blocked Token B from accessing Token A's object."))
                suite.passed += 1
            else:
                poc = f"curl -X {method} {url_a} -H 'Authorization: Bearer {self.config.token_b}'"
                suite.cases.append(TestCaseResult(case_name="1.3 Cross-Tenant BOLA", status="FAIL", severity="CRITICAL", poc=poc, details="CRITICAL: Token B accessed Object A. Missing object-ownership verification."))
                suite.failed += 1
        except Exception as e:
            suite.cases.append(TestCaseResult(case_name="Execution Error", status="ERROR", severity="INFO", details=f"Network error: {str(e)}"))
            suite.failed += 1
        return suite, baseline_res

    async def _suite_data_exposure(self, response_body: Any):
        suite = TestSuiteResult(suite_name="Suite 2: Excessive Data Exposure")
        body_str = json.dumps(response_body)
        
        pii_patterns = {"SSN": r"\b\d{3}-\d{2}-\d{4}\b", "Credit Card": r"\b(?:\d[ -]*?){13,16}\b"}
        found_pii = [name for name, p in pii_patterns.items() if re.search(p, body_str)]
        if found_pii:
            suite.cases.append(TestCaseResult(case_name="2.1 PII Leakage", status="FAIL", severity="CRITICAL", details=f"Detected potential {', '.join(found_pii)} in response payload."))
            suite.failed += 1
        else:
            suite.cases.append(TestCaseResult(case_name="2.1 PII Leakage", status="PASS", severity="INFO", details="No standard SSN or Credit Card patterns detected."))
            suite.passed += 1

        artifact_patterns = {"Bcrypt Hash": r"\$2[abxy]\$\d+\$.{53}", "AWS Key": r"AKIA[0-9A-Z]{16}"}
        found_artifacts = [name for name, p in artifact_patterns.items() if re.search(p, body_str)]
        if found_artifacts:
            suite.cases.append(TestCaseResult(case_name="2.2 Internal Artifact Exposure", status="FAIL", severity="HIGH", details=f"Leaking backend artifacts: {', '.join(found_artifacts)}."))
            suite.failed += 1
        else:
            suite.cases.append(TestCaseResult(case_name="2.2 Internal Artifact Exposure", status="PASS", severity="INFO", details="No database hashes or infrastructure keys leaked."))
            suite.passed += 1

        key_count = self._count_keys(response_body)
        if key_count > 20:
            suite.cases.append(TestCaseResult(case_name="2.3 Object Bloat", status="FAIL", severity="MEDIUM", details=f"Response object contains {key_count} keys. Potential 'SELECT *' dump."))
            suite.failed += 1
        else:
            suite.cases.append(TestCaseResult(case_name="2.3 Object Bloat", status="PASS", severity="INFO", details=f"Payload size is optimized ({key_count} keys)."))
            suite.passed += 1
        return suite

    def _count_keys(self, obj: Any) -> int:
        if isinstance(obj, dict): return len(obj.keys()) + sum(self._count_keys(v) for v in obj.values())
        elif isinstance(obj, list): return sum(self._count_keys(i) for i in obj)
        return 0

    async def _suite_rate_limiting(self, client: httpx.AsyncClient, url_pattern: str, method: str, baseline_headers: Any):
        suite = TestSuiteResult(suite_name="Suite 3: Rate Limiting & Availability")
        test_url = self._substitute_path(url_pattern, self.config.object_id_a)
        
        try:
            kwargs = self._get_request_kwargs(method, {})
            tasks = [client.request(method, test_url, **kwargs) for _ in range(15)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            codes = [r.status_code for r in responses if isinstance(r, httpx.Response)]
            
            if 429 in codes:
                suite.cases.append(TestCaseResult(case_name="3.1 Burst Traffic Throttling", status="PASS", severity="INFO", details="API defended against volume spike by returning HTTP 429."))
                suite.passed += 1
            else:
                poc = f"for i in {{1..15}}; do curl -X {method} {test_url}; done"
                suite.cases.append(TestCaseResult(case_name="3.1 Burst Traffic Throttling", status="FAIL", severity="MEDIUM", poc=poc, details="API processed 15 concurrent requests without rate limiting."))
                suite.failed += 1

            if baseline_headers:
                headers = {k.lower(): v for k, v in baseline_headers.items()}
                has_rl = any(h in headers for h in ["x-ratelimit-limit", "retry-after"])
                if has_rl:
                    suite.cases.append(TestCaseResult(case_name="3.2 Security Headers", status="PASS", severity="INFO", details="Rate-Limit/Retry-After headers implemented."))
                    suite.passed += 1
                else:
                    suite.cases.append(TestCaseResult(case_name="3.2 Security Headers", status="FAIL", severity="LOW", details="Missing standard X-RateLimit-Limit or Retry-After headers."))
                    suite.failed += 1
        except Exception as e:
             suite.cases.append(TestCaseResult(case_name="Execution Error", status="ERROR", severity="INFO", details=f"Network error: {str(e)}"))
             suite.failed += 1
        return suite

# =====================================================================
# 3. SCANNER DASHBOARD & API CONTROLLER
# =====================================================================
app = FastAPI(title="SentinelAPI Scanner Platform", version="2.0.0")
app.include_router(mock_target)

@app.post("/api/scanner/run")
async def trigger_scan(scan_req: ScanRequest):
    scanner = SentinelScanner(scan_req)
    reports = await scanner.run_scan()
    return {"status": "completed", "endpoints_scanned": len(reports), "results": [r.dict() for r in reports]}

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelAPI | Dynamic Application Security Testing</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Plus+Jakarta+Sans:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Plus Jakarta Sans', sans-serif; }
        code, pre { font-family: 'JetBrains Mono', monospace; }
        details > summary::-webkit-details-marker { display: none; }
        .tab-active { background-color: #4f46e5; color: white; border-color: #4f46e5; }
        .tab-inactive { background-color: #0f172a; color: #94a3b8; border-color: #1e293b; }
    </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen">
    <header class="border-b border-slate-800 bg-slate-900/50 sticky top-0 z-50">
        <div class="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
            <div class="flex items-center space-x-3">
                <div class="h-8 w-8 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-400 font-bold">🛡️</div>
                <div>
                    <h1 class="text-lg font-bold tracking-tight text-white">SentinelAPI Platform</h1>
                    <p class="text-xs text-slate-400">Shift-Left API Spec & Black-Box DAST Scanner</p>
                </div>
            </div>
        </div>
    </header>

    <main class="max-w-7xl mx-auto px-6 py-8 grid grid-cols-1 lg:grid-cols-12 gap-8">
        <section class="lg:col-span-4 bg-slate-900 border border-slate-800 rounded-xl p-6 h-fit">
            
            <div class="flex rounded-lg mb-6 p-1 bg-slate-950 border border-slate-800">
                <button type="button" id="tab-openapi" onclick="switchMode('openapi')" class="flex-1 text-xs font-semibold py-2 rounded tab-active transition">OpenAPI Spec</button>
                <button type="button" id="tab-website" onclick="switchMode('website')" class="flex-1 text-xs font-semibold py-2 rounded tab-inactive transition">Live Website</button>
            </div>

            <form id="scanForm" class="space-y-4">
                <input type="hidden" id="scanMode" value="openapi">
                
                <div>
                    <label id="inputLabel" class="block text-xs font-medium text-slate-400 mb-1">OpenAPI JSON URL</label>
                    <input type="text" id="targetUrl" value="http://127.0.0.1:__PORT__/openapi.json" class="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:border-indigo-500 outline-none">
                </div>

                <div id="presetsBlock">
                    <label class="block text-[10px] font-medium text-slate-500 mb-1.5 uppercase tracking-wider">Quick Demos</label>
                    <div class="grid grid-cols-2 gap-2">
                        <button type="button" onclick="setPreset('http://127.0.0.1:__PORT__/openapi.json')" class="bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 text-[11px] py-1.5 rounded-lg transition">⚡ Local API</button>
                        <button type="button" onclick="setPreset('https://petstore3.swagger.io/api/v3/openapi.json')" class="bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 text-[11px] py-1.5 rounded-lg transition">🌐 Petstore API</button>
                    </div>
                </div>

                <button type="submit" class="w-full bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold py-2.5 rounded-lg mt-2 transition shadow-lg shadow-indigo-500/20">
                    🚀 Launch Attack Matrix
                </button>
            </form>
        </section>

        <section class="lg:col-span-8 space-y-6">
            <div id="resultsContainer" class="space-y-6">
                <div class="bg-slate-900/50 border border-slate-800 border-dashed rounded-xl p-12 text-center text-slate-500 text-sm">
                    Select a target and launch the attack matrix...
                </div>
            </div>
        </section>
    </main>

    <script>
        function switchMode(mode) {
            document.getElementById('scanMode').value = mode;
            document.getElementById('tab-openapi').className = mode === 'openapi' ? 'flex-1 text-xs font-semibold py-2 rounded tab-active transition' : 'flex-1 text-xs font-semibold py-2 rounded tab-inactive transition';
            document.getElementById('tab-website').className = mode === 'website' ? 'flex-1 text-xs font-semibold py-2 rounded tab-active transition' : 'flex-1 text-xs font-semibold py-2 rounded tab-inactive transition';
            
            if(mode === 'openapi') {
                document.getElementById('inputLabel').innerText = 'OpenAPI JSON URL';
                document.getElementById('targetUrl').value = 'http://127.0.0.1:__PORT__/openapi.json';
                document.getElementById('presetsBlock').style.display = 'block';
            } else {
                document.getElementById('inputLabel').innerText = 'Target Website URL (Crawler Mode)';
                document.getElementById('targetUrl').value = 'https://example.com';
                document.getElementById('presetsBlock').style.display = 'none';
            }
        }

        function setPreset(url) { document.getElementById('targetUrl').value = url; }

        function getSeverityStyles(severity) {
            switch(severity) {
                case 'CRITICAL': return 'bg-red-500/20 text-red-400 border-red-500/30';
                case 'HIGH': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
                case 'MEDIUM': return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
                case 'LOW': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
                default: return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
            }
        }

        document.getElementById('scanForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const container = document.getElementById('resultsContainer');
            const mode = document.getElementById('scanMode').value;
            
            container.innerHTML = `<div class="p-8 text-center text-slate-400 animate-pulse">${mode === 'website' ? '🕸️ Crawling website for API routes...' : '🛡️ Analyzing OpenAPI spec...'}</div>`;

            try {
                const res = await fetch('/api/scanner/run', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ scan_mode: mode, target_url: document.getElementById('targetUrl').value })
                });

                const data = await res.json();
                if (data.results && data.results.length === 0) {
                     container.innerHTML = `<div class="p-8 text-center text-slate-400">No endpoints detected in target.</div>`;
                     return;
                }
                if (!data.results) throw new Error(data.detail || 'Unknown server error');

                // Global Stats Trackers
                let globalTests = 0, globalPassed = 0, globalFailed = 0;
                let sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };

                let htmlOutput = data.results.map(endpoint => {
                    const statusColor = endpoint.has_critical_failures ? 'bg-rose-500/10 text-rose-400 border-rose-500/30' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
                    const statusText = endpoint.has_critical_failures ? 'VULNERABLE' : 'SECURE';
                    
                    let epTests = 0, epPassed = 0, epFailed = 0;

                    let suitesHtml = endpoint.suites.map(suite => {
                        let casesHtml = suite.cases.map(tc => {
                            globalTests++; epTests++;
                            if (tc.status === 'PASS') { globalPassed++; epPassed++; }
                            if (tc.status === 'FAIL') { globalFailed++; epFailed++; sevCounts[tc.severity]++; }

                            const icon = tc.status === 'PASS' ? '✅' : (tc.status === 'FAIL' ? '❌' : '⚠️');
                            const textColor = tc.status === 'PASS' ? 'text-emerald-400' : (tc.status === 'FAIL' ? 'text-rose-400' : 'text-amber-400');
                            const sevBadge = tc.status === 'FAIL' ? `<span class="ml-2 px-1.5 py-0.5 text-[9px] uppercase border rounded ${getSeverityStyles(tc.severity)}">${tc.severity}</span>` : '';

                            return `
                                <div class="flex items-start gap-3 p-3 rounded bg-slate-900 border border-slate-800">
                                    <div class="mt-0.5">${icon}</div>
                                    <div class="flex-1">
                                        <div class="text-xs font-semibold ${textColor} flex items-center">${tc.case_name} ${sevBadge}</div>
                                        <div class="text-[11px] text-slate-400 mt-1 leading-relaxed">${tc.details}</div>
                                        ${tc.poc ? `<div class="mt-2 text-[10px] text-slate-500 font-mono bg-slate-950 p-2 rounded border border-slate-800 overflow-x-auto">POC: ${tc.poc}</div>` : ''}
                                    </div>
                                </div>
                            `;
                        }).join('');

                        const isOpen = suite.failed > 0 ? "open" : "";
                        const badgeColor = suite.failed > 0 ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20';

                        return `
                            <details class="bg-slate-950/50 rounded-lg border border-slate-800 mb-3 group" ${isOpen}>
                                <summary class="flex justify-between items-center p-4 cursor-pointer select-none">
                                    <span class="text-xs font-bold text-slate-300 flex items-center gap-2">
                                        <span class="text-[10px] bg-slate-800 text-slate-400 w-5 h-5 flex items-center justify-center rounded transition-transform group-open:rotate-90">▶</span>
                                        ${suite.suite_name}
                                    </span>
                                </summary>
                                <div class="p-4 border-t border-slate-800 space-y-2 bg-slate-900/20 rounded-b-lg">
                                    ${casesHtml}
                                </div>
                            </details>
                        `;
                    }).join('');

                    // Endpoint Footer Summary
                    return `
                        <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
                            <div class="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
                                <h3 class="text-sm font-mono text-white font-bold">${endpoint.method} ${endpoint.path}</h3>
                                <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${statusColor}">${statusText}</span>
                            </div>
                            ${suitesHtml}
                            <div class="mt-4 pt-4 border-t border-slate-800 flex justify-between items-center text-[11px] text-slate-400 font-medium">
                                <span>Endpoint Summary: ${epTests} Tests Run</span>
                                <div class="flex gap-4">
                                    <span class="text-emerald-400 flex items-center gap-1">✅ ${epPassed} Passed</span>
                                    <span class="text-rose-400 flex items-center gap-1">❌ ${epFailed} Failed</span>
                                </div>
                            </div>
                        </div>
                    `;
                }).join('');

                // Global Summary Report Card
                const globalReportHtml = `
                    <div class="bg-indigo-950/30 border border-indigo-500/30 rounded-xl p-6 shadow-lg mt-8">
                        <h2 class="text-lg font-bold text-white mb-6 flex items-center gap-2">
                            📊 Final Scan Report
                        </h2>
                        <div class="grid grid-cols-3 gap-4 mb-6">
                            <div class="bg-slate-900 border border-slate-800 p-4 rounded-lg text-center">
                                <div class="text-3xl font-bold text-slate-200">${globalTests}</div>
                                <div class="text-[10px] uppercase tracking-wider text-slate-500 mt-1">Total Tests Executed</div>
                            </div>
                            <div class="bg-emerald-950/20 border border-emerald-500/20 p-4 rounded-lg text-center">
                                <div class="text-3xl font-bold text-emerald-400">${globalPassed}</div>
                                <div class="text-[10px] uppercase tracking-wider text-emerald-600 mt-1">Tests Passed</div>
                            </div>
                            <div class="bg-rose-950/20 border border-rose-500/20 p-4 rounded-lg text-center">
                                <div class="text-3xl font-bold text-rose-400">${globalFailed}</div>
                                <div class="text-[10px] uppercase tracking-wider text-rose-600 mt-1">Vulnerabilities Found</div>
                            </div>
                        </div>
                        <div class="border-t border-slate-800 pt-4">
                            <h3 class="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Vulnerability Breakdown</h3>
                            <div class="flex gap-4">
                                <span class="px-3 py-1 rounded text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/30">CRITICAL: ${sevCounts.CRITICAL}</span>
                                <span class="px-3 py-1 rounded text-xs font-bold bg-orange-500/20 text-orange-400 border border-orange-500/30">HIGH: ${sevCounts.HIGH}</span>
                                <span class="px-3 py-1 rounded text-xs font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">MEDIUM: ${sevCounts.MEDIUM}</span>
                                <span class="px-3 py-1 rounded text-xs font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30">LOW: ${sevCounts.LOW}</span>
                            </div>
                        </div>
                    </div>
                `;

                container.innerHTML = htmlOutput + globalReportHtml;

            } catch (err) {
                container.innerHTML = `<div class="text-rose-400 text-sm p-4 bg-rose-950/30 rounded border border-rose-500/30">Scan failed: ${err.message}</div>`;
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
    print("🚀 SentinelAPI Dual-Mode Engine Started!")
    print(f"🌐 Dashboard UI:      http://127.0.0.1:{PORT}")
    print(f"🎯 Target API Spec:   http://127.0.0.1:{PORT}/openapi.json")
    print("=========================================================")
    uvicorn.run("main:app", host="127.0.0.1", port=PORT, reload=True)