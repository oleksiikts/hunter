#!/usr/bin/env python3
"""
hunter.py — Transaction State Recon Engine (v7.0 - Strategic Logic Edition)
=====================================================================
Features:
  Stage 1: Foundation (Graph Topology, Contextual Scoring)
  Stage 2: Detection (Smart Parser, DeFi, Entropy)
  Stage 3: Interaction (Auth, Active Probe, Dynamic Payloads)
  Stage 4: Logic (State Machine, Replay Detection, Architecture)
  Stage 5: Intelligence (AI Strategy, Human Mode)
=====================================================================
"""

from __future__ import annotations
import asyncio
import os
import re
import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse
import aiohttp
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

# ─────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────
TARGETS_FILE = os.getenv("TARGETS_FILE", "targets.txt")
REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "reports"))
CONCURRENCY = int(os.getenv("CONCURRENCY", "10"))
TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "15"))
AI_API_KEY = os.getenv("OPENAI_API_KEY", "")
AI_MODEL = os.getenv("AI_MODEL", "gpt-4o")

# ═══════════════════════════════════════════════════════════════
# STAGE 2: ADVANCED PATTERNS
# ═══════════════════════════════════════════════════════════════

STATE_PATTERNS = {
    # Core Transactions
    "State Change": r"(?i)(/withdraw|/deposit|/transfer|/payout|/exchange|/swap|/order/create|/buy|/sell)",
    "Processing":   r"(?i)(pending|processing|queued|awaiting_confirm|confirming|webhook|callback)",
    "Idempotency":  r"(?i)(nonce|request_id|idempotency|transaction_hash|dedup_id|uuid)",
    
    # DeFi / Crypto (L2)
    "DeFi Slippage":r"(?i)(minAmount|amountOutMin|slippage|maxSlippage|priceImpact|slippageTolerance)",
    "Flash Loan":   r"(?i)(flashloan|flashLoan|flash_loan|flashSwap|flashBorrow|aave.*?flash|dydx.*?solo)",
    "Token Approve":r"(?i)(\.approve\s*\(|allowance|increaseAllowance|decreaseAllowance|permit\s*\(|ERC20.*?approve)",
    "DeFi Router":  r"(?i)(swapExactTokens|addLiquidity|removeLiquidity|getAmountsOut|pancakeRouter|uniswapRouter)",
}

LOGIC_PATTERNS = {
    "Client Math":  r"(?i)(parseFloat|toFixed|Math\.round|calculateFee|getRate|totalAmount)\s*\(",
    "Sensitive Params": r"(?i)(price|cost|amount|fee|rate|currency_id|wallet_id|destination_tag)['\"]:\s*",
    "Client Auth":  r"(?i)(isAdmin|userRole|canWithdraw|kycLevel|isVerified)['\"]:\s*(true|1|'admin')",
}

INFRA_PATTERNS = {
    "Secrets":      r"(?i)(api_key|private_key|secret_key|access_token|auth_token)\s*[:=]\s*['\"]([a-zA-Z0-9\-_]{32,})['\"]",
    "Debug Mode":   r"(?i)(APP_DEBUG|stack trace|laravel ignition|symfony profiler)",
    "WebSocket":    r"wss?://[\w\.-]+[\w/]+",
}

AUTOMATION_PATTERNS = {
    "Full Auto": [r"(?i)(instant payout|automatic processing|auto-confirm|webhook|ipn|api callback)"],
    "Semi Auto": [r"(?i)(manual processing|operator review|admin approval|security check)"],
    "Manual":    [r"(?i)(contact support|telegram operator|manager)"]
}

FLOW_CHAINS = { # L6
    "Payment Flow":    ["create", "pending", "confirm", "complete", "callback", "webhook"],
    "Withdrawal Flow": ["withdraw", "verify", "approve", "process", "complete", "status"],
    "Exchange Flow":   ["order", "match", "fill", "settle", "cancel"],
    "DeFi Flow":       ["approve", "swap", "addLiquidity", "removeLiquidity", "harvest"],
}

SOURCE_WEIGHTS = { # L17
    "Runtime Confirmed": 2.0,  # Validated by probe
    "Smart Parser": 1.2,       # Extracted from logic
    "JS Regex": 0.8,           # Regex match in JS
    "HTML Text": 0.2,          # Static text
    "API Response": 1.5,       # Live data
}

console = Console()
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# ═══════════════════════════════════════════════════════════════
# STAGE 1: NEW FOUNDATION (Data Structures)
# ═══════════════════════════════════════════════════════════════

@dataclass
class Finding:
    category: str
    description: str
    risk_score: int       # 0-100 Base Risk
    exploitability: int   # 0-100 Ease of Exploit
    confidence: int       # 0-100 Validity Chance
    source_type: str
    evidence: str = ""

    @property
    def composite(self) -> float:
        # L17: Confidence Weighting
        w = SOURCE_WEIGHTS.get(self.source_type, 1.0)
        base = self.risk_score * 0.4 + self.exploitability * 0.3 + self.confidence * 0.3
        return base * w

    @property
    def severity(self) -> str:
        c = self.composite
        if c >= 100: return "CRITICAL"
        if c >= 60: return "HIGH"
        if c >= 35: return "MEDIUM"
        return "LOW"

@dataclass
class EndpointNode: # L14
    path: str
    method: str = "GET"
    is_state_change: bool = False
    has_idempotency: bool = False
    params: set[str] = field(default_factory=set)
    config_object: dict = field(default_factory=dict) # From Smart Parser
    source: str = "Unknown"

@dataclass
class TargetResult:
    domain: str
    alive_urls: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    
    # Graph & Logic
    endpoint_graph: dict[str, EndpointNode] = field(default_factory=dict)
    state_flow_map: dict = field(default_factory=dict)
    active_replays: list[str] = field(default_factory=list)
    
    # Meta
    automation_type: str = "Unknown"
    automation_score: int = 0
    architecture: dict = field(default_factory=lambda: {"type": "Unknown", "api_domain": None})
    ai_analysis: str = ""
    stop_triggered: bool = False
    stop_reason: str = ""

    @property
    def score(self) -> int:
        return int(sum(f.composite for f in self.findings)) if self.findings else 0

    def add_finding(self, category, description, risk=50, exploit=50, conf=50, source="JS Regex"):
        f = Finding(category, description, risk, exploit, conf, source)
        self.findings.append(f)

# ═══════════════════════════════════════════════════════════════
# STAGE 2: SMART PARSER (L19)
# ═══════════════════════════════════════════════════════════════

class JSParser:
    """Recursive Descent Parser for extracting JS objects inside function calls."""
    
    @staticmethod
    def extract_function_calls(text: str, func_name: str) -> list[tuple[str, str]]:
        """Used to find patterns like 'axios.post(url, config)'."""
        results = []
        start_idx = 0
        while True:
            idx = text.find(func_name, start_idx)
            if idx == -1: break
            
            # Find opening parenthesis
            open_paren = text.find("(", idx)
            if open_paren == -1: 
                start_idx = idx + 1
                continue
                
            # Extract arguments respecting nesting
            args_str, end_pos = JSParser._extract_balanced(text, open_paren)
            if args_str:
                # Naive split by comma (ignoring commas inside strings/objects would be better but complex)
                # For now, we assume standard 'url, config' pattern
                parts = JSParser._split_args(args_str)
                if len(parts) >= 1:
                    url = parts[0].strip().strip("'\"")
                    config = parts[1] if len(parts) > 1 else "{}"
                    results.append((url, config))
            
            start_idx = end_pos
        return results

    @staticmethod
    def _extract_balanced(text: str, start_index: int) -> tuple[str, int]:
        """Extracts content between ( and ) handling nested structures."""
        depth = 0
        in_string = False
        quote_char = ''
        
        for i in range(start_index, len(text)):
            char = text[i]
            
            if in_string:
                if char == quote_char and text[i-1] != '\\': in_string = False
            else:
                if char in "'\"`":
                    in_string = True; quote_char = char
                elif char in "({[": depth += 1
                elif char in ")}]": depth -= 1
                
                if depth == 0:
                    return text[start_index+1:i], i + 1
        return "", start_index + 1

    @staticmethod
    def _split_args(args_str: str) -> list[str]:
        # Simple split, doesn't handle commas in strings fully, but good enough for axios(url, {obj})
        # Improve: track depth while splitting
        parts = []
        depth = 0; last_idx = 0
        for i, char in enumerate(args_str):
            if char in "({[": depth += 1
            elif char in ")}]": depth -= 1
            elif char == "," and depth == 0:
                parts.append(args_str[last_idx:i])
                last_idx = i + 1
        parts.append(args_str[last_idx:])
        return parts

    @staticmethod
    def parse_keys(obj_str: str) -> list[str]:
        """Extracts keys from a JS object string like { amount: 100, headers: ... }"""
        return re.findall(r"([a-zA-Z0-9_]+)\s*:", obj_str)

# ═══════════════════════════════════════════════════════════════
# STAGE 3: HANDS (Auth & Probe)
# ═══════════════════════════════════════════════════════════════

def load_auth() -> tuple[dict, dict]: # L3/L21
    """Restored Auth Loading"""
    try:
        data = json.loads((Path(__file__).parent / "auth.json").read_text(encoding="utf-8"))
        cookies = {k: v for k, v in data.get("cookies", {}).items() if "YOUR_" not in v}
        headers = {k: v for k, v in data.get("headers", {}).items() if "YOUR_" not in v}
        if cookies or headers: console.print("[green]✔ Auth Loaded[/green]")
        return cookies, headers
    except: return {}, {}

async def active_probe_verifier(session, base_url: str, tr: TargetResult): # L4/L16/L20
    """Scans Endpoint Graph and sends Dynamic Payloads."""
    
    # 1. CORS Check
    try:
        async with session.options(base_url, timeout=5) as resp:
            if resp.headers.get("Access-Control-Allow-Origin") == "*":
                tr.add_finding("infra", "CORS Wildcard (*)", 50, 40, 90, "Runtime Confirmed")
    except: pass

    # 2. Dynamic Payload Probing
    state_nodes = [n for n in tr.endpoint_graph.values() if n.is_state_change]
    
    for node in state_nodes[:5]: # Cap at 5 to avoid noise
        url = urljoin(base_url, node.path)
        
        # Construct Payload from Smart Parser Keys (L20)
        payload = {}
        for param in node.params:
            if "amount" in param or "price" in param: payload[param] = 1
            elif "email" in param: payload[param] = "hunter@test.com"
            elif "id" in param: payload[param] = "1"
            else: payload[param] = "test"
            
        try:
            # POST Probe
            async with session.post(url, json=payload, timeout=5) as resp:
                if resp.status == 200:
                    tr.add_finding("logic", f"Unauth Access/Logic Success: {node.path}", 90, 90, 100, "Runtime Confirmed")
                elif resp.status == 500:
                    text = await resp.text()
                    if "trace" in text.lower():
                        tr.add_finding("infra", f"Stack Trace Leak: {node.path}", 60, 50, 100, "Runtime Confirmed")
        except: pass

# ═══════════════════════════════════════════════════════════════
# STAGE 4: BRAIN (Logic & State)
# ═══════════════════════════════════════════════════════════════

def analyze_logic_graph(tr: TargetResult): # L6/L7/L15
    """L15: State Machine Analysis"""
    graph_keys = set(tr.endpoint_graph.keys())
    
    for flow, steps in FLOW_CHAINS.items():
        # Match steps in graph (fuzzy match)
        found_steps = []
        for step in steps:
            matches = [k for k in graph_keys if step in k.lower()]
            if matches: found_steps.append(matches[0])
            
        if len(found_steps) >= 2:
            tr.state_flow_map[flow] = found_steps
            
            # Replay Logic: "create" + "complete" exists but no idempotency in ANY step
            has_idemp = any(tr.endpoint_graph[k].has_idempotency for k in found_steps)
            has_entry = any("create" in k or "withdraw" in k for k in found_steps)
            has_exit = any("complete" in k or "process" in k for k in found_steps)
            
            if has_entry and has_exit and not has_idemp:
                tr.active_replays.append(flow)
                tr.add_finding("state", f"Critical Replay Surface: {flow}", 95, 80, 70, "Smart Parser")

def contextual_score(text: str, source: str) -> float: # L1
    if "HTML" in source: return 0.1
    if "JS" in source: return 1.0
    return 0.5

# ═══════════════════════════════════════════════════════════════
# STAGE 5: AI & CORE PIPELINE
# ═══════════════════════════════════════════════════════════════

async def ai_strategize(session, tr: TargetResult): # L18
    if not AI_API_KEY: return "No AI Key."
    prompt = f"""Target: {tr.domain} Type: {tr.automation_type}
    Flows: {json.dumps(tr.state_flow_map)}
    Top Findings: {[f.description for f in tr.findings[:3]]}
    Identify ONE critical logic weakness strategy."""
    
    try:
        async with session.post("https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {AI_API_KEY}"},
            json={"model": AI_MODEL, "messages": [{"role":"user","content":prompt}]}, timeout=10) as r:
            if r.status==200: tr.ai_analysis = (await r.json())["choices"][0]["message"]["content"]
    except: pass

async def process_content(session, url: str, tr: TargetResult, source: str = "HTML"):
    try:
        async with session.get(url, ssl=False, timeout=TIMEOUT) as resp:
            text = await resp.text(errors='ignore')
            ctx = contextual_score(text, source)
            
            # L12: Architecture
            if "HTML" in source and len(tr.endpoint_graph) > 5: tr.architecture["type"] = "SPA"

            # L19: Smart Parser (Axios Extraction)
            calls = JSParser.extract_function_calls(text, "axios.post")
            calls += JSParser.extract_function_calls(text, "http.post")
            
            for path, config in calls:
                node = EndpointNode(path=path, method="POST", source="Smart Parser")
                # Parse config logic
                keys = JSParser.parse_keys(config)
                node.params.update(keys)
                
                # Check Idempotency by Keys
                if any(k in keys for k in ["nonce", "idempotency", "uuid"]):
                    node.has_idempotency = True
                
                # Check State Change by Path
                if re.search(STATE_PATTERNS["State Change"], path):
                    node.is_state_change = True
                
                tr.endpoint_graph[path] = node

            # Fallback Regex (for non-axios)
            for name, pat in STATE_PATTERNS.items():
                if re.search(pat, text):
                    tr.add_finding("state", f"Pattern: {name}", 50, 50, 50, "JS Regex" if ctx==1 else "HTML Text")

    except: pass

async def main_async():
    console.print("[bold red]🐺 HUNTER v7.0 — STRATEGIC LOGIC EDITION[/bold red]")
    cookies, headers = load_auth()
    
    targets = []
    if os.path.exists(TARGETS_FILE):
        with open(TARGETS_FILE) as f: targets = [l.strip() for l in f if l.strip()]

    results = {t: TargetResult(domain=t) for t in targets}
    
    async with aiohttp.ClientSession(headers=headers, cookies=cookies) as session:
        for t in targets:
            url = f"https://{t}" if not t.startswith("http") else t
            
            # 1. Digest Content
            await process_content(session, url, results[t], "HTML")
            # (Stub: JS extraction logic normally goes here)
            
            # 2. Logic Analysis
            analyze_logic_graph(results[t])
            
            # 3. Active Interaction (L13 Stop Check)
            is_critical = any(f.severity == "CRITICAL" for f in results[t].findings)
            if not is_critical: # Don't probe if already critical/stopped
                await active_probe_verifier(session, url, results[t])
            else:
                results[t].stop_triggered = True
                results[t].stop_reason = "Critical Findings Found (Skip Probe)"

            # 4. AI
            await ai_strategize(session, results[t])
            
            # Report
            res = results[t]
            console.print(f"[green]Finished {t} | Score: {res.score} | Auto: {res.automation_type}[/green]")
            if res.stop_triggered: console.print(f"[red]🛑 STOP: {res.stop_reason}[/red]")

if __name__ == "__main__":
    asyncio.run(main_async())