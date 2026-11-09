"""
POWER Personal AI Assistant (Claude API, agentic tool use)

Setup:
    pip install anthropic
    export ANTHROPIC_API_KEY="your-key-here"
    python power_assistant.py

What it can do by itself (it decides when to use each tool):
    - get current date/time
    - calculate math safely
    - save / search long-term memories about you
    - list, read, write, and search files inside ./workspace
    - run Python code (asks your permission first)
    - search the web (Anthropic server-side web search tool)

Chat commands:
    /memories   list saved memories
    /forget N   delete memory number N
    /reset      clear current conversation
    /quit       exit
"""

import ast
import json
import operator
import subprocess
import sys
import hashlib
import shutil
import socket
import re
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from datetime import datetime
from pathlib import Path

import anthropic

# ------------------------------------------------------------------ config
MODEL = "claude-sonnet-5-5"
WORKSPACE = Path("workspace")          # the only folder the assistant may touch
MEMORY_FILE = Path("assistant_memory.json")
HISTORY_FILE = Path("assistant_history.json")
ENABLE_WEB_SEARCH = True               # set False if your account lacks it
ASK_BEFORE_RISKY = True                # confirm before writing files / running code
MAX_TOOL_ROUNDS = 12                   # safety limit for one question
MAX_SAVED_TURNS = 30

PROFILE = """
Name: Your Name
Role: (student / developer / founder - edit this)
Goals: (what you are working towards)
Style: Clear, practical answers. Short unless I ask for detail.
Language: English (you can mix Hindi if I do)
"""

WORKSPACE.mkdir(exist_ok=True)


# ------------------------------------------------------------------ storage
def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


memories = load_json(MEMORY_FILE, [])


def safe_path(name: str) -> Path:
    """Resolve a filename inside WORKSPACE; block escapes like ../../secret."""
    p = (WORKSPACE / name).resolve()
    if WORKSPACE.resolve() not in p.parents and p != WORKSPACE.resolve():
        raise ValueError("Path is outside the workspace folder.")
    return p


def confirm(question: str) -> bool:
    if not ASK_BEFORE_RISKY:
        return True
    return input(f"\n  [permission] {question} (y/n): ").strip().lower() == "y"


# ------------------------------------------------------------------ tools
_OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.Pow: operator.pow, ast.Mod: operator.mod,
    ast.FloorDiv: operator.floordiv, ast.USub: operator.neg,
}


def _eval(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval(node.left), _eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval(node.operand))
    raise ValueError("Unsupported expression")


def tool_get_time(**_):
    return datetime.now().strftime("%A, %d %B %Y, %I:%M %p")


def tool_calculate(expression: str):
    return str(_eval(ast.parse(expression, mode="eval").body))


def tool_save_memory(fact: str):
    memories.append(fact)
    save_json(MEMORY_FILE, memories)
    return f"Saved memory #{len(memories)}."


def tool_search_memory(query: str):
    hits = [f"#{i}: {m}" for i, m in enumerate(memories, 1) if query.lower() in m.lower()]
    return "\n".join(hits) or "No matching memories."


def tool_list_files(**_):
    files = [str(p.relative_to(WORKSPACE)) for p in WORKSPACE.rglob("*") if p.is_file()]
    return "\n".join(sorted(files)) or "(workspace is empty)"


def tool_read_file(filename: str):
    return safe_path(filename).read_text(encoding="utf-8")[:20000]


def tool_write_file(filename: str, content: str):
    if not confirm(f"Write file '{filename}' ({len(content)} chars)?"):
        return "User denied permission."
    p = safe_path(filename)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return f"Wrote {filename}."


def tool_search_files(query: str):
    results = []
    for p in WORKSPACE.rglob("*"):
        if p.is_file():
            try:
                for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                    if query.lower() in line.lower():
                        results.append(f"{p.relative_to(WORKSPACE)}:{n}: {line.strip()[:150]}")
            except (UnicodeDecodeError, OSError):
                pass
    return "\n".join(results[:40]) or "No matches."


def tool_run_python(code: str):
    print("\n  --- code to run ---\n" + code + "\n  -------------------")
    if not confirm("Run this Python code?"):
        return "User denied permission."
    try:
        r = subprocess.run(
            [sys.executable, "-c", code],
            cwd=WORKSPACE, capture_output=True, text=True, timeout=30,
        )
        return (r.stdout + r.stderr)[:8000] or "(no output)"
    except subprocess.TimeoutExpired:
        return "Timed out after 30 seconds."


# ---------------------- ethical security / diagnostic tools
# These tools are for systems you own or have explicit permission to test.
def _valid_host(target: str) -> str:
    target = target.strip()
    if not target or len(target) > 253 or any(c in target for c in "/\\@ "):
        raise ValueError("Enter one hostname or IP address only (no URL, path, or network range).")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", target):
        raise ValueError("Invalid hostname/IP format.")
    return target


def tool_nmap_scan(target: str):
    """A limited service/version scan of one authorized host."""
    target = _valid_host(target)
    nmap = shutil.which("nmap")
    if not nmap:
        return "Nmap is not installed. Install it first (Ubuntu: sudo apt install nmap)."
    if not confirm(f"Scan {target} with Nmap (top 100 TCP ports, service detection)? Only scan systems you own or are authorized to test."):
        return "User denied permission."
    try:
        result = subprocess.run(
            [nmap, "-sV", "--top-ports", "100", "-T3", "--reason", target],
            capture_output=True, text=True, timeout=120, check=False,
        )
        return (result.stdout + result.stderr)[:12000] or f"Nmap exited with code {result.returncode}."
    except subprocess.TimeoutExpired:
        return "Nmap scan timed out after 120 seconds."


def tool_dns_lookup(hostname: str):
    hostname = _valid_host(hostname)
    try:
        records = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None)})
        return f"DNS results for {hostname}:\n" + "\n".join(records)
    except socket.gaierror as exc:
        return f"DNS lookup failed: {exc}"


def tool_http_security_headers(url: str):
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        return "Enter a valid http:// or https:// URL without embedded credentials."
    if not confirm(f"Request the HTTP headers from {url}? Only test websites you own or are authorized to assess."):
        return "User denied permission."
    try:
        req = Request(url, headers={"User-Agent": "POWER-Security-Header-Check/1.0"}, method="HEAD")
        with urlopen(req, timeout=12) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            status = response.status
        checks = {
            "Strict-Transport-Security": "strict-transport-security",
            "Content-Security-Policy": "content-security-policy",
            "X-Content-Type-Options": "x-content-type-options",
            "X-Frame-Options": "x-frame-options",
            "Referrer-Policy": "referrer-policy",
        }
        lines = [f"HTTP status: {status}", "Security header review:"]
        for label, key in checks.items():
            lines.append(f"{'PRESENT' if key in headers else 'MISSING'} - {label}" + (f": {headers[key]}" if key in headers else ""))
        lines.append("\nNote: missing headers are review findings, not proof of a vulnerability.")
        return "\n".join(lines)
    except Exception as exc:
        return f"HTTP header check failed: {type(exc).__name__}: {exc}"


def tool_sha256_file(filename: str):
    path = safe_path(filename)
    if not path.is_file():
        return "File not found inside the workspace."
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"SHA-256  {filename}: {digest.hexdigest()}"


# ---------------------- defensive security analysis tools

def tool_worm_detector(filename: str):
    """Look for suspicious worm-like code indicators in a workspace text file; never execute it."""
    path = safe_path(filename)
    if not path.is_file():
        return "File not found inside the workspace."
    try:
        content = path.read_text(encoding="utf-8", errors="replace")[:1_000_000]
    except OSError as exc:
        return f"Could not read file: {exc}"
    indicators = {
        "network connection capability": r'(?i)socket\.(connect|create_connection)|requests\.(get|post)|urllib',
        "process or shell execution": r'(?i)subprocess\.|os\.(system|popen)|Popen\(',
        "replication or file copying": r'(?i)shutil\.(copy|copy2)|copyfile\(|write_text\(',
        "startup/persistence modification": r'(?i)RunOnce|CurrentVersion\\Run|crontab|systemd|Startup',
        "recursive filesystem traversal": r'(?i)os\.walk|rglob\(|walk\(',
    }
    found=[]
    for label, pattern in indicators.items():
        if re.search(pattern, content):
            found.append(label)
    if not found:
        return f"No listed worm-like indicators found in {filename}. This is not proof the file is safe."
    return "Potentially suspicious indicators (manual review required):\n- " + "\n- ".join(found) + "\nNo code was executed."


def tool_wireshark_analyze(filename: str):
    """Summarize an authorized PCAP/PCAPNG capture using tshark read-only."""
    path = safe_path(filename)
    if not path.is_file() or path.suffix.lower() not in (".pcap", ".pcapng", ".cap"):
        return "Provide a .pcap, .pcapng, or .cap file located inside ./workspace."
    tshark = shutil.which("tshark")
    if not tshark:
        return "TShark is not installed. Ubuntu/WSL: sudo apt install tshark (then rerun)."
    if not confirm(f"Read and summarize capture {filename}? Only analyze captures you are authorized to inspect."):
        return "User denied permission."
    try:
        result = subprocess.run([tshark, "-r", str(path), "-q", "-z", "io,phs"], capture_output=True, text=True, timeout=60, check=False)
        if result.returncode != 0:
            return (result.stderr or result.stdout)[:6000]
        return (result.stdout or "No protocol statistics returned.")[:10000]
    except subprocess.TimeoutExpired:
        return "Capture analysis timed out after 60 seconds."


def tool_phishing_analyze(indicator: str):
    """Perform offline heuristic analysis of a URL or pasted email text; no links are opened."""
    value = indicator.strip()
    if not value:
        return "Paste a suspicious URL or email text."
    flags=[]
    urls=re.findall(r'https?://[^\s<>\"\']+', value, flags=re.I)
    if re.search(r'(?i)urgent|immediately|verify your account|password expires|suspended|prize|wire transfer', value):
        flags.append("Urgency, account-threat, or reward language")
    if re.search(r'(?i)password|one.time.code|OTP|bank details|credit.card|login credentials', value):
        flags.append("Requests sensitive credentials or financial information")
    if re.search(r'(?i)bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd', value):
        flags.append("URL shortener detected")
    for raw in urls[:10]:
        try:
            host=(urlparse(raw).hostname or "").lower()
            if not host:
                flags.append(f"Malformed URL: {raw[:120]}")
                continue
            if host.startswith("xn--") or ".xn--" in host:
                flags.append(f"Internationalized/punycode domain: {host}")
            if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', host):
                flags.append(f"URL uses an IP address: {host}")
            if host.count("-") >= 3:
                flags.append(f"Domain contains many hyphens: {host}")
            if urlparse(raw).scheme != "https":
                flags.append(f"URL does not use HTTPS: {host}")
        except ValueError:
            flags.append("Malformed URL detected")
    if not flags:
        flags.append("No obvious heuristic warning found; this does not establish that the message is safe.")
    return "Offline phishing review (no links opened):\n- " + "\n- ".join(dict.fromkeys(flags)) + "\nDo not enter credentials or open attachments unless independently verified."


def tool_bruteforce_detect(log_text: str):
    """Identify repeated authentication failures in pasted/local log text; does not attempt logins."""
    if len(log_text) > 200_000:
        return "Log input is too large (maximum 200,000 characters)."
    counts={}
    for line in log_text.splitlines():
        if re.search(r'(?i)(failed password|authentication failure|login failed|invalid user|failed login)', line):
            m=re.search(r'(?i)(?:from|rhost=|ip[=: ]+)\s*([0-9a-fA-F:.]+)', line)
            source=m.group(1) if m else "source-not-found"
            counts[source]=counts.get(source,0)+1
    if not counts:
        return "No common failed-login patterns found in the supplied log text."
    ranked=sorted(counts.items(), key=lambda x:x[1], reverse=True)
    report=[f"{ip}: {n} failed-login event(s)" for ip,n in ranked[:20]]
    return "Possible brute-force indicators (review thresholds and time window):\n- " + "\n- ".join(report) + "\nThis is log analysis only; no passwords or accounts were tested."


def tool_bugbounty_scope_check(target: str, allowed_domains: str):
    """Check whether a hostname appears within a user-supplied bug bounty scope list."""
    host=_valid_host(target).lower().rstrip('.')
    allowed=[x.strip().lower().rstrip('.') for x in allowed_domains.split(',') if x.strip()]
    if not allowed:
        return "Paste the exact in-scope domains from the program policy."
    matches=[]
    for domain in allowed:
        domain=domain.removeprefix('*.')
        if domain and (host == domain or host.endswith('.'+domain)):
            matches.append(domain)
    if matches:
        return f"POTENTIALLY IN SCOPE: {host} matches {', '.join(matches)}. Verify exclusions, wildcard rules, ports, and testing restrictions in the official program policy before testing."
    return f"NOT IN THE SUPPLIED SCOPE LIST: {host}. Do not test unless the program explicitly authorizes it."

# ---------------------- advanced bug bounty workflow (passive / report-focused)

def _domain_matches(host: str, rule: str) -> bool:
    """Match exact or wildcard domain rules without accepting lookalike suffixes."""
    rule = rule.strip().lower().rstrip('.')
    host = host.strip().lower().rstrip('.')
    wildcard = rule.startswith('*.')
    base = rule[2:] if wildcard else rule
    if not base:
        return False
    if wildcard:
        return host.endswith('.' + base) and host != base
    return host == base


def tool_bugbounty_asset_inventory(assets: str, in_scope: str, out_of_scope: str = ""):
    """Classify supplied assets against explicit program scope rules; no probing."""
    if len(assets) > 50000:
        return "Asset list is too large (maximum 50,000 characters)."
    scope = [x.strip() for x in in_scope.splitlines() if x.strip()]
    exclusions = [x.strip() for x in out_of_scope.splitlines() if x.strip()]
    if not scope:
        return "Add the program's exact in-scope domain rules, one per line."
    rows, seen = [], set()
    for raw in assets.splitlines():
        raw = raw.strip()
        if not raw or raw.startswith('#'):
            continue
        candidate = raw if '://' in raw else 'https://' + raw
        try:
            host = (urlparse(candidate).hostname or '').lower().rstrip('.')
        except ValueError:
            host = ''
        if not host or any(ch.isspace() for ch in host):
            rows.append((raw, 'INVALID / REVIEW'))
            continue
        if host in seen:
            continue
        seen.add(host)
        excluded = any(_domain_matches(host, rule) for rule in exclusions)
        included = any(_domain_matches(host, rule) or host == rule.lower().removeprefix('*.').rstrip('.') for rule in scope)
        status = 'OUT OF SCOPE / DO NOT TEST' if excluded else ('POTENTIALLY IN SCOPE — VERIFY PROGRAM RULES' if included else 'NOT IN SUPPLIED SCOPE')
        rows.append((host, status))
    if not rows:
        return "No usable assets were supplied."
    return "Passive inventory (no DNS enumeration, requests, or scans):\n" + "\n".join(f"- {h}: {st}" for h, st in rows[:300]) + "\n\nVerify wildcard semantics, exclusions, ports, rate limits, and prohibited tests in the live policy."


def tool_bugbounty_test_plan(program_name: str, target: str, in_scope: str, out_of_scope: str, rules: str):
    """Build a safe manual test plan only after checking user-supplied scope and rules."""
    try:
        host = _valid_host(target).lower().rstrip('.')
    except Exception:
        return "Enter a valid target hostname."
    scope = [x.strip() for x in in_scope.splitlines() if x.strip()]
    exclusions = [x.strip() for x in out_of_scope.splitlines() if x.strip()]
    if not scope:
        return "Cannot create a plan without published in-scope rules."
    if any(_domain_matches(host, rule) or host == rule.lower().removeprefix('*.').rstrip('.') for rule in exclusions):
        return f"BLOCKED: {host} matches a supplied exclusion. Do not test it."
    if not any(_domain_matches(host, rule) or host == rule.lower().removeprefix('*.').rstrip('.') for rule in scope):
        return f"BLOCKED: {host} is not in the supplied scope. Do not test it."
    if not rules.strip():
        return "Add the program's testing rules and restrictions before generating a plan."
    return (f"BUG BOUNTY TEST PLAN — {program_name or 'Unnamed program'}\nTarget: {host}\n"
        "Scope: potentially in scope based only on user-supplied rules.\n\nPRE-FLIGHT\n"
        "1. Re-open the live policy and confirm asset, ports, and ownership.\n"
        "2. Record prohibited actions, rate limits, testing windows, and data rules.\n"
        "3. Use dedicated test accounts and synthetic data where permitted.\n"
        "4. Stop if testing affects availability or exposes real user data.\n\n"
        "SAFE MANUAL REVIEW CHECKLIST\n"
        "- Authentication/session: review configuration; use only your own account.\n"
        "- Access control: compare two accounts you control; never access another user's data.\n"
        "- Input handling: harmless, non-destructive strings only; no data extraction or command execution.\n"
        "- Business logic: document deviations without real financial transactions.\n"
        "- Configuration: review headers, cookie flags, TLS, and exposed documentation.\n"
        "- Information disclosure: collect minimal proof and redact secrets/personal data.\n\n"
        f"PROGRAM RULES PROVIDED\n{rules[:6000]}\n\n"
        "EVIDENCE: timestamp/timezone, exact in-scope URL, test account, minimal redacted request/response, expected vs actual result, impact, steps, and cleanup.\n"
        "This plan performs no tests and does not guarantee authorization; the live program policy takes precedence.")


def tool_bugbounty_report(program_name: str, target: str, title: str, weakness: str, summary: str, steps: str, impact: str, remediation: str):
    """Create a Markdown disclosure draft in workspace after explicit confirmation."""
    if not all(x.strip() for x in (target, title, weakness, summary, steps, impact, remediation)):
        return "Provide target, title, weakness, summary, reproduction steps, impact, and remediation."
    safe_title = re.sub(r'[^a-zA-Z0-9_-]+', '_', title).strip('_')[:60] or 'finding'
    filename = f"bug_bounty_reports/{datetime.now():%Y%m%d_%H%M%S}_{safe_title}.md"
    content = (f"# {title}\n\n- Program: {program_name or 'Not specified'}\n- Affected asset: {target}\n"
        f"- Weakness: {weakness}\n- Date: {datetime.now():%Y-%m-%d}\n- Status: Draft — verify scope and policy\n\n"
        f"## Summary\n{summary}\n\n## Steps to Reproduce\n{steps}\n\n## Impact\n{impact}\n\n"
        f"## Remediation\n{remediation}\n\n## Evidence and Safety\n"
        "Attach only minimal, redacted evidence from authorized testing. Remove credentials, tokens, personal data, and unrelated customer information.\n")
    if not confirm(f"Save report draft to workspace/{filename}?"):
        return "User denied permission; no report was saved."
    path = safe_path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')
    return f"Saved report draft: {filename}. Review and redact it before submitting."


TOOL_FUNCS = {
    "get_time": tool_get_time,
    "calculate": tool_calculate,
    "save_memory": tool_save_memory,
    "search_memory": tool_search_memory,
    "list_files": tool_list_files,
    "read_file": tool_read_file,
    "write_file": tool_write_file,
    "search_files": tool_search_files,
    "run_python": tool_run_python,
    "nmap_scan": tool_nmap_scan,
    "dns_lookup": tool_dns_lookup,
    "http_security_headers": tool_http_security_headers,
    "sha256_file": tool_sha256_file,
    "worm_detector": tool_worm_detector,
    "wireshark_analyze": tool_wireshark_analyze,
    "phishing_analyze": tool_phishing_analyze,
    "bruteforce_detect": tool_bruteforce_detect,
    "bugbounty_scope_check": tool_bugbounty_scope_check,
    "bugbounty_asset_inventory": tool_bugbounty_asset_inventory,
    "bugbounty_test_plan": tool_bugbounty_test_plan,
    "bugbounty_report": tool_bugbounty_report,
}


def schema(name, desc, props=None):
    props = props or {}
    return {
        "name": name,
        "description": desc,
        "input_schema": {
            "type": "object",
            "properties": {k: {"type": "string", "description": v} for k, v in props.items()},
            "required": list(props),
        },
    }


TOOLS = [
    schema("get_time", "Get the current local date and time."),
    schema("calculate", "Evaluate a math expression, e.g. '(12*7)/3'.", {"expression": "Math expression"}),
    schema("save_memory", "Save a lasting fact about the user (preferences, goals, people, projects). "
                          "Use when the user shares something worth remembering.", {"fact": "One clear sentence"}),
    schema("search_memory", "Search saved memories by keyword.", {"query": "Keyword"}),
    schema("list_files", "List files in the user's workspace folder."),
    schema("read_file", "Read a text file from the workspace.", {"filename": "Relative file name"}),
    schema("write_file", "Create or overwrite a text file in the workspace.",
           {"filename": "Relative file name", "content": "Full file content"}),
    schema("search_files", "Search all workspace files for a keyword.", {"query": "Keyword"}),
    schema("run_python", "Run Python code in the workspace folder and return its output. "
                         "Use for data work, scripts, and anything needing exact computation.",
           {"code": "Python source code"}),
    schema("nmap_scan", "Run a limited Nmap service/version scan against ONE host that the user owns or is explicitly authorized to test. Never scan public or third-party systems without permission.",
           {"target": "One hostname or IP address; no URL or CIDR range"}),
    schema("dns_lookup", "Resolve DNS for a hostname for network troubleshooting.",
           {"hostname": "Hostname or IP address"}),
    schema("http_security_headers", "Review common defensive HTTP security headers on a website the user owns or is authorized to assess.",
           {"url": "Full http:// or https:// URL"}),
    schema("sha256_file", "Calculate a SHA-256 hash for a file inside the assistant workspace; does not execute the file.",
           {"filename": "Relative file path inside workspace"}),
    schema("worm_detector", "Defensively inspect a workspace text file for suspicious worm-like code indicators. Never execute the file.", {"filename": "Relative text file path inside workspace"}),
    schema("wireshark_analyze", "Read-only protocol hierarchy summary of an authorized PCAP/PCAPNG capture using TShark.", {"filename": "Capture filename inside workspace"}),
    schema("phishing_analyze", "Offline heuristic review of a suspicious URL or pasted email. Never opens links or collects credentials.", {"indicator": "Suspicious URL or email text"}),
    schema("bruteforce_detect", "Detect repeated failed authentication events in supplied log text. Does not attempt logins.", {"log_text": "Pasted authentication log text"}),
    schema("bugbounty_scope_check", "Compare a target hostname with user-supplied bug bounty in-scope domains. Does not scan the target.", {"target": "Hostname to check", "allowed_domains": "Comma-separated exact in-scope domains from program policy"}),
    schema("bugbounty_asset_inventory", "Passively classify supplied assets against published scope and exclusions. Does not discover or probe assets.", {"assets": "Newline-separated hostnames or URLs", "in_scope": "Published in-scope domain rules, one per line; supports *.example.com", "out_of_scope": "Published exclusions, one per line"}),
    schema("bugbounty_test_plan", "Create a safe manual bug bounty checklist only when target matches user-supplied scope and program rules. Performs no testing.", {"program_name": "Program name", "target": "Target hostname", "in_scope": "Published in-scope rules, one per line", "out_of_scope": "Published exclusions, one per line", "rules": "Program policy, restrictions, rate limits, and prohibited tests"}),
    schema("bugbounty_report", "Create a Markdown vulnerability disclosure draft in workspace after user confirmation. Does not submit it.", {"program_name": "Program name", "target": "Affected asset", "title": "Finding title", "weakness": "Weakness category", "summary": "Concise finding summary", "steps": "Reproduction steps from authorized testing", "impact": "Demonstrated impact", "remediation": "Suggested remediation"}),
]
if ENABLE_WEB_SEARCH:
    TOOLS.append({"type": "web_search_20250305", "name": "web_search", "max_uses": 5})


# ------------------------------------------------------------------ prompt
def system_prompt():
    mem = "\n".join(f"- {m}" for m in memories) or "- (none yet)"
    return f"""You are a powerful personal AI assistant for one person. You can act, not just talk.

ABOUT THE USER:
{PROFILE.strip()}

LONG-TERM MEMORY:
{mem}

RULES:
- Use tools whenever they make the answer more accurate or useful (math, code, files, current info).
- Cybersecurity tools are for defensive learning and systems the user owns or has explicit permission to test. Bug bounty helpers only classify user-supplied scope, create non-invasive plans, and draft reports; never perform unauthorized discovery, exploitation, data access, or submission.
- Never perform exploitation, password guessing/brute force, credential theft, phishing delivery, malware deployment, persistence, or stealth/evasion. Defensive log analysis, offline phishing review, capture analysis, and scope checks are allowed. Do not scan third-party targets without authorization.
- When the user shares a lasting preference, goal, or fact, call save_memory (don't announce it every time).
- For anything needing the current date, call get_time. For current events, use web search.
- Work step by step on bigger tasks. Say briefly what you did at the end.
- If a tool fails, read the error, fix the input, and retry once.
- Be concise and honest. Never invent file contents or search results.
Today is {datetime.now():%A, %d %B %Y}."""


# ------------------------------------------------------------------ agent loop
def run_turn(client, messages):
    """Keep calling the model until it stops asking for tools."""
    for _ in range(MAX_TOOL_ROUNDS):
        resp = client.messages.create(
            model=MODEL, max_tokens=4000, system=system_prompt(),
            tools=TOOLS, messages=messages,
        )
        messages.append({"role": "assistant", "content": resp.content})

        for block in resp.content:
            if block.type == "text" and block.text.strip():
                print(f"\nAssistant: {block.text}")

        if resp.stop_reason == "pause_turn":      # server-side tool (web search) still running
            continue
        if resp.stop_reason != "tool_use":
            return "".join(b.text for b in resp.content if b.type == "text")

        results = []
        for block in resp.content:
            if block.type != "tool_use":
                continue
            print(f"  [tool] {block.name}")
            try:
                out = TOOL_FUNCS[block.name](**block.input)
                results.append({"type": "tool_result", "tool_use_id": block.id, "content": str(out)})
            except Exception as e:  # report the error to the model so it can recover
                results.append({"type": "tool_result", "tool_use_id": block.id,
                                "content": f"Error: {e}", "is_error": True})
        messages.append({"role": "user", "content": results})

    return "(Stopped: too many tool steps. Ask me to continue.)"


def main():
    client = anthropic.Anthropic()
    saved = load_json(HISTORY_FILE, [])          # only plain text turns are saved
    messages = list(saved)
    print("Power assistant ready. Workspace folder: ./workspace  |  /quit to exit\n")

    while True:
        try:
            text = input("\nYou: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not text:
            continue
        if text == "/quit":
            break
        if text == "/reset":
            messages, saved = [], []
            save_json(HISTORY_FILE, saved)
            print("Conversation cleared.")
            continue
        if text == "/memories":
            for i, m in enumerate(memories, 1):
                print(f"{i}. {m}")
            if not memories:
                print("No memories saved.")
            continue
        if text.startswith("/forget "):
            try:
                print("Forgot:", memories.pop(int(text.split()[1]) - 1))
                save_json(MEMORY_FILE, memories)
            except (ValueError, IndexError):
                print("Usage: /forget <number>")
            continue

        start = len(messages)
        messages.append({"role": "user", "content": text})
        try:
            final = run_turn(client, messages)
        except anthropic.APIError as e:
            print(f"\n[API error: {e}]")
            del messages[start:]                  # roll back the failed turn
            continue

        # Save only the text of this turn; tool details are not needed next session.
        saved += [{"role": "user", "content": text},
                  {"role": "assistant", "content": final or "(done)"}]
        saved = saved[-MAX_SAVED_TURNS * 2:]
        save_json(HISTORY_FILE, saved)


if __name__ == "__main__":
    main()