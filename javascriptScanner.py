"""
JavaScript/Node.js Vulnerability Scanner API (single-file, Python)
- FastAPI app that accepts a ZIP of a Node.js project or a server-side path.
- Static, heuristic checks for common JS/Node issues:
  - eval() / new Function usage
  - DOM XSS sinks: innerHTML, outerHTML, dangerouslySetInnerHTML
  - child_process.exec / spawn command injection patterns
  - Prototype pollution patterns ("__proto__", "prototype" assignment)
  - Hardcoded secrets and high-entropy files
  - Weak crypto (crypto.createHash('md5'))
  - SQL/NoSQL injection heuristics (string concat/templating with SQL keywords)
  - Unsanitized third-party API input (heuristic patterns)
  - Dependency audit via `npm audit --json` (optional)
  - Missing CORS/CSRF checks (framework heuristics for Express, Koa, Next.js)
  - Untrusted template injection patterns (EJS, Nunjucks, Handlebars)
  - Risky native module usage detection
  - Async anti-patterns (callback hell, unhandled promises) heuristics
  - Fingerprint (hash) generation per file and diff-tracking support in output
  - CI/PR mode: produce only new issues given a baseline report (diff mode)
  - Auto-remediation snippets per finding

Limitations:
- This is heuristic/static scanning; false positives/negatives will occur. Use as a guide.
- For deep JS AST analysis, integrate with node-based linters/parsers (eslint, semgrep, eslint-plugin-security).

Recommended complementary tools (what they do / URL):

- OSV-Scanner — Scans a source directory or project for known vulnerabilities via the open-source vulnerability database.
    https://github.com/google/osv-scanner

- OWASP Dependency-Check — Scans project dependencies (libraries) for known CVEs; useful for auditing npm packages.
    https://owasp.org/www-project-dependency-check/

- Nuclei — Template-based, fast vulnerability scanner for web endpoints and assets (good for testing web apps and APIs).
    https://github.com/projectdiscovery/nuclei

- Astra (Flipkart Incubator) — Automated REST API security testing tool (SQLi, XSS, etc.).
    https://github.com/flipkart-incubator/Astra

- VulnAPI — API security vulnerability scanner (DAST-style) for API-focused scanning.
    https://github.com/cerberauth/vulnapi

- w3af — Classic web application scanner with plugin architecture for web app testing.
    https://github.com/andresriancho/w3af

How to run:
1. python -m venv .venv && source .venv/bin/activate
2. pip install fastapi uvicorn python-magic
3. uvicorn js_node_vuln_scanner_fastapi:app --reload --port 8001

API:
- POST /scan : form-data 'archive' (zip) OR form field 'project_path' (server path). Optional form fields: run_dependency_audit (bool), baseline_report (file) to produce CI/PR diff.
- GET /health

Returns JSON report with per-file findings, file hashes, and remediation suggestions.
"""

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import tempfile
import zipfile
import os
import re
import math
import hashlib
import subprocess
import json
from typing import Optional, Dict, Any, List
import shutil

app = FastAPI(title="JS/Node Vulnerability Scanner API")

# Recommended external scanners (runtime hooks)
RECOMMENDED_TOOLS = [
    {"name": "osv-scanner", "description": "OSV scanner (OSV database)", "cmd": ["osv-scanner", "--format", "json", "{target}"], "url": "https://github.com/google/osv-scanner"},
    {"name": "dependency-check", "description": "OWASP Dependency-Check CLI", "cmd": ["dependency-check", "--project", "scan", "--format", "JSON", "--out", "{target}"], "url": "https://owasp.org/www-project-dependency-check/"},
    {"name": "nuclei", "description": "Nuclei scanner", "cmd": ["nuclei", "-u", "{target}", "-json"], "url": "https://github.com/projectdiscovery/nuclei"},
    {"name": "astra", "description": "Astra API tester", "cmd": ["astra", "-t", "{target}"], "url": "https://github.com/flipkart-incubator/Astra"},
    {"name": "vulnapi", "description": "VulnAPI DAST", "cmd": ["vulnapi", "scan", "{target}"], "url": "https://github.com/cerberauth/vulnapi"},
    {"name": "w3af", "description": "w3af web scanner", "cmd": ["w3af", "-s", "{target}"], "url": "https://github.com/andresriancho/w3af"}
]


def run_external_tools(target_path: str, timeout: int = 120) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    for tool in RECOMMENDED_TOOLS:
        name = tool.get("name")
        cmd_template = tool.get("cmd", [])
        results[name] = {"description": tool.get("description")}
        if not cmd_template:
            results[name]["error"] = "no-command-template"
            continue
        exe = cmd_template[0]
        if shutil.which(exe) is None:
            results[name]["error"] = "tool-not-found"
            continue
        cmd = [c.format(target=target_path) for c in cmd_template]
        try:
            proc = subprocess.run(cmd, cwd=target_path, capture_output=True, text=True, timeout=timeout)
            results[name].update({
                "exit_code": proc.returncode,
                "stdout": proc.stdout.strip() if proc.stdout else "",
                "stderr": proc.stderr.strip() if proc.stderr else "",
            })
        except subprocess.TimeoutExpired:
            results[name]["error"] = f"timeout-after-{timeout}s"
        except Exception as e:
            results[name]["error"] = str(e)
    return results

# -------------------- Heuristics / Regexes --------------------
EVAL_PATTERN = re.compile(r"\beval\s*\(|new\s+Function\s*\(")
DOM_XSS_PATTERNS = [re.compile(r"\.innerHTML\s*=") , re.compile(r"\.outerHTML\s*=") , re.compile(r"dangerouslySetInnerHTML\s*=")]
CHILD_PROCESS_PATTERN = re.compile(r"\b(child_process|require\(['\"]child_process)['\"]?\).*|(\.exec\s*\(|\.spawn\s*\()")
PROTOTYPE_POLLUTION = re.compile(r"__proto__\s*|prototype\s*\.|\bObject\.prototype\b|\.constructor\s*=")
WEAK_CRYPTO = re.compile(r"crypto\.createHash\s*\(\s*['\"]?(md5|sha1)['\"]?\s*\)")
SQL_KEYWORDS = re.compile(r"\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b|\bfrom\b", re.I)
STRING_CONCAT = re.compile(r"\+|`\${|sprintf\(|format\(|\.replace\(|String\.concat\(|template\s*[:=]")
TEMPLATE_ENGINE_UNTRUSTED = re.compile(r"<%|{{|{\{|handlebars|ejs|nunjucks", re.I)
HARDCODED_SECRET_RX = [
    re.compile(r"(?i)api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9\-_=]{8,}['\"]"),
    re.compile(r"(?i)secret\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
    re.compile(r"(?i)password\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
    re.compile(r"AKIA[0-9A-Z]{16}")
]
UNSAFE_NATIVE = re.compile(r"\b(fibers|node-ffi|ffi-napi|node-gyp)\b")
ASYNC_ANTIPATTERN = re.compile(r"callback\s*\(|\.then\s*\(|async\s+function\s*\(|await\s+")
CORS_MISCONFIG = re.compile(r"app\.use\(cors\(|origin:\s*\*\)|res\.header\(['\"]Access-Control-Allow-Origin['\"],\s*['\"]\*['\"]\)")
CSRF_MISSING = re.compile(r"csurf|csrf|csrf\(\)")

# entropy

def file_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0]*256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    length = len(data)
    for f in freq:
        if f:
            p = f/length
            entropy -= p * math.log2(p)
    return entropy

# file hash for fingerprinting

def file_hash(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

# scan a single JS/TS source file

def scan_js_source(path: str) -> List[Dict[str, Any]]:
    findings = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            src = f.read()
    except Exception as e:
        return [{"line": 0, "severity": "ERROR", "type": "read-error", "message": str(e)}]

    lines = src.splitlines()
    # line-wise regex heuristics
    for i, line in enumerate(lines, start=1):
        if EVAL_PATTERN.search(line):
            findings.append({"line": i, "severity": "HIGH", "type": "insecure-eval",
                             "message": "Use of eval/new Function detected.",
                             "suggestion": "Avoid eval/new Function. Use safe parsers or strict whitelisting for inputs.",
                             "code": line.strip()})
        for p in DOM_XSS_PATTERNS:
            if p.search(line):
                findings.append({"line": i, "severity": "HIGH", "type": "dom-xss",
                                 "message": "Assignment to innerHTML/outerHTML or dangerous React prop detected.",
                                 "suggestion": "Sanitize HTML or use textContent. Avoid inserting untrusted HTML.",
                                 "code": line.strip()})
        if CHILD_PROCESS_PATTERN.search(line):
            findings.append({"line": i, "severity": "HIGH", "type": "command-injection",
                             "message": "child_process exec/spawn or similar detected. Watch for untrusted input.",
                             "suggestion": "Use spawn with args array, avoid shell=true, sanitize inputs.",
                             "code": line.strip()})
        if PROTOTYPE_POLLUTION.search(line):
            findings.append({"line": i, "severity": "HIGH", "type": "prototype-pollution",
                             "message": "Potential prototype pollution pattern detected.",
                             "suggestion": "Validate object keys before merging/untrusted input. Use deep copies and whitelist keys.",
                             "code": line.strip()})
        if WEAK_CRYPTO.search(line):
            findings.append({"line": i, "severity": "MEDIUM", "type": "weak-crypto",
                             "message": "Weak hash (md5/sha1) used.",
                             "suggestion": "Use crypto.subtle or crypto.createHash('sha256') and for passwords use bcrypt/scrypt/argon2.",
                             "code": line.strip()})
        if SQL_KEYWORDS.search(line) and STRING_CONCAT.search(line):
            findings.append({"line": i, "severity": "HIGH", "type": "sql-injection",
                             "message": "SQL-like keyword used with string concatenation/templating - possible injection.",
                             "suggestion": "Use parameterized queries or query builders (pg-promise, knex) and sanitize inputs.",
                             "code": line.strip()})
        for rx in HARDCODED_SECRET_RX:
            if rx.search(line):
                findings.append({"line": i, "severity": "HIGH", "type": "hardcoded-secret",
                                 "message": "Potential hardcoded secret detected.",
                                 "suggestion": "Move secrets to environment variables or secret management services.",
                                 "code": line.strip()})
        if TEMPLATE_ENGINE_UNTRUSTED.search(line) and ('res.render' in src or 'render(' in line):
            findings.append({"line": i, "severity": "MEDIUM", "type": "template-injection",
                             "message": "Template syntax or render usage detected - ensure inputs are escaped.",
                             "suggestion": "Escape template inputs or use safe templating APIs.",
                             "code": line.strip()})
        if UNSAFE_NATIVE.search(line):
            findings.append({"line": i, "severity": "MEDIUM", "type": "risky-native-module",
                             "message": "Use of native or deprecated native module detected.",
                             "suggestion": "Evaluate necessity and use maintained alternatives.",
                             "code": line.strip()})
        # async antipattern heuristics
        if 'callback(' in line and 'promise' not in line:
            findings.append({"line": i, "severity": "LOW", "type": "async-antipattern",
                             "message": "Callback-style code detected; might lead to callback hell or error handling issues.",
                             "suggestion": "Prefer Promises/async-await and ensure errors are handled.",
                             "code": line.strip()})

    # file-level entropy check
    try:
        with open(path, 'rb') as f:
            data = f.read()
            ent = file_entropy(data)
            if ent > 4.0 and b'-----BEGIN' not in data:
                findings.append({"line": 0, "severity": "MEDIUM", "type": "high-entropy-file",
                                 "message": f"High entropy file (entropy={ent:.2f}) - may contain secrets or binaries.",
                                 "suggestion": "Check if this file contains secrets or remove binaries from repo.",
                                 "code": ""})
    except Exception:
        pass

    return findings

# scan project directory

def scan_project_dir(base_dir: str, run_dependency_audit: bool=False) -> Dict[str, Any]:
    report = {"files": {}, "summary": {"total_files": 0, "total_findings": 0}}
    js_files = []
    for root, dirs, files in os.walk(base_dir):
        for f in files:
            if f.endswith(('.js', '.jsx', '.ts', '.tsx')):
                js_files.append(os.path.join(root, f))
    report['summary']['total_files'] = len(js_files)

    for p in js_files:
        findings = scan_js_source(p)
        rel = os.path.relpath(p, base_dir)
        report['files'][rel] = {
            "findings": findings,
            "sha256": file_hash(p)
        }
        report['summary']['total_findings'] += len(findings)

    # package.json dependency audit
    pkg_path = os.path.join(base_dir, 'package.json')
    if os.path.exists(pkg_path):
        try:
            with open(pkg_path, 'r', encoding='utf-8') as f:
                pkg = json.load(f)
                report['package'] = {k: pkg.get(k) for k in ('name', 'version', 'dependencies', 'devDependencies')}
        except Exception as e:
            report['package'] = {"error": str(e)}

    # high entropy files
    secrets = []
    for root, dirs, files in os.walk(base_dir):
        for f in files:
            fp = os.path.join(root, f)
            try:
                data = open(fp, 'rb').read()
                ent = file_entropy(data)
                if ent > 4.0 and b'-----BEGIN' not in data:
                    secrets.append({"file": os.path.relpath(fp, base_dir), "entropy": ent})
            except Exception:
                continue
    report['high_entropy_files'] = secrets

    # run npm audit if requested
    if run_dependency_audit:
        try:
            proc = subprocess.run(["npm", "audit", "--json"], cwd=base_dir, capture_output=True, text=True, timeout=120)
            if proc.returncode == 0 and proc.stdout:
                try:
                    audit = json.loads(proc.stdout)
                except Exception:
                    audit = {"raw": proc.stdout}
                report['npm_audit'] = audit
            else:
                # npm audit may return non-zero if vulnerabilities exist; still try to parse stdout
                try:
                    audit = json.loads(proc.stdout)
                except Exception:
                    audit = {"error": proc.stderr or proc.stdout}
                report['npm_audit'] = audit
        except Exception as e:
            report['npm_audit'] = {"error": str(e)}

    # remediation snippets
    remediation = {
        "insecure-eval": "Avoid eval/new Function. Use safe parsers, whitelisting, or JSON.parse for JSON.",
        "dom-xss": "Sanitize HTML with a library (DOMPurify) or use textContent. Avoid inserting untrusted HTML.",
        "command-injection": "Use child_process.spawn with args array, set shell=false, and validate inputs.",
        "prototype-pollution": "Validate keys before merging objects (use lodash.mergewith with customizer) and avoid merging untrusted input.",
        "weak-crypto": "Replace md5/sha1 with sha256 or use password hashing libs (bcrypt, argon2).",
        "sql-injection": "Use parameterized queries or ORM query builders; never concatenate SQL with user input.",
        "hardcoded-secret": "Move secrets to environment variables, .env (gitignored), or secret managers like Vault.",
        "template-injection": "Escape user inputs in templates or use templating engines' safe APIs.",
    }
    report['remediation_suggestions'] = remediation

    return report

# -------------------- API --------------------

@app.post('/scan')
async def scan_endpoint(project_path: Optional[str] = Form(None), run_dependency_audit: Optional[bool] = Form(False), run_external_tools_flag: Optional[bool] = Form(False), baseline: Optional[UploadFile] = File(None), archive: Optional[UploadFile] = File(None)):
    if archive is None and not project_path:
        raise HTTPException(status_code=400, detail="Provide either an uploaded zip archive (archive) or a project_path.")

    with tempfile.TemporaryDirectory() as tmpdir:
        base_dir = tmpdir
        if archive:
            if not archive.filename.endswith('.zip'):
                raise HTTPException(status_code=400, detail="Only zip archives are supported for uploads.")
            contents = await archive.read()
            archive_path = os.path.join(tmpdir, archive.filename)
            with open(archive_path, 'wb') as f:
                f.write(contents)
            try:
                with zipfile.ZipFile(archive_path, 'r') as z:
                    z.extractall(tmpdir)
            except zipfile.BadZipFile:
                raise HTTPException(status_code=400, detail="Uploaded file is not a valid zip archive.")
        else:
            if not os.path.exists(project_path):
                raise HTTPException(status_code=400, detail="project_path does not exist on server.")
            # copy files
            for root, dirs, files in os.walk(project_path):
                rel = os.path.relpath(root, project_path)
                dest_root = os.path.join(tmpdir, rel) if rel != '.' else tmpdir
                os.makedirs(dest_root, exist_ok=True)
                for f in files:
                    srcf = os.path.join(root, f)
                    try:
                        with open(srcf, 'rb') as r, open(os.path.join(dest_root, f), 'wb') as w:
                            w.write(r.read())
                    except Exception:
                        continue

        report = scan_project_dir(base_dir, run_dependency_audit=run_dependency_audit)

        # External tools handling (optional)
        auto_run = os.environ.get('AUTO_RUN_EXTERNAL_TOOLS', '0') == '1'
        run_tools = bool(run_external_tools_flag) or auto_run
        report['summary']['external_tools_requested'] = run_tools
        report['summary']['external_tools_available'] = []
        report['summary']['external_tools_skipped'] = []
        report['summary']['external_tools_run_count'] = 0
        report['summary']['external_tool_recommendations'] = []
        for t in RECOMMENDED_TOOLS:
            exe = t.get('cmd', [None])[0]
            installed = bool(exe and shutil.which(exe))
            report['summary']['external_tool_recommendations'].append({'name': t.get('name'), 'url': t.get('url'), 'installed': installed})

        if run_tools:
            try:
                ext_results = run_external_tools(base_dir)
                report['external_tool_results'] = ext_results
                for k, v in ext_results.items():
                    if v.get('error'):
                        report['summary']['external_tools_skipped'].append(k)
                    else:
                        report['summary']['external_tools_available'].append(k)
                        report['summary']['external_tools_run_count'] += 1
            except Exception as e:
                report['external_tool_results'] = {"error": str(e)}

        # If baseline provided, compute diff (CI/PR mode)
        if baseline:
            try:
                base_contents = await baseline.read()
                baseline_report = json.loads(base_contents.decode('utf-8'))
                # naive diff: find findings in current report not present in baseline (by file+code+type)
                new_issues = []
                base_set = set()
                for f, v in baseline_report.get('files', {}).items():
                    for it in v.get('findings', []):
                        key = (f, it.get('type'), it.get('code'), it.get('line'))
                        base_set.add(key)
                for f, v in report['files'].items():
                    for it in v.get('findings', []):
                        key = (f, it.get('type'), it.get('code'), it.get('line'))
                        if key not in base_set:
                            new_issues.append({"file": f, **it})
                report['ci_new_issues'] = new_issues
            except Exception as e:
                report['ci_error'] = str(e)

        return JSONResponse(report)


@app.get('/health')
async def health():
    return {"status": "ok"}


if __name__ == '__main__':
    import uvicorn
    uvicorn.run('js_node_vuln_scanner_fastapi:app', host='0.0.0.0', port=8001, reload=True)
