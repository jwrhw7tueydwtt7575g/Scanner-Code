"""
Vulnerability Scanner API (single-file)
- FastAPI app that accepts uploaded .zip of a Python project or a path on disk
- Performs static checks using AST + regex, simple taint analysis, entropy-based secret detection,
  dependency audit (optional, requires pip-audit installed), and suggestions for auto-remediation.

How to run:
1. Create virtualenv: python -m venv .venv && source .venv/bin/activate
2. Install requirements: pip install -r requirements.txt
3. Start server: uvicorn python_vuln_scanner:app --reload --port 8000

Endpoints:
- POST /scan : form-data 'archive' file (zip) OR json body { "project_path": "/path/to/project" }
  Returns JSON report of findings grouped by file and vulnerability type.

Limitations:
- This is a static analyzer, not a replacement for dynamic testing or a full SAST product.
- Some checks are heuristic-based and may produce false positives/negatives.

Recommended complementary tools (what they do / URL):

- OSV-Scanner — Scans a source directory or project for known vulnerabilities via the open-source vulnerability database (good for native package databases and source-level vuln matching).
    https://github.com/google/osv-scanner

- OWASP Dependency-Check — Scans project dependencies (libraries) for known CVEs. Useful as an additional dependency auditor.
    https://owasp.org/www-project-dependency-check/

- Nuclei — Template-based, fast vulnerability scanner for web endpoints and assets. Useful for API/web testing in CI.
    https://github.com/projectdiscovery/nuclei

- Astra (Flipkart Incubator) — Automated REST API security testing tool (SQLi, XSS, etc.).
    https://github.com/flipkart-incubator/Astra

- VulnAPI — API security vulnerability scanner (DAST-like) for testing APIs.
    https://github.com/cerberauth/vulnapi

- w3af — Web application attack and audit framework (classic scanner with plugins).
    https://github.com/andresriancho/w3af
"""

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn
import tempfile
import zipfile
import os
import ast
import re
import math
import base64
import subprocess
import shutil
from typing import List, Dict, Any, Optional

app = FastAPI(title="Python Vulnerability Scanner API")

# Recommended external scanners (runtime hooks). Each entry contains a label,
# a short description, and a simple 'cmd' template or command to run when
# available on the system. The runner below will attempt to execute these
# commands in sequence and attach stdout/stderr to the response JSON.
RECOMMENDED_TOOLS = [
    {
        "name": "osv-scanner",
        "description": "Scans a source directory or project for known vulnerabilities via the OSV database.",
        "cmd": ["osv-scanner", "--format", "json", "{target}"],
        "url": "https://github.com/google/osv-scanner"
    },
    {
        "name": "dependency-check",
        "description": "OWASP Dependency-Check for scanning dependencies for CVEs.",
        "cmd": ["dependency-check", "--project", "scan", "--format", "JSON", "--out", "{target}"],
        "url": "https://owasp.org/www-project-dependency-check/"
    },
    {
        "name": "nuclei",
        "description": "Nuclei scanner for web/app assets (templates).",
        "cmd": ["nuclei", "-u", "{target}", "-json"],
        "url": "https://github.com/projectdiscovery/nuclei"
    },
    {
        "name": "astra",
        "description": "Astra automated REST API security testing tool.",
        "cmd": ["astra", "-t", "{target}"],
        "url": "https://github.com/flipkart-incubator/Astra"
    },
    {
        "name": "vulnapi",
        "description": "VulnAPI DAST-style API scanner.",
        "cmd": ["vulnapi", "scan", "{target}"],
        "url": "https://github.com/cerberauth/vulnapi"
    },
    {
        "name": "w3af",
        "description": "w3af web application scanner (plugin architecture).",
        "cmd": ["w3af", "-s", "{target}"],
        "url": "https://github.com/andresriancho/w3af"
    }
]


def run_external_tools(target_path: str, timeout: int = 120) -> Dict[str, Any]:
    """Attempt to run recommended external tools sequentially against target_path.

    This function is best-effort: if a tool isn't installed or returns an error,
    we capture that output and move on. We never allow a single tool to block
    the scan for longer than `timeout` seconds.
    """
    results: Dict[str, Any] = {}
    for tool in RECOMMENDED_TOOLS:
        name = tool.get("name")
        cmd_template = tool.get("cmd", [])
        results[name] = {"description": tool.get("description")}
        if not cmd_template:
            results[name]["error"] = "no-command-template"
            continue
        # quick installed check: look for the executable (first token) in PATH
        exe = cmd_template[0]
        if shutil.which(exe) is None:
            results[name]["error"] = "tool-not-found"
            continue
        # render the target into the command template
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

# -------------------- Helper utilities --------------------
SQL_PATTERN = re.compile(r"\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b", re.I)
SECRET_REGEXES = [
    re.compile(r"(?i)api[_-]?key\s*[=:]\s*['\"]([A-Za-z0-9\-_=]{8,})['\"]"),
    re.compile(r"(?i)secret[_-]?key\s*[=:]\s*['\"]([A-Za-z0-9\-_=]{8,})['\"]"),
    re.compile(r"(?i)password\s*[=:]\s*['\"](.{6,})['\"]"),
    re.compile(r"AKIA[0-9A-Z]{16}")  # AWS access key pattern
]
WEAK_HASHES = ["md5", "sha1"]

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

# Simple AST visitors and checks
class VulnerabilityFinder(ast.NodeVisitor):
    def __init__(self, source: str):
        self.source = source.splitlines()
        self.findings = []
        self.current_function = None
        # tracks assignments for naive taint analysis
        self.assignments = {}

    def add(self, lineno, severity, vtype, message, suggestion=None):
        self.findings.append({
            "line": lineno,
            "severity": severity,
            "type": vtype,
            "message": message,
            "suggestion": suggestion,
            "code": self.source[lineno-1].strip() if 0 <= lineno-1 < len(self.source) else ""
        })

    def visit_Call(self, node: ast.Call):
        # detect eval, exec usage
        try:
            func = node.func
            if isinstance(func, ast.Name) and func.id in ("eval", "exec", "execfile"):
                self.add(node.lineno, "HIGH", "insecure-eval-exec",
                         f"Use of {func.id}() detected.",
                         "Avoid eval/exec. Use ast.literal_eval or proper parsing and validation.")

            # subprocess/os.system calls
            if isinstance(func, ast.Attribute):
                # e.g., subprocess.Popen or os.system
                full = f"{getattr(func.value, 'id', getattr(func.value, 'attr', ''))}.{func.attr}"
                if (isinstance(func.value, ast.Name) and func.value.id == 'subprocess') or full.endswith('.system'):
                    self.add(node.lineno, "HIGH", "unsafe-subprocess",
                             f"Call to subprocess/os.system-like: {ast.unparse(node.func)}",
                             "Use subprocess.run with args list and shell=False; sanitize inputs.")
        except Exception:
            pass
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        # detect crypto usage like Crypto.Cipher.AES.MODE_ECB
        try:
            attr_full = ast.unparse(node)
            if 'MODE_ECB' in attr_full or '.MODE_ECB' in attr_full:
                self.add(node.lineno, "HIGH", "weak-crypto-ecb",
                         "ECB mode used in symmetric encryption (deterministic).",
                         "Use GCM or CBC with random IVs and authentication (AES-GCM).")
        except Exception:
            pass
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # record simple assignments for naive taint
        targets = [ast.unparse(t) for t in node.targets]
        try:
            value = ast.unparse(node.value)
        except Exception:
            value = ''
        for t in targets:
            self.assignments[t] = value
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module and ('flask' in node.module.lower() or 'django' in node.module.lower()):
            # we will later inspect for DEBUG config via regex
            self.add(node.lineno, "LOW", "framework-usage",
                     f"Imports from framework: {node.module}",
                     "Check framework configuration for DEBUG/SECRET_KEY exposure.")
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        prev = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = prev

# File scanning logic

def scan_python_source(path: str) -> List[Dict[str, Any]]:
    try:
        with open(path, 'r', encoding='utf-8') as f:
            src = f.read()
    except Exception:
        return [{"line": 0, "severity": "ERROR", "type": "read-error", "message": "Failed to read file."}]

    findings = []
    # regex checks
    for i, line in enumerate(src.splitlines(), start=1):
        # SQL via string concatenation heuristic
        if SQL_PATTERN.search(line) and ('+' in line or '%' in line or 'format(' in line):
            findings.append({"line": i, "severity": "HIGH", "type": "sql-injection",
                             "message": "SQL-like keyword used in concatenation or formatting - possible SQL injection.",
                             "suggestion": "Use parameterized queries (cursor.execute(query, params)) or ORM placeholders.",
                             "code": line.strip()})
        # os.system pattern
        if re.search(r"\bos\.system\(|\bsubprocess\.Popen\(|\bsubprocess\.call\(|\bsubprocess\.run\(", line):
            findings.append({"line": i, "severity": "HIGH", "type": "unsafe-subprocess",
                             "message": "Shell/subprocess invocation detected. Ensure shell=False and sanitize inputs.",
                             "suggestion": "Use subprocess.run([...], shell=False) and avoid building shell strings.",
                             "code": line.strip()})
        # detect yaml.load without Loader
        if re.search(r"yaml\.load\(", line) and 'Loader=' not in line:
            findings.append({"line": i, "severity": "HIGH", "type": "unsafe-deserialization",
                             "message": "yaml.load() called without specifying a safe Loader.",
                             "suggestion": "Use yaml.safe_load() instead of yaml.load().",
                             "code": line.strip()})
        # eval/exec in-line
        if re.search(r"\beval\(|\bexec\(|\bexecfile\(", line):
            findings.append({"line": i, "severity": "HIGH", "type": "insecure-eval-exec",
                             "message": "Use of eval/exec detected.",
                             "suggestion": "Avoid eval/exec; use parsers or ast.literal_eval for safe literals.",
                             "code": line.strip()})
        # hardcoded secrets heuristics
        for rx in SECRET_REGEXES:
            m = rx.search(line)
            if m:
                findings.append({"line": i, "severity": "HIGH", "type": "hardcoded-secret",
                                 "message": "Possible hardcoded secret or API key.",
                                 "suggestion": "Move secrets to environment variables or a secret manager.",
                                 "code": line.strip()})
        # weak hash
        if re.search(r"\b(hashlib\.|import\s+hashlib|from\s+hashlib\s+import)", line, re.I):
            if any(w in line.lower() for w in WEAK_HASHES):
                findings.append({"line": i, "severity": "MEDIUM", "type": "weak-crypto",
                                 "message": "Weak hash algorithm usage (MD5/SHA1).",
                                 "suggestion": "Use hashlib.sha256 or stronger; for passwords use bcrypt/argon2.",
                                 "code": line.strip()})
        # unvalidated redirect (flask redirect with request.args)
        if re.search(r"redirect\(|flask\.redirect\(|HttpResponseRedirect\(|django\.shortcuts\.redirect\(", line) and 'request.args' in line:
            findings.append({"line": i, "severity": "MEDIUM", "type": "unvalidated-redirect",
                             "message": "Redirect using user input detected.",
                             "suggestion": "Validate target URLs or use a mapping of allowed redirects.",
                             "code": line.strip()})

    # AST-based deeper checks
    try:
        tree = ast.parse(src)
        vf = VulnerabilityFinder(src)
        vf.visit(tree)
        findings.extend(vf.findings)
    except SyntaxError as e:
        findings.append({"line": e.lineno or 0, "severity": "ERROR", "type": "syntax-error",
                         "message": str(e), "suggestion": "Fix syntax errors before scanning.", "code": ""})

    return findings

# Scan an extracted project directory

def scan_project_dir(base_dir: str, run_dependency_audit: bool=False) -> Dict[str, Any]:
    report = {"files": {}, "summary": {"total_files": 0, "total_findings": 0}}
    py_files = []
    for root, dirs, files in os.walk(base_dir):
        for f in files:
            if f.endswith('.py'):
                py_files.append(os.path.join(root, f))
    report['summary']['total_files'] = len(py_files)

    for p in py_files:
        findings = scan_python_source(p)
        report['files'][os.path.relpath(p, base_dir)] = findings
        report['summary']['total_findings'] += len(findings)

    # Entropy-based secret detection for all files
    secrets = []
    for root, dirs, files in os.walk(base_dir):
        for f in files:
            fp = os.path.join(root, f)
            try:
                data = open(fp, 'rb').read()
                ent = file_entropy(data)
                if ent > 4.0 and b'-----BEGIN' not in data:  # high entropy heuristic, ignore certs
                    secrets.append({"file": os.path.relpath(fp, base_dir), "entropy": ent})
            except Exception:
                continue
    report['high_entropy_files'] = secrets

    # Optional: run pip-audit if requested and available
    if run_dependency_audit:
        try:
            # run pip-audit in the project directory (requires pip-audit installed)
            proc = subprocess.run(["pip-audit", "-f", "json"], cwd=base_dir, capture_output=True, text=True, timeout=60)
            if proc.returncode == 0 and proc.stdout:
                report['dependencies'] = {"pip_audit": proc.stdout}
            else:
                report['dependencies'] = {"error": proc.stderr or proc.stdout}
        except Exception as e:
            report['dependencies'] = {"error": str(e)}

    return report

# -------------------- API Endpoints --------------------

class ScanRequest(BaseModel):
    project_path: Optional[str] = None
    run_dependency_audit: Optional[bool] = False


@app.post('/scan')
async def scan_endpoint(project_path: Optional[str] = Form(None), run_dependency_audit: Optional[bool] = Form(False), run_external_tools_flag: Optional[bool] = Form(False), archive: Optional[UploadFile] = File(None)):
    """Accept either an uploaded zip archive of a project (form file), or a server-side path (dangerous - use carefully).
    Returns a JSON vulnerability report.
    """
    if archive is None and not project_path:
        raise HTTPException(status_code=400, detail="Provide either an uploaded zip archive (archive) or a project_path.")

    with tempfile.TemporaryDirectory() as tmpdir:
        base_dir = tmpdir
        # if archive provided, extract
        if archive:
            if not archive.filename.endswith('.zip'):
                raise HTTPException(status_code=400, detail="Only zip archives are supported for uploads.")
            archive_path = os.path.join(tmpdir, archive.filename)
            contents = await archive.read()
            with open(archive_path, 'wb') as f:
                f.write(contents)
            try:
                with zipfile.ZipFile(archive_path, 'r') as z:
                    z.extractall(tmpdir)
            except zipfile.BadZipFile:
                raise HTTPException(status_code=400, detail="Uploaded file is not a valid zip archive.")
        else:
            # using a server-side path - copy files into tmpdir
            if not os.path.exists(project_path):
                raise HTTPException(status_code=400, detail="project_path does not exist on server.")
            # for safety, perform a shallow copy of files
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

        # Optionally run external scanners (best-effort). This can be slow; the
        # caller should only enable it when desired. Results are included under
        # the `external_tool_results` key.
        # Determine whether to run external tools: explicit flag or env var
        auto_run = os.environ.get('AUTO_RUN_EXTERNAL_TOOLS', '0') == '1'
        run_tools = bool(run_external_tools_flag) or auto_run
        report['summary']['external_tools_requested'] = run_tools
        report['summary']['external_tools_available'] = []
        report['summary']['external_tools_skipped'] = []
        report['summary']['external_tools_run_count'] = 0
        # Provide recommendations metadata (installed flag and URL)
        report['summary']['external_tool_recommendations'] = []
        for t in RECOMMENDED_TOOLS:
            exe = t.get('cmd', [None])[0]
            installed = bool(exe and shutil.which(exe))
            report['summary']['external_tool_recommendations'].append({
                'name': t.get('name'), 'url': t.get('url'), 'installed': installed
            })

        if run_tools:
            try:
                ext_results = run_external_tools(base_dir)
                report['external_tool_results'] = ext_results
                # summarize
                for k, v in ext_results.items():
                    if v.get('error'):
                        report['summary']['external_tools_skipped'].append(k)
                    else:
                        report['summary']['external_tools_available'].append(k)
                        report['summary']['external_tools_run_count'] += 1
            except Exception as e:
                report['external_tool_results'] = {"error": str(e)}
        # Add simple remediation suggestions summary
        remediation = {
            "insecure-eval-exec": "Replace eval/exec with safe parsers or ast.literal_eval. Validate inputs.",
            "unsafe-subprocess": "Use subprocess.run([...], shell=False). Sanitize inputs or avoid shell usage.",
            "sql-injection": "Use parameterized queries or ORM placeholders instead of string concatenation.",
            "hardcoded-secret": "Move secrets to environment variables, .env (gitignored), or secret manager like AWS Secrets Manager.",
            "unsafe-deserialization": "Use safe loaders (yaml.safe_load) and avoid untrusted pickles (pickle.loads).",
            "weak-crypto-ecb": "Use authenticated modes like AES-GCM and ensure IVs are random and unique.",
            "weak-crypto": "Use SHA-256 or better. For passwords, use bcrypt/argon2 with salt.",
            "unvalidated-redirect": "Whitelist redirect targets or map short names to URLs rather than using raw user input.",
        }
        report['remediation_suggestions'] = remediation
        return JSONResponse(report)


@app.get('/health')
async def health():
    return {"status": "ok"}


if __name__ == '__main__':
    uvicorn.run('python_vuln_scanner:app', host='0.0.0.0', port=8000, reload=True)
