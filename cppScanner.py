"""
C/C++ Vulnerability Scanner API (single-file, Python)
- FastAPI app that accepts a ZIP of a C/C++ project or a server-side path.
- Static, heuristic checks for common memory and format issues:
  - Dangerous functions: strcpy/strcat/gets/sprintf/scanf without width/strncpy misuse
  - Format string vulnerabilities (printf(user_input))
  - Use-after-free / double-free detection (naive, flow-insensitive but line-ordered)
  - Memory leaks: malloc/new without corresponding free/delete (naive)
  - Buffer overflow sinks (gets, gets_s, strcpy into fixed-size buffers)
  - Potential integer overflow in allocation (malloc(sizeof(type) * count) patterns)
  - Integration hooks for cppcheck / clang-tidy (optional) to improve detection
  - File fingerprinting (SHA-256), CI baseline diff mode
  - Remediation suggestions and code snippets for fixes

Limitations:
- This tool uses static regex/heuristics and simple flow tracking. It can produce false positives/negatives.
- For deep analysis use AddressSanitizer (ASAN), Valgrind, Clang Static Analyzer, or commercial SAST tools.

Recommended complementary tools (what they do / URL):

- OSV-Scanner — Scans a source directory or project for known vulnerabilities via the open-source vulnerability database.
    https://github.com/google/osv-scanner

- OWASP Dependency-Check — Scans project dependencies (libraries) for known CVEs. Useful when C/C++ projects use packaged dependencies.
    https://owasp.org/www-project-dependency-check/

- Nuclei — Template-based, fast vulnerability scanner for web endpoints and assets; useful for testing network-exposed services.
    https://github.com/projectdiscovery/nuclei

- Astra (Flipkart Incubator) — Automated REST API security testing tool (SQLi, XSS, etc.).
    https://github.com/flipkart-incubator/Astra

- VulnAPI — API security vulnerability scanner (DAST-style) for API testing.
    https://github.com/cerberauth/vulnapi

- w3af — Classic web application scanner with plugin architecture.
    https://github.com/andresriancho/w3af

How to run:
1. python -m venv .venv && source .venv/bin/activate
2. pip install fastapi uvicorn
3. uvicorn c_cpp_vuln_scanner_fastapi:app --reload --port 8003

API:
- POST /scan : form-data 'archive' (zip) OR form field 'project_path' (server path). Optional form fields: run_static_tools (bool), baseline (file)
- GET /health

Returns JSON report with per-file findings, fingerprints, and remediation suggestions.
"""

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
import tempfile
import zipfile
import os
import re
import hashlib
import subprocess
import json
from typing import Optional, Dict, Any, List, Tuple
import shutil

app = FastAPI(title="C/C++ Vulnerability Scanner API")

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
DANGEROUS_FUNCS = re.compile(r"\b(strcpy|strcat|gets|sprintf|vsprintf|scanf|sscanf|strcpy_s|strcat_s)\b")
GETS_PATTERN = re.compile(r"\bgets\s*\(")
STRCPY_PATTERN = re.compile(r"\bstrcpy\s*\(\s*([A-Za-z_][\w]*)\s*,")
STRCAT_PATTERN = re.compile(r"\bstrcat\s*\(\s*([A-Za-z_][\w]*)\s*,")
SPRINTF_PATTERN = re.compile(r"\bsprintf\s*\(")
SNPRINTF_SAFE = re.compile(r"\b(sn?printf|snprintf_s)\s*\(")
SCANF_PATTERN = re.compile(r"\bscanf\s*\(\s*\"%[sduoxXfFeEgGaAcspn]")
PRINTF_VAR_PATTERN = re.compile(r"\bprintf\s*\(\s*([A-Za-z_][\w\.]*)\s*\)")
MALLOC_PATTERN = re.compile(r"\b(malloc|calloc|realloc)\s*\(")
FREE_PATTERN = re.compile(r"\bfree\s*\(\s*([A-Za-z_][\w]*)\s*\)")
NEW_PATTERN = re.compile(r"\bnew\s+([A-Za-z_][\w<>:]*)")
DELETE_PATTERN = re.compile(r"\bdelete\s*\(\s*([A-Za-z_][\w]*)\s*\)|\bdelete\s+([A-Za-z_][\w]*)")
BUFFER_DECL_PATTERN = re.compile(r"\bchar\s+([A-Za-z_][\w]*)\s*\[\s*(\d+)\s*\]")
ALLOC_SIZE_PATTERN = re.compile(r"malloc\s*\(\s*sizeof\s*\(.*\)\s*\*\s*([A-Za-z_][\w]*)\s*\)")

# -------------------- Utilities --------------------

def file_hash(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

# Simple line-ordered flow analysis for malloc/free/new/delete tracking

def analyze_memory_flow(lines: List[str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Returns (leaks, use_after_free_or_double_free)
    This is a naive analyzer:
      - Tracks allocations by variable name when patterns like ptr = malloc(...) or Type* ptr = new ... are seen.
      - Tracks frees/deletes and notes if a variable is used after free/delete (use-after-free) or freed twice (double-free).
      - If allocation occurs and no corresponding free/delete by end of file, mark as potential leak.
    """
    allocs = {}  # var -> line allocated
    frees = {}   # var -> count of frees
    uses_after_free = []
    allocations = []

    var_assign_pattern = re.compile(r"([A-Za-z_][\w<>:\*\s]*)\s*([A-Za-z_][\w]*)\s*=\s*(.*);")
    malloc_assign = re.compile(r"([A-Za-z_][\w]*)\s*=\s*(malloc|calloc|realloc)\b")
    new_assign = re.compile(r"([A-Za-z_][\w]*)\s*=\s*new\b")
    free_call = re.compile(r"\bfree\s*\(\s*([A-Za-z_][\w]*)\s*\)")
    delete_call = re.compile(r"\bdelete\s*(?:\[\])?\s*(?:\(|\s)+([A-Za-z_][\w]*)\s*(?:\))?")
    var_usage = re.compile(r"\b([A-Za-z_][\w]*)\b")

    for lineno, line in enumerate(lines, start=1):
        # detect allocation via assignment
        m = malloc_assign.search(line)
        if m:
            var = m.group(1)
            allocs[var] = lineno
            allocations.append((var, lineno))
            continue
        m2 = new_assign.search(line)
        if m2:
            var = m2.group(1)
            allocs[var] = lineno
            allocations.append((var, lineno))
            continue
        # detect free/delete
        fm = free_call.search(line)
        if fm:
            var = fm.group(1)
            frees[var] = frees.get(var, 0) + 1
            # double free?
            if frees[var] > 1:
                uses_after_free.append({"line": lineno, "type": "double-free", "var": var, "message": f"Variable {var} freed more than once (double-free)."})
            # mark variable as freed
            allocs.pop(var, None)
            continue
        dm = delete_call.search(line)
        if dm:
            var = dm.group(1)
            frees[var] = frees.get(var, 0) + 1
            if frees[var] > 1:
                uses_after_free.append({"line": lineno, "type": "double-free", "var": var, "message": f"Variable {var} delete called more than once (double-delete)."})
            allocs.pop(var, None)
            continue
        # naive use-after-free: if a var that was freed is referenced later
        for var in list(frees.keys()):
            if re.search(rf"\b{re.escape(var)}\b", line) and not free_call.search(line) and not delete_call.search(line):
                uses_after_free.append({"line": lineno, "type": "use-after-free", "var": var, "message": f"Use of {var} after free/delete detected."})
    # remaining allocs are potential leaks
    leaks = []
    for var, lineno in allocations:
        if var in allocs:
            leaks.append({"line": lineno, "var": var, "type": "memory-leak", "message": f"Allocation to {var} at line {lineno} has no corresponding free/delete detected."})

    return (leaks, uses_after_free)

# scan a single C/C++ source file

def scan_c_cpp_source(path: str) -> List[Dict[str, Any]]:
    findings = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            src = f.read()
    except Exception as e:
        return [{"line": 0, "severity": "ERROR", "type": "read-error", "message": str(e)}]

    lines = src.splitlines()

    # line-based heuristics
    for i, line in enumerate(lines, start=1):
        if GETS_PATTERN.search(line):
            findings.append({"line": i, "severity": "HIGH", "type": "unsafe-input-gets",
                             "message": "Use of gets() detected which is inherently unsafe (no bounds checking).",
                             "suggestion": "Replace gets() with fgets() and ensure buffer sizes are respected.",
                             "code": line.strip()})
        if STRCPY_PATTERN.search(line):
            var = STRCPY_PATTERN.search(line).group(1)
            findings.append({"line": i, "severity": "HIGH", "type": "unsafe-strcpy",
                             "message": f"strcpy into variable '{var}' detected. Buffer overflow risk.",
                             "suggestion": "Use strncpy/snprintf and ensure proper bounds checking.",
                             "code": line.strip()})
        if STRCAT_PATTERN.search(line):
            var = STRCAT_PATTERN.search(line).group(1)
            findings.append({"line": i, "severity": "HIGH", "type": "unsafe-strcat",
                             "message": f"strcat into variable '{var}' detected. Buffer overflow risk.",
                             "suggestion": "Use strncat or track remaining buffer size before concatenation.",
                             "code": line.strip()})
        if SPRINTF_PATTERN.search(line) and not SNPRINTF_SAFE.search(line):
            findings.append({"line": i, "severity": "HIGH", "type": "unsafe-sprintf",
                             "message": "sprintf used without bounds checking (use snprintf).",
                             "suggestion": "Use snprintf with buffer size to avoid overflows.",
                             "code": line.strip()})
        if SCANF_PATTERN.search(line) and '%s' in line:
            findings.append({"line": i, "severity": "HIGH", "type": "unsafe-scanf",
                             "message": "scanf with %s detected without width specifier.",
                             "suggestion": "Specify maximum field width in scanf (e.g., %15s) or use fgets.",
                             "code": line.strip()})
        if PRINTF_VAR_PATTERN.search(line):
            var = PRINTF_VAR_PATTERN.search(line).group(1)
            # heuristic: if printf called with single variable (no format string), potential format string vuln
            findings.append({"line": i, "severity": "HIGH", "type": "format-string-vuln",
                             "message": f"printf called with variable '{var}' as format string - potential format string vulnerability.",
                             "suggestion": "Use printf(\"%s\", var) or otherwise sanitize/validate format strings.",
                             "code": line.strip()})
        if DANGEROUS_FUNCS.search(line) and 'strncpy' not in line and 'snprintf' not in line:
            findings.append({"line": i, "severity": "MEDIUM", "type": "dangerous-function",
                             "message": f"Dangerous function usage detected: {line.strip()}",
                             "suggestion": "Review and replace with safe variants and bounds checks.",
                             "code": line.strip()})
        if ALLOC_SIZE_PATTERN.search(line):
            findings.append({"line": i, "severity": "MEDIUM", "type": "alloc-int-overflow",
                             "message": "Malloc pattern with sizeof * count detected - check for integer overflow in allocation size.",
                             "suggestion": "Validate multiplication results and use overflow-checked allocation helpers.",
                             "code": line.strip()})

    # memory-flow analysis
    leaks, mem_issues = analyze_memory_flow(lines)
    for l in leaks:
        findings.append({"line": l['line'], "severity": "MEDIUM", "type": l['type'], "message": l['message'], "suggestion": "Ensure free() or delete is called for every allocation.", "code": ""})
    for m in mem_issues:
        findings.append({"line": m['line'], "severity": "HIGH", "type": m['type'], "message": m['message'], "suggestion": "Avoid double free; set pointers to NULL after free; validate pointer ownership.", "code": ""})

    # high entropy check for possible embedded binaries or keys
    try:
        data = open(path, 'rb').read()
        ent = 0.0
        if data:
            import math
            freq = [0]*256
            for b in data:
                freq[b] += 1
            L = len(data)
            for f in freq:
                if f:
                    p = f/L
                    ent -= p * math.log2(p)
        if ent > 4.0 and b'ELF' not in data and b'PE' not in data:
            findings.append({"line": 0, "severity": "LOW", "type": "high-entropy-file", "message": f"High-entropy file (entropy={ent:.2f}) - may contain secrets or embedded binary.", "suggestion": "Verify file contents.", "code": ""})
    except Exception:
        pass

    return findings

# scan project directory

def scan_project_dir(base_dir: str, run_static_tools: bool=False) -> Dict[str, Any]:
    report = {"files": {}, "summary": {"total_files": 0, "total_findings": 0}}
    src_files = []
    for root, dirs, files in os.walk(base_dir):
        for f in files:
            if f.endswith(('.c', '.cpp', '.cc', '.cxx', '.h', '.hpp')):
                src_files.append(os.path.join(root, f))
    report['summary']['total_files'] = len(src_files)

    for p in src_files:
        findings = scan_c_cpp_source(p)
        rel = os.path.relpath(p, base_dir)
        report['files'][rel] = {
            "findings": findings,
            "sha256": file_hash(p)
        }
        report['summary']['total_findings'] += len(findings)

    # optional: run cppcheck or clang-tidy if requested and available
    tools = {}
    if run_static_tools:
        try:
            proc = subprocess.run(["cppcheck", "--version"], capture_output=True, text=True, timeout=5)
            if proc.returncode == 0:
                # run a simple cppcheck (suppressing output to console)
                try:
                    proc2 = subprocess.run(["cppcheck", "--enable=all", "--inconclusive", "--xml", "--xml-version=2", base_dir], capture_output=True, text=True, timeout=120)
                    tools['cppcheck_raw_xml'] = proc2.stdout or proc2.stderr
                except Exception as e:
                    tools['cppcheck_error'] = str(e)
        except FileNotFoundError:
            tools['cppcheck'] = "not-installed"
        except Exception as e:
            tools['cppcheck_error'] = str(e)
        # clang-tidy
        try:
            proc = subprocess.run(["clang-tidy", "--version"], capture_output=True, text=True, timeout=5)
            if proc.returncode == 0:
                tools['clang-tidy'] = proc.stdout.strip()
        except FileNotFoundError:
            tools['clang-tidy'] = "not-installed"
        except Exception as e:
            tools['clang-tidy_error'] = str(e)

    report['static_tools'] = tools

    remediation = {
        "unsafe-input-gets": "Replace gets() with fgets(buffer, size, stdin); always check bounds.",
        "unsafe-strcpy": "Use strncpy or preferably use snprintf with explicit buffer sizes and checks.",
        "unsafe-strcat": "Use strncat or check remaining buffer size before concatenation; prefer safer APIs.",
        "unsafe-sprintf": "Replace sprintf with snprintf and pass buffer size.",
        "unsafe-scanf": "Provide width specifiers (e.g., %15s) or use fgets + sscanf for safer parsing.",
        "format-string-vuln": "Do not pass untrusted input as the format string. Use printf(\"%s\", input) or validate/escape format strings.",
        "memory-leak": "Ensure every allocation has a corresponding free/delete in all code paths or use smart pointers (C++ RAII).",
        "use-after-free": "After free(), set pointer to NULL and avoid using freed memory; prefer smart pointers in C++.",
        "double-free": "Do not free/delete the same pointer multiple times; set to NULL after free to avoid accidental reuse.",
        "alloc-int-overflow": "Validate multiplication before calling malloc. Use checked allocation helpers or fail safely.",
    }
    report['remediation_suggestions'] = remediation

    return report

# -------------------- API --------------------

@app.post('/scan')
async def scan_endpoint(project_path: Optional[str] = Form(None), run_static_tools: Optional[bool] = Form(False), run_external_tools_flag: Optional[bool] = Form(False), baseline: Optional[UploadFile] = File(None), archive: Optional[UploadFile] = File(None)):
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

        report = scan_project_dir(base_dir, run_static_tools=run_static_tools)

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

        # baseline diff (CI/PR) - naive
        if baseline:
            try:
                base_contents = await baseline.read()
                baseline_report = json.loads(base_contents.decode('utf-8'))
                base_set = set()
                for f, v in baseline_report.get('files', {}).items():
                    for it in v.get('findings', []):
                        key = (f, it.get('type'), it.get('code'), it.get('line'))
                        base_set.add(key)
                new_issues = []
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
    uvicorn.run('c_cpp_vuln_scanner_fastapi:app', host='0.0.0.0', port=8003, reload=True)
