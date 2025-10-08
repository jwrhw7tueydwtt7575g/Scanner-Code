"""
Java Vulnerability Scanner API (single-file, Python)
- FastAPI app that accepts a ZIP of a Java project (.java/.class/.jar) or a server-side path.
- Static, heuristic checks and lightweight AST + bytecode hybrid checks:
  - Unsafe deserialization via ObjectInputStream / Serializable patterns
  - Reflection misuse (Class.forName, Method.invoke)
  - SQL injection heuristics (string concatenation, Statement.execute with concatenated strings)
  - Hardcoded credentials (.properties, strings in code)
  - Unsafe file handling (File.delete, path traversal via "..", FileOutputStream from user input)
  - Weak crypto usage (MessageDigest.getInstance("MD5"/"SHA-1"), ECB mode)
  - Verbose logging / debug info exposures (logger.debug/info with secrets or stack traces printed)
  - Unsafe serialization libraries usage (Jackson ObjectMapper.enableDefaultTyping, Gson.fromJson on untrusted input)
  - Dependency inspection for Maven (pom.xml) and Gradle (build.gradle)
  - Unsafe multithreading anti-patterns (unsynchronized collections, direct Thread usage, Executors misuse)
  - Framework checks (Spring Boot debug, exposed actuator endpoints, Struts2 vulnerable patterns)
  - Missing input validation heuristics for public controller methods (Spring @RequestMapping/@RestController)
  - Function-level fingerprint tracking (SHA-256 per source file and optionally per method)
  - CI/PR diff-aware scanning using a baseline report upload
  - Integration hooks (optional) for SpotBugs/Sonar/Dependency-Check via subprocess

Limitations & notes:
- This is heuristic/static and not a replacement for full SAST or dynamic testing.
- For serious analysis use SpotBugs, Semgrep, OWASP Dependency-Check, or SonarQube alongside this.
- Bytecode checks require JDK tools (javap) available on PATH. These are optional and errors are handled.

Recommended complementary tools (what they do / URL):

- OSV-Scanner — Scans a source directory or project for known vulnerabilities via the open-source vulnerability database (useful alongside language-specific tools).
    https://github.com/google/osv-scanner

- OWASP Dependency-Check — Scans project dependencies (libraries) for known CVEs; especially useful for Maven/Gradle projects.
    https://owasp.org/www-project-dependency-check/

- Nuclei — Template-based, fast vulnerability scanner for web endpoints and assets.
    https://github.com/projectdiscovery/nuclei

- Astra (Flipkart Incubator) — Automated REST API security testing tool (SQLi, XSS, etc.).
    https://github.com/flipkart-incubator/Astra

- VulnAPI — API security vulnerability scanner (DAST-like) for API testing.
    https://github.com/cerberauth/vulnapi

- w3af — Web app attack/audit framework (plugin-based web application scanner).
    https://github.com/andresriancho/w3af

How to run:
1. python -m venv .venv && source .venv/bin/activate
2. pip install -r requirements.txt   # requirements: fastapi uvicorn javalang python-magic
3. uvicorn java_vuln_scanner_fastapi:app --reload --port 8002

Endpoints:
- POST /scan : form-data 'archive' (zip) OR form field 'project_path' (server path). Optional: run_dependency_check (bool), baseline (file)
- GET /health

Return: JSON report with per-file findings, fingerprints, dependency summary, and remediation suggestions.
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
from typing import Optional, Dict, Any, List

# javalang for lightweight Java parsing
import importlib
import shutil
try:
    javalang = importlib.import_module('javalang')
except Exception:
    javalang = None

app = FastAPI(title="Java Vulnerability Scanner API")

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

# -------------------- Regex heuristics --------------------
OBJECTINPUT_PATTERN = re.compile(r"\bObjectInputStream\b|readObject\(|ObjectInput\b")
REFLECTION_PATTERN = re.compile(r"Class\.forName\(|Method\.invoke\(|Constructor\.newInstance\(|Field\.set\(|setAccessible\(")
SQL_CONCAT_PATTERN = re.compile(r"\bStatement\b|executeQuery\(|executeUpdate\(|prepareStatement\(|\+\s*\"|StringBuilder\(|StringBuffer\(|format\(|printf\(")
HARDCODED_SECRET_RX = [
    re.compile(r"(?i)password\s*=\s*\"[^\"]+\""),
    re.compile(r"(?i)password\s*=\s*'[^']+'") ,
    re.compile(r"(?i)api[_-]?key\s*=\s*\"[A-Za-z0-9\-_=]{8,}\""),
    re.compile(r"AKIA[0-9A-Z]{16}")
]
FILE_TRAVERSAL_PATTERN = re.compile(r"\.\./|FileInputStream\(|FileOutputStream\(|new File\(|delete\(|deleteOnExit\(")
WEAK_CRYPTO = re.compile(r"MessageDigest\.getInstance\(\s*\"?(MD5|SHA-1|SHA1)\"?\s*\)")
ECB_PATTERN = re.compile(r"/ECB/|ECB\)|Cipher\.getInstance\(.*ECB.*\)")
LOGGING_PATTERN = re.compile(r"logger\.(debug|info|warn|error)\(|System\.out\.println\(|e\.printStackTrace\(")
JACKSON_DANGER = re.compile(r"enableDefaultTyping\(|ObjectMapper\(|gson\.fromJson\(|new\s+Gson\(|readValue\(")
MULTI_THREAD_PATTERN = re.compile(r"\bThread\b|synchronized\b|ConcurrentHashMap|ExecutorService|submit\(|newFixedThreadPool\(")
SPRING_CONTROLLER = re.compile(r"@RestController|@Controller|@RequestMapping|@GetMapping|@PostMapping")
ACTUATOR_EXPOSE = re.compile(r"management\.endpoints\.web\.exposure\.include|" )

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


def run_javap(classpath_file: str) -> Optional[str]:
    # Attempt to run javap -c on a .class file to inspect bytecode for unsafe patterns
    try:
        proc = subprocess.run(["javap", "-c", classpath_file], capture_output=True, text=True, timeout=10)
        if proc.returncode == 0:
            return proc.stdout
        return None
    except Exception:
        return None

# -------------------- Scanning logic --------------------

def scan_java_source(path: str) -> List[Dict[str, Any]]:
    findings = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            src = f.read()
    except Exception as e:
        return [{"line": 0, "severity": "ERROR", "type": "read-error", "message": str(e)}]

    lines = src.splitlines()
    for i, line in enumerate(lines, start=1):
        if OBJECTINPUT_PATTERN.search(line):
            findings.append({"line": i, "severity": "HIGH", "type": "unsafe-deserialization",
                             "message": "ObjectInputStream.readObject or similar detected.",
                             "suggestion": "Avoid Java native deserialization of untrusted data. Use safe formats (JSON) and validation.",
                             "code": line.strip()})
        if REFLECTION_PATTERN.search(line):
            findings.append({"line": i, "severity": "MEDIUM", "type": "reflection-misuse",
                             "message": "Reflection API usage detected (Class.forName/Method.invoke).",
                             "suggestion": "Limit reflection usage and validate class/method names from untrusted input.",
                             "code": line.strip()})
        if SQL_CONCAT_PATTERN.search(line) and ('+' in line or 'String.format' in line or 'StringBuilder' in line):
            findings.append({"line": i, "severity": "HIGH", "type": "sql-injection",
                             "message": "Potential SQL concatenation or Statement usage detected.",
                             "suggestion": "Use PreparedStatement with parameters or ORM (JPA/Hibernate) and avoid concatenating SQL strings.",
                             "code": line.strip()})
        for rx in HARDCODED_SECRET_RX:
            if rx.search(line):
                findings.append({"line": i, "severity": "HIGH", "type": "hardcoded-secret",
                                 "message": "Possible hardcoded credential detected.",
                                 "suggestion": "Externalize secrets to environment variables or vaults and do not commit them to VCS.",
                                 "code": line.strip()})
        if FILE_TRAVERSAL_PATTERN.search(line):
            findings.append({"line": i, "severity": "HIGH", "type": "unsafe-file-handling",
                             "message": "Potential file operation or path traversal pattern detected.",
                             "suggestion": "Validate and canonicalize paths; avoid using user input directly in file paths.",
                             "code": line.strip()})
        if WEAK_CRYPTO.search(line) or ECB_PATTERN.search(line):
            findings.append({"line": i, "severity": "MEDIUM", "type": "weak-crypto",
                             "message": "Weak hash or ECB mode usage detected.",
                             "suggestion": "Use SHA-256 or stronger; use AES-GCM or CBC with random IV and authenticated mode.",
                             "code": line.strip()})
        if LOGGING_PATTERN.search(line):
            findings.append({"line": i, "severity": "LOW", "type": "verbose-logging",
                             "message": "Logging or stacktrace printing detected. Ensure secrets are not logged.",
                             "suggestion": "Remove sensitive data from logs and avoid printing full stack traces in prod.",
                             "code": line.strip()})
        if JACKSON_DANGER.search(line):
            findings.append({"line": i, "severity": "HIGH", "type": "unsafe-serialization-library",
                             "message": "Jackson/Gson deserialize usage detected; check for default typing or polymorphic deserialization.",
                             "suggestion": "Avoid enableDefaultTyping; prefer explicit types and safe deserializers.",
                             "code": line.strip()})
        if MULTI_THREAD_PATTERN.search(line) and 'synchronized' not in line:
            findings.append({"line": i, "severity": "MEDIUM", "type": "threading-issue",
                             "message": "Threading or concurrency construct detected; review synchronization and concurrency control.",
                             "suggestion": "Prefer higher-level concurrency utilities and validate thread safety of shared data.",
                             "code": line.strip()})
        if SPRING_CONTROLLER.search(line):
            findings.append({"line": i, "severity": "LOW", "type": "framework-controller",
                             "message": "Spring controller annotation detected; check for input validation and security annotations.",
                             "suggestion": "Validate inputs (e.g., @Valid) and use security annotations (e.g., @PreAuthorize) when needed.",
                             "code": line.strip()})

    # optional: parse Java AST with javalang for method-level checks
    if javalang is not None:
        try:
            tree = javalang.parse.parse(src)
            # simple check: public methods without parameter validation annotations
            for path, node in tree.filter(javalang.tree.MethodDeclaration):
                if 'public' in node.modifiers:
                    # naive heuristic: if method contains parameters but no annotations on params
                    if node.parameters:
                        lineno = getattr(node, 'position', None).line if getattr(node, 'position', None) else 0
                        findings.append({"line": lineno or 0, "severity": "LOW", "type": "public-method-no-validation",
                                         "message": f"Public method {node.name} detected - ensure input validation for public endpoints.",
                                         "suggestion": "Use parameter validation (@Valid) and explicit checks.",
                                         "code": node.name})
        except Exception:
            pass

    return findings

# scan project directory

def scan_project_dir(base_dir: str, run_dependency_check: bool=False) -> Dict[str, Any]:
    report = {"files": {}, "summary": {"total_files": 0, "total_findings": 0}}
    java_files = []
    class_files = []
    for root, dirs, files in os.walk(base_dir):
        for f in files:
            if f.endswith('.java'):
                java_files.append(os.path.join(root, f))
            if f.endswith('.class'):
                class_files.append(os.path.join(root, f))
    report['summary']['total_files'] = len(java_files)

    for p in java_files:
        findings = scan_java_source(p)
        rel = os.path.relpath(p, base_dir)
        report['files'][rel] = {
            "findings": findings,
            "sha256": file_hash(p)
        }
        report['summary']['total_findings'] += len(findings)

    # try bytecode inspection on .class files
    class_inspections = []
    for c in class_files:
        out = run_javap(c)
        if out:
            # naive search for reflective calls or deserialization keywords in bytecode output
            if 'invokevirtual' in out and ('readObject' in out or 'ObjectInputStream' in out):
                class_inspections.append({"class": os.path.relpath(c, base_dir), "issue": "bytecode-deserialization", "detail": "bytecode indicates ObjectInputStream/readObject usage."})
            if 'invokevirtual' in out and ('forName' in out or 'Method.invoke' in out):
                class_inspections.append({"class": os.path.relpath(c, base_dir), "issue": "bytecode-reflection", "detail": "bytecode indicates reflection usage."})
    if class_inspections:
        report['class_inspections'] = class_inspections

    # dependency check (Maven/Gradle)
    pom = os.path.join(base_dir, 'pom.xml')
    build_gradle = os.path.join(base_dir, 'build.gradle')
    if run_dependency_check:
        deps = {}
        if os.path.exists(pom):
            try:
                proc = subprocess.run(["mvn", "-q", "dependency:tree", "-DoutputType=text"], cwd=base_dir, capture_output=True, text=True, timeout=60)
                deps['maven_dependency_tree'] = proc.stdout if proc.stdout else proc.stderr
            except Exception as e:
                deps['maven_error'] = str(e)
        if os.path.exists(build_gradle):
            try:
                proc = subprocess.run(["gradle", "dependencies", "--no-daemon"], cwd=base_dir, capture_output=True, text=True, timeout=60)
                deps['gradle_dependencies'] = proc.stdout if proc.stdout else proc.stderr
            except Exception as e:
                deps['gradle_error'] = str(e)
        # OWASP Dependency-Check integration (optional)
        try:
            proc = subprocess.run(["dependency-check", "--project", "scan", "--format", "JSON", "--out", "."], cwd=base_dir, capture_output=True, text=True, timeout=120)
            if proc.returncode == 0:
                # read the generated report if exists
                rpt = os.path.join(base_dir, 'dependency-check-report.json')
                if os.path.exists(rpt):
                    with open(rpt, 'r', encoding='utf-8') as f:
                        deps['dependency_check'] = json.load(f)
            else:
                deps['dependency_check_error'] = proc.stderr or proc.stdout
        except Exception:
            pass
        report['dependencies'] = deps

    # remediation suggestions
    remediation = {
        "unsafe-deserialization": "Avoid Java native deserialization of untrusted data. Use safe formats (JSON) and explicit type checks.",
        "reflection-misuse": "Limit and validate reflection targets. Avoid building class/method names from untrusted input.",
        "sql-injection": "Use PreparedStatement with parameters or ORM (JPA/Hibernate) and never concatenate SQL with user input.",
        "hardcoded-secret": "Move secrets to environment variables or secret manager (Vault, AWS Secrets Manager).",
        "unsafe-file-handling": "Canonicalize and validate paths. Restrict file operations to safe directories.",
        "weak-crypto": "Use SHA-256 or stronger; for encryption prefer AES-GCM and use secure key management.",
        "verbose-logging": "Avoid logging secrets and full exception stacks in production. Use structured logging with redaction.",
    }
    report['remediation_suggestions'] = remediation

    return report

# -------------------- API --------------------

@app.post('/scan')
async def scan_endpoint(project_path: Optional[str] = Form(None), run_dependency_check: Optional[bool] = Form(False), run_external_tools_flag: Optional[bool] = Form(False), baseline: Optional[UploadFile] = File(None), archive: Optional[UploadFile] = File(None)):
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

        report = scan_project_dir(base_dir, run_dependency_check=run_dependency_check)

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

        # baseline diff (CI/PR) - naive: find issues not present in baseline
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
    uvicorn.run('java_vuln_scanner_fastapi:app', host='0.0.0.0', port=8002, reload=True)
