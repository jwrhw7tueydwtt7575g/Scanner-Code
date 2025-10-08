# lang_router_fastapi.py
"""
Language Router FastAPI

Usage:
  1) python -m venv .venv && source .venv/bin/activate
  2) pip install fastapi uvicorn python-multipart
  3) uvicorn lang_router_fastapi:app --reload --port 8004

Endpoints:
  POST /detect     - form fields:
                       - git_url (optional) : HTTPS/SSH git repo URL
                       - archive  (optional): uploaded zip file of repo
                       - redirect (optional, bool): if true, issue HTTP redirect to chosen scanner URL
                     Returns JSON with language scores and redirect_url (or performs redirect).

  GET  /health     - simple health check
"""
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
import tempfile
import zipfile
import os
import subprocess
import shutil
import re
from typing import Dict, Tuple, List, Optional

app = FastAPI(title="Language Router")

# mapping from extension -> language key
EXTENSION_MAP = {
    # Python
    ".py": "python",
    # JS/TS
    ".js": "javascript", ".jsx": "javascript", ".ts": "javascript", ".tsx": "javascript",
    # Java
    ".java": "java",
    # C / C++
    ".c": "c_cpp", ".h": "c_cpp", ".cpp": "c_cpp", ".cc": "c_cpp", ".cxx": "c_cpp", ".hpp": "c_cpp",
    # Go
    ".go": "go",
    # Ruby
    ".rb": "ruby",
    # PHP
    ".php": "php",
    # Rust
    ".rs": "rust",
    # C#
    ".cs": "csharp",
    # Kotlin/Scala
    ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala",
    # HTML/CSS
    ".html": "markup", ".htm": "markup", ".css": "markup",
    # Shell
    ".sh": "shell",
    # Dockerfile
    "Dockerfile": "docker",
    # Makefile
    "Makefile": "makefile",
    # JSON/YAML (config)
    ".json": "json", ".yml": "yaml", ".yaml": "yaml",
}

# Default language-to-URL mapping (change these to match your actual scanner endpoints)
LANGUAGE_URL_MAP = {
    "python": "/scan/python",         # route in your scanner service for Python
    "javascript": "/scan/javascript",
    "java": "/scan/java",
    "c_cpp": "/scan/cpp",
    "go": "/scan/go",
    "ruby": "/scan/ruby",
    "php": "/scan/php",
    "rust": "/scan/rust",
    "csharp": "/scan/csharp",
    "kotlin": "/scan/kotlin",
    "scala": "/scan/scala",
    "markup": "/scan/markup",
    "shell": "/scan/shell",
    "docker": "/scan/docker",
    "makefile": "/scan/makefile",
    "json": "/scan/config",
    "yaml": "/scan/config",
}

SHEBANG_PY = re.compile(r"^#!.*\\bpython[0-9.]*\\b")
SHEBANG_SH = re.compile(r"^#!.*\\b(sh|bash|zsh)\\b")
SHEBANG_NODE = re.compile(r"^#!.*\\b(node)\\b")

def _is_text_file(path: str) -> bool:
    # naive check: try reading small chunk as text
    try:
        with open(path, 'rb') as f:
            chunk = f.read(1024)
            if b'\0' in chunk:
                return False
            # otherwise assume text
            return True
    except Exception:
        return False

def analyze_repo_stats(root_dir: str) -> Tuple[Dict[str, int], Dict[str, int]]:
    """
    Walk the repo and compute:
      - language_counts: count of files per detected language key
      - ext_counts: count of file extensions encountered (for diagnostic)
    """
    language_counts: Dict[str, int] = {}
    ext_counts: Dict[str, int] = {}
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for fname in filenames:
            full = os.path.join(dirpath, fname)
            # skip common binary-ish files quickly
            if not _is_text_file(full):
                continue
            name_lower = fname
            ext = os.path.splitext(fname)[1].lower()
            if fname in EXTENSION_MAP:
                lang = EXTENSION_MAP[fname]
            elif ext in EXTENSION_MAP:
                lang = EXTENSION_MAP[ext]
            else:
                lang = None

            # Shebang detection for extensionless scripts
            if lang is None and ext == "":
                try:
                    with open(full, 'r', encoding='utf-8', errors='ignore') as fh:
                        first = fh.readline()
                        if SHEBANG_PY.search(first):
                            lang = "python"
                        elif SHEBANG_NODE.search(first):
                            lang = "javascript"
                        elif SHEBANG_SH.search(first):
                            lang = "shell"
                except Exception:
                    pass

            # fallback: try to inspect content heuristics
            if lang is None:
                try:
                    with open(full, 'r', encoding='utf-8', errors='ignore') as fh:
                        sample = fh.read(4096)
                        if "import java." in sample or "public class" in sample:
                            lang = "java"
                        elif "using System;" in sample or "namespace " in sample:
                            lang = "csharp"
                        elif "#include <" in sample or "int main(" in sample:
                            lang = "c_cpp"
                        elif "package main" in sample and "func main()" in sample:
                            lang = "go"
                        elif "fn main()" in sample:
                            lang = "rust"
                except Exception:
                    pass

            if lang:
                language_counts[lang] = language_counts.get(lang, 0) + 1
            ext_counts[ext or fname] = ext_counts.get(ext or fname, 0) + 1

    return language_counts, ext_counts

def choose_primary_language(language_counts: Dict[str,int]) -> Optional[str]:
    if not language_counts:
        return None
    # pick language with highest count; tie-breaker by deterministic sort
    items = sorted(language_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return items[0][0]

def clone_git_repo(git_url: str, dest: str, timeout_sec: int = 60) -> None:
    """Clone using git via subprocess. Raises HTTPException on failure."""
    try:
        # shallow clone --depth 1 to be faster
        res = subprocess.run(["git", "clone", "--depth", "1", git_url, dest],
                             capture_output=True, text=True, timeout=timeout_sec)
        if res.returncode != 0:
            raise HTTPException(status_code=400, detail=f"git clone failed: {res.stderr.strip() or res.stdout.strip()}")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="git clone timed out")

@app.post("/detect")
async def detect_language(
    git_url: Optional[str] = Form(None),
    archive: Optional[UploadFile] = File(None),
    redirect: Optional[bool] = Form(False),
):
    """
    Provide either git_url (HTTPS/SSH) or upload a .zip archive of the repository.
    If redirect=true and a primary language is detected, the API will return a 307 redirect to the language URL.
    Otherwise returns JSON with language counts and candidate URLs.
    """
    if not git_url and not archive:
        raise HTTPException(status_code=400, detail="Provide git_url or upload an archive file (zip).")

    tmpdir = tempfile.mkdtemp(prefix="langscan_")
    repo_dir = os.path.join(tmpdir, "repo")
    os.makedirs(repo_dir, exist_ok=True)

    try:
        # extract archive or clone git
        if archive:
            # only zip supported for upload
            if not archive.filename.lower().endswith(".zip"):
                raise HTTPException(status_code=400, detail="Uploaded archive must be a .zip file.")
            zpath = os.path.join(tmpdir, archive.filename)
            contents = await archive.read()
            with open(zpath, "wb") as f:
                f.write(contents)
            try:
                with zipfile.ZipFile(zpath, 'r') as z:
                    z.extractall(repo_dir)
            except zipfile.BadZipFile:
                raise HTTPException(status_code=400, detail="Uploaded file is not a valid zip archive.")
        else:
            # clone git
            clone_git_repo(git_url, repo_dir)

        # Analyze repository
        language_counts, ext_counts = analyze_repo_stats(repo_dir)
        primary = choose_primary_language(language_counts)

        # Build response
        language_scores = sorted(language_counts.items(), key=lambda kv: -kv[1])

        # Map to target URLs (could be absolute URLs if your scanners are separate services)
        candidate_urls = []
        for lang, cnt in language_scores:
            url = LANGUAGE_URL_MAP.get(lang, f"/scan/other?lang={lang}")
            candidate_urls.append({"language": lang, "count": cnt, "url": url})

        result = {
            "primary_language": primary,
            "language_scores": language_scores,
            "candidates": candidate_urls,
            "extension_counts": ext_counts
        }

        if redirect and primary:
            redirect_url = LANGUAGE_URL_MAP.get(primary, f"/scan/other?lang={primary}")
            # If you want absolute redirect (assuming same host/port), use request.url_for in a real app.
            return RedirectResponse(url=redirect_url, status_code=307)

        return JSONResponse(result)
    finally:
        # cleanup
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass

@app.get("/health")
async def health():
    return {"status": "ok"}
