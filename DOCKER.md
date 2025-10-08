# Running Scanners with Docker

Quick steps for Windows PowerShell to build and run all scanner API endpoints using docker-compose.

1. Build and start all services (compose uses build args configured in `docker-compose.yml`):

```powershell
docker compose build
docker compose up -d
```

2. Follow logs for a service (example: python scanner):

```powershell
docker compose logs -f python-scanner
```

3. Run a single scanner container (example: Python scanner):

```powershell
# Build image with Python requirements installed
docker build --build-arg INSTALL_REQUIREMENTS=1 -t edi/python-vuln-scanner:latest .

# Run Python scanner (binds uploads and exposes port 8000)
docker run --rm -p 8000:8000 -v ${PWD}/uploads:/app/uploads -e AUTO_RUN_EXTERNAL_TOOLS=0 edi/python-vuln-scanner:latest
```

Endpoints (when services are running on localhost):

- Python scanner: http://localhost:8000/
- JS scanner: http://localhost:8001/
- Java scanner: http://localhost:8002/
- C/C++ scanner: http://localhost:8003/

Notes:

- The Dockerfile tries to download optional binaries (nuclei) at build time. If download fails during build, the entrypoint will attempt to download them at container start.
- For the Java scanner, dependency-check is installed when build arg INSTALL_DEP_CHECK=1 is passed (this requires Java in the image at build time).
- The containers mount `./uploads` into `/app/uploads` so uploads persist on the host.
