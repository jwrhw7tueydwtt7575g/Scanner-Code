#!/bin/sh
set -e

# Ensure tools directory exists
mkdir -p /home/scanner/tools
chown scanner:scanner /home/scanner/tools || true

# If nuclei missing, try to fetch again (non-fatal)
if [ ! -x /usr/local/bin/nuclei ]; then
  echo "nuclei binary not found, attempting download..."
  NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei-linux-amd64.zip"
  curl -fSL "$NUCLEI_URL" -o /tmp/nuclei.zip || true
  if [ -f /tmp/nuclei.zip ]; then
    unzip /tmp/nuclei.zip -d /tmp || true
    if [ -f /tmp/nuclei ]; then mv /tmp/nuclei /usr/local/bin/nuclei || true; fi
    chmod +x /usr/local/bin/nuclei || true
    rm -f /tmp/nuclei.zip || true
  fi
fi

# If dependency-check exists in /opt, expose wrapper (should be installed during build when requested)
if [ -f /opt/dependency-check/bin/dependency-check.sh ] && [ ! -x /usr/local/bin/dependency-check ]; then
  printf '#!/bin/sh\n/opt/dependency-check/bin/dependency-check.sh "$@"\n' > /usr/local/bin/dependency-check || true
  chmod +x /usr/local/bin/dependency-check || true
fi

# Execute passed command (usually uvicorn)
exec "$@"
