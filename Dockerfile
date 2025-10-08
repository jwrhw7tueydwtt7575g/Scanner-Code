# Minimal Dockerfile for scanner services
# Use a stable, small python base and keep installs minimal by default.
FROM python:3.11-slim-bullseye

ARG INSTALL_DEP_CHECK=0
ARG INSTALL_REQUIREMENTS=0
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install minimal system packages
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip git \
    && if [ "${INSTALL_DEP_CHECK}" = "1" ]; then apt-get install -y --no-install-recommends openjdk-21-jre-headless unzip; fi \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user and tools dir
RUN groupadd -r scanner && useradd -r -g scanner scanner \
    && mkdir -p /home/scanner/tools /app/uploads \
    && chown -R scanner:scanner /home/scanner /app
ENV PATH="/home/scanner/.local/bin:/home/scanner/tools:${PATH}"

# Copy requirements if present. Installing requirements is optional to keep
# default builds fast (set INSTALL_REQUIREMENTS=1 to enable installation).
COPY requirements.txt /app/requirements.txt
RUN python3 -m pip install --upgrade pip setuptools wheel \
    && if [ "${INSTALL_REQUIREMENTS}" = "1" ] && [ -f /app/requirements.txt ]; then echo "Installing requirements.txt (this may be large)" && python3 -m pip install --no-cache-dir -r /app/requirements.txt; else echo "Skipping requirements.txt installation"; fi \
    && python3 -m pip install --no-cache-dir uvicorn fastapi pip-audit

# Install nuclei (small binary) but don't fail the build if fetching fails.
# Use the releases/latest/download path to avoid parsing GitHub API output.
RUN set -eux; \
    NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei-linux-amd64.zip"; \
    curl -fSL "$NUCLEI_URL" -o /tmp/nuclei.zip || true; \
    if [ -f /tmp/nuclei.zip ]; then \
        unzip /tmp/nuclei.zip -d /tmp || true; \
        if [ -f /tmp/nuclei ]; then mv /tmp/nuclei /usr/local/bin/nuclei || true; fi; \
        chmod +x /usr/local/bin/nuclei || true; \
        rm -f /tmp/nuclei.zip || true; \
    fi

# Conditionally install OWASP Dependency-Check (requires Java)
RUN if [ "${INSTALL_DEP_CHECK}" = "1" ]; then \
      DC_VER="8.4.0"; \
      curl -L "https://github.com/jeremylong/DependencyCheck/releases/download/v${DC_VER}/dependency-check-${DC_VER}-release.zip" -o /tmp/dc.zip || true; \
      if [ -f /tmp/dc.zip ]; then unzip /tmp/dc.zip -d /opt/ || true; rm -f /tmp/dc.zip || true; chmod +x /opt/dependency-check/bin/dependency-check.sh || true; printf '#!/bin/sh\n/opt/dependency-check/bin/dependency-check.sh "$@"\n' > /usr/local/bin/dependency-check || true; chmod +x /usr/local/bin/dependency-check || true; fi; \
    else echo "Skipping dependency-check installation"; fi

# Copy app and set permissions
COPY . /app
RUN chown -R scanner:scanner /app || true

# install entrypoint and make executable
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh || true

USER scanner
EXPOSE 8000 8001 8002 8003

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["uvicorn", "python_vuln_scanner:app", "--host", "0.0.0.0", "--port", "8000"]