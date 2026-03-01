# Multi-stage build for OPNBoss
# Build stage: Install dependencies and build wheels
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files and source code
COPY pyproject.toml ./
COPY opn_boss/ ./opn_boss/

# Install dependencies to a temporary location
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir --prefix=/install .

# Runtime stage: Minimal production image
FROM python:3.12-slim

LABEL org.opencontainers.image.title="OPNBoss" \
      org.opencontainers.image.description="OPNSense Analyzer & Recommendation Service" \
      org.opencontainers.image.vendor="Jason Hagerty" \
      org.opencontainers.image.source="https://github.com/jasonthagerty/opn_boss"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create non-root user for security
RUN groupadd -r opnboss && useradd -r -g opnboss -u 1000 opnboss

WORKDIR /app

# Copy source and config example
COPY pyproject.toml ./
COPY opn_boss/ ./opn_boss/
COPY config/config.yaml.example ./config/config.yaml.example

# Copy pre-built dependencies from builder
COPY --from=builder /install /usr/local

# Install the package (creates console scripts)
RUN pip install --no-cache-dir .

# Create runtime directories
RUN mkdir -p /app/config /app/data && \
    chown -R opnboss:opnboss /app

# Health check — polls the firewalls API
COPY --chmod=755 <<'EOF' /usr/local/bin/healthcheck.py
#!/usr/bin/env python3
"""Health check for OPNBoss container."""
import sys
import urllib.request
import urllib.error

def main() -> int:
    try:
        with urllib.request.urlopen("http://localhost:8080/api/firewalls", timeout=5) as r:
            return 0 if r.getcode() == 200 else 1
    except urllib.error.URLError as e:
        print(f"Cannot connect: {e.reason}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Health check failed: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
EOF

USER opnboss

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["python3", "/usr/local/bin/healthcheck.py"]

ENTRYPOINT ["opnboss"]
CMD ["serve"]
