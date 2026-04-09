# Courra-Sec — Multi-stage Docker image
# Works on Linux containers (amd64 / arm64)

FROM python:3.11-slim AS base

WORKDIR /app

# System dependencies (minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (layer-cached)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Create data/log directories and set permissions
RUN mkdir -p data/geolite data/models data/tls logs \
 && chmod -R 755 /app

# Expose ports (Render overrides via PORT env var at runtime)
EXPOSE 5001 5140/udp 5141/tcp

# Run as non-root user for security
RUN useradd -m -u 1000 courra-sec \
 && chown -R courra-sec:courra-sec /app
USER courra-sec

# Health check — uses PORT env var (Render) or falls back to 5001
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import os,urllib.request; urllib.request.urlopen('http://localhost:{}/health'.format(os.environ.get('PORT',5001)))"

# Start with waitress (no interactive browser prompt in container)
# Shell form lets Render's PORT env var be picked up by the Python app
CMD ["python", "courra-sec.py", "--no-browser", "--host", "0.0.0.0"]
