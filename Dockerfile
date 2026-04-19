FROM python:3.12-slim

WORKDIR /app

# System deps (minimal; libsodium is bundled with pynacl wheels)
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the library + registry
COPY oversight_core/ ./oversight_core/
COPY registry/ ./registry/

# Persistent data volume
VOLUME ["/data"]
ENV OVERSIGHT_DB=/data/oversight-registry.sqlite

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/health').read()" || exit 1

CMD ["uvicorn", "registry.server:app", "--host", "0.0.0.0", "--port", "8765"]
