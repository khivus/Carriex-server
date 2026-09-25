FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir ".[server]" \
    && groupadd --system carriex \
    && useradd --system --gid carriex --no-create-home carriex \
    && mkdir -p /var/lib/carriex \
    && chown carriex:carriex /var/lib/carriex \
    && chmod 700 /var/lib/carriex
USER carriex
EXPOSE 5000
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=3)"
# WebSocket registrations belong to this single process; messages use SQLite.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--worker-class", "gthread", "--threads", "100", "--access-logfile", "-", "--error-logfile", "-", "src.app:app"]
