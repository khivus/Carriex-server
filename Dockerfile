FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY pyproject.toml README.md requirements.lock .env.example ./
COPY src/ ./src/
RUN pip install --no-cache-dir -r requirements.lock \
    && pip install --no-cache-dir --no-deps . \
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
CMD ["python", "-m", "src.production", "--host", "0.0.0.0", "--port", "5000"]
