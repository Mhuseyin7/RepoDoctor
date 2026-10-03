FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
RUN groupadd --system repodoctor && useradd --system --gid repodoctor --create-home repodoctor
COPY pyproject.toml README.md ./
COPY src ./src
COPY alembic.ini ./
COPY migrations ./migrations
COPY docker/entrypoint.sh /usr/local/bin/repodoctor-entrypoint
RUN python -m pip install --upgrade pip && python -m pip install ".[server]"
RUN chmod 755 /usr/local/bin/repodoctor-entrypoint
USER repodoctor
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')"
ENTRYPOINT ["repodoctor-entrypoint"]
