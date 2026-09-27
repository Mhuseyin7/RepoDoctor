FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
RUN groupadd --system repodoctor && useradd --system --gid repodoctor --create-home repodoctor
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --upgrade pip && python -m pip install ".[server]"
USER repodoctor
EXPOSE 8000
CMD ["repodoctor", "serve", "--host", "0.0.0.0", "--port", "8000"]
