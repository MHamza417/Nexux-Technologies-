FROM python:3.12-slim

WORKDIR /app

ENV DATABASE_PATH=/data/db.sqlite3
ENV DJANGO_DEBUG=false
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements-prod.txt .

RUN pip install --no-cache-dir -r requirements-prod.txt

RUN groupadd --system app && useradd --system --gid app --home-dir /app app \
    && mkdir -p /data /app/logs \
    && chown -R app:app /data /app

COPY --chown=app:app . .

USER app

EXPOSE 5000

VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health/', timeout=3)"]

CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "60"]