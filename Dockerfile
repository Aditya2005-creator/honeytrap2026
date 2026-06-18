FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py config.py services.py export.py gunicorn.conf.py healthcheck.py ./
COPY templates/ templates/

RUN mkdir -p /data
ENV DATABASE=/data/attacks.db
ENV PORT=8000

VOLUME /data
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "healthcheck.py"]

CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]
