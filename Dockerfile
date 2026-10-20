# syntax=docker/dockerfile:1
FROM python:3.15-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Chart.js 4.4.1, the official npm build, checked against a pinned SHA-256.
FROM base AS vendor
ARG CHARTJS_URL=https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.js
ARG CHARTJS_SHA256=74401d738dd3e03ee5dfb3b6841210fe2c4ead8a960c4011ca4ba0b78a9fd8f3
RUN python - <<EOF
import hashlib, urllib.request
data = urllib.request.urlopen("${CHARTJS_URL}", timeout=60).read()
digest = hashlib.sha256(data).hexdigest()
assert digest == "${CHARTJS_SHA256}", f"Chart.js checksum mismatch: {digest}"
open("/chart.umd.min.js", "wb").write(data)
EOF

FROM base
WORKDIR /app
COPY requirements.txt .
RUN pip install --require-hashes -r requirements.txt
COPY twinhole ./twinhole
COPY --from=vendor /chart.umd.min.js ./twinhole/static/vendor/chart.umd.min.js
ENV DB_PATH=/data/twinhole.db \
    TZ=Europe/London
EXPOSE 8053
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8053/healthz', timeout=3)"]
CMD ["uvicorn", "twinhole.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8053", "--no-access-log"]
