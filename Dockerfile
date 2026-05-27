FROM python:3.11-slim

ARG DCLOUD_GIT_REVISION=unbekannt
ARG DCLOUD_GIT_BRANCH=unbekannt

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DCLOUD_CONFIG=/data/config.yml \
    DCLOUD_GIT_REVISION=${DCLOUD_GIT_REVISION} \
    DCLOUD_GIT_BRANCH=${DCLOUD_GIT_BRANCH}

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git php-cli php-cgi \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r requirements.txt

COPY . .

RUN printf "%s\n" "$DCLOUD_GIT_REVISION" > /app/.dcloud_git_revision \
    && printf "%s\n" "$DCLOUD_GIT_BRANCH" > /app/.dcloud_git_branch \
    && chmod +x /app/scripts/docker-entrypoint.sh

VOLUME ["/data"]
EXPOSE 8787/tcp 6881/udp 445/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/healthz', timeout=3).read()"

ENTRYPOINT ["/app/scripts/docker-entrypoint.sh"]
CMD ["python", "-m", "dcloud_client.main", "--config", "/data/config.yml"]
