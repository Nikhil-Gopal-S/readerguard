# ReaderGuard scan image: rebuilds bytes into visible text / fresh PNGs. It never fetches anything.
# Fetch URLs outside this container (readerguard.fetch.fetch); scan the bytes inside it.
#
#   docker build -t readerguard-scan .
#   docker run --rm -i --network none --read-only --tmpfs /tmp:size=512m \
#     --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --memory 2g --cpus 2 \
#     readerguard-scan scan --json --with-text - < upload.pdf
#
# --network none: a parser exploit has nowhere to send anything. No secrets, no volumes with data you care about.
# --read-only + --tmpfs /tmp: the only writable place is /tmp (the worker passes each file through temp files).
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY readerguard ./readerguard
RUN pip install . && rm -rf /src \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin scan

WORKDIR /tmp
USER 10001:10001
ENTRYPOINT ["readerguard"]
CMD ["--help"]
