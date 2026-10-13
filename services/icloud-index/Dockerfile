# iCloud Drive index (k8s/apps/icloud-index.yaml, icloud_index/server.py). Build context = this
# directory (.github/workflows/services.yml). trixie: its SQLite (>= 3.43) has FTS5
# contentless_delete. The unit tests run in the build, so a broken index never ships.
FROM python:3.13-slim-trixie
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1
# not RCLONE_*: rclone reads every RCLONE_* env var as a flag (RCLONE_VERSION = --version)
ARG RCLONE_RELEASE=v1.75.1
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl unzip ffmpeg antiword catdoc 7zip libimage-exiftool-perl \
 && curl -fsSL -o /tmp/rclone.zip https://downloads.rclone.org/${RCLONE_RELEASE}/rclone-${RCLONE_RELEASE}-linux-amd64.zip \
 && unzip -j /tmp/rclone.zip '*/rclone' -d /usr/local/bin && rm /tmp/rclone.zip \
 && ln -sf /usr/bin/7zz /usr/local/bin/7z \
 && apt-get purge -y unzip && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 1001 -s /bin/bash indexer
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY icloud_index /app/icloud_index
COPY tests /app/tests
RUN cd /app && python -m unittest discover -s tests
USER indexer
WORKDIR /app
CMD ["python", "-m", "icloud_index.server"]
