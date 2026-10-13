# Watch check runner (k8s/apps/watch.yaml). Build context = this directory (.github/workflows/services.yml).
# The tools a check script may use: bash, curl, python3 (stdlib), git, openssl, jq. The tests run in the build.
FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates git openssl jq \
    && rm -rf /var/lib/apt/lists/*
COPY runner.py test_runner.py /app/
RUN cd /app && python3 -m unittest -v test_runner
USER 65532:65532
WORKDIR /app
CMD ["python3", "-u", "/app/runner.py"]
