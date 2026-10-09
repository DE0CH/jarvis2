# Jarvis 2 session image: Jarvis 1's session image (tools, harnesses, entrypoint, supervisor) with Jarvis 2's
# machine side in front of it. jarvis2-machine is the entry point: it makes the machine's key pairs, waits
# for the core's init (which prints them), checks the core against the built-in master key, checks the succession cert, restores the predecessor's snapshot, pulls the secrets,
# then execs Jarvis 1's entrypoint. The base is pinned by digest; moving it is a visible commit.
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY machine/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/jarvis2-machine .

FROM ghcr.io/de0ch/claude-sessions:sha-d8dda24b0a99@sha256:e29ba0b11a8789b338a873b91dbbf2c4e9662d0ed60d30688005c4d6c12a7b0a
COPY --from=build /out/jarvis2-machine /usr/local/bin/jarvis2-machine
# the master public key: a core is trusted when the master key signed its key in recovery. The production
# image takes keys/master.pub; the test image (jarvis2-session-test) the public TEST key.
ARG MASTER_PUB=keys/master.pub
COPY ${MASTER_PUB} /etc/jarvis2/master.pub
# task templates (tasks/<name>/, router/tasks.go): a task line's machine runs one of these instead of a harness;
# the image digest in the line's cert fixes which code that is
COPY tasks/ /opt/jarvis2/tasks/
USER root
# the one command the core runs through Fly (core/fly.go initPath): no arguments; it prints this machine's
# public keys and lets boot go on
RUN printf '#!/bin/sh\nexec /usr/local/bin/jarvis2-machine init\n' > /usr/local/bin/jarvis2-init \
 && chmod 755 /usr/local/bin/jarvis2-init \
 && ln -s /usr/local/bin/jarvis2-machine /usr/local/bin/jarvis2 \
 && chmod -R a+rX,go-w /opt/jarvis2/tasks
USER claude
ENTRYPOINT ["/usr/local/bin/jarvis2-machine", "boot"]
