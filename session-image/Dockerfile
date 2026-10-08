# Jarvis 2 session image: Jarvis 1's session image (tools, harnesses, entrypoint, supervisor) with Jarvis 2's
# machine side in front of it. jarvis2-machine is the entry point: it makes the machine's key pairs, waits
# for the core's init, checks the succession cert, restores the predecessor's snapshot, pulls the secrets,
# then execs Jarvis 1's entrypoint. The base is pinned by digest; moving it is a visible commit.
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY machine/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/jarvis2-machine .

FROM ghcr.io/de0ch/claude-sessions:sha-d8dda24b0a99@sha256:e29ba0b11a8789b338a873b91dbbf2c4e9662d0ed60d30688005c4d6c12a7b0a
COPY --from=build /out/jarvis2-machine /usr/local/bin/jarvis2-machine
USER root
# the core's fixed init entry point (core/fly.go initPath): no arguments, it only tells boot to go on
RUN printf '#!/bin/sh\nexec /usr/local/bin/jarvis2-machine init\n' > /usr/local/bin/jarvis2-init \
 && chmod 755 /usr/local/bin/jarvis2-init \
 && ln -s /usr/local/bin/jarvis2-machine /usr/local/bin/jarvis2
USER claude
ENTRYPOINT ["/usr/local/bin/jarvis2-machine", "boot"]
