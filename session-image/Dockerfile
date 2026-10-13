# Jarvis 2 session image: the base (session-image/base/: tools, harnesses, entrypoint, supervisor, carried over from
# Jarvis 1's session image) with Jarvis 2's machine side in front of it. jarvis2-machine is the entry point: it makes the machine's key pairs, waits
# for the core's init (which prints them), takes the core's key from its Fly config (the core sets it), checks the succession cert, restores the predecessor's snapshot, pulls the secrets,
# then execs the base's entrypoint. The base is pinned by digest in BASE below; moving it is a visible commit (the
# images workflow's pin job writes it after building a changed session-image/base/, and builds this image from that
# new base in the same run through --build-arg BASE).
ARG BASE=ghcr.io/de0ch/jarvis2-session:base-sha-9d171d5edcd0@sha256:d4becffc95fdc162cd2bf8872d66e9588ec846ce7213c0ae899d2c4f2f91d98f
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY machine/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/jarvis2-machine .

FROM ${BASE}
COPY --from=build /out/jarvis2-machine /usr/local/bin/jarvis2-machine
# task templates (tasks/<name>/, router/tasks.go): a task line's machine runs one of these instead of a harness;
# the image digest in the line's cert fixes which code that is
COPY tasks/ /opt/jarvis2/tasks/
# jarvis2-request: a session asks Deyao for something that needs his Face ID (an Inbox request, router/inbox.go)
COPY --chmod=755 session-image/bin/jarvis2-request /usr/local/bin/jarvis2-request
USER root
# Only vouched inputs shape a machine (docs/DESIGN.md "Inputs to a machine"):
#  - the image's own ENV, recorded here, is the env jarvis2-machine keeps (everything the machine's config adds
#    besides the core's key and the router's address is dropped at boot: machine/vouch.go cleanEnv);
#  - the OpenClaw runtime bundle is pinned by sha256, not only by URL.
RUN mkdir -p /opt/jarvis2 && env | grep -Ev '^(HOSTNAME|HOME|PWD|OLDPWD|SHLVL|_|TERM|USER|LOGNAME|SHELL)=' | sort > /opt/jarvis2/image.env
COPY session-image/openclaw-runtime.json /opt/jarvis2/openclaw-runtime.json
COPY --chmod=755 session-image/bin/openclaw /usr/local/bin/openclaw
# the one command the core runs through Fly (core/fly.go initPath): no arguments; it prints this machine's
# public keys and lets boot go on
RUN printf '#!/bin/sh\nexec /usr/local/bin/jarvis2-machine init\n' > /usr/local/bin/jarvis2-init \
 && chmod 755 /usr/local/bin/jarvis2-init \
 && ln -s /usr/local/bin/jarvis2-machine /usr/local/bin/jarvis2 \
 && chmod -R a+rX,go-w /opt/jarvis2/tasks
USER claude
ENTRYPOINT ["/usr/local/bin/jarvis2-machine", "boot"]
