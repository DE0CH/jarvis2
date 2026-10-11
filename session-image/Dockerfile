# Jarvis 2 session image: Jarvis 1's session image (tools, harnesses, entrypoint, supervisor) with Jarvis 2's
# machine side in front of it. jarvis2-machine is the entry point: it makes the machine's key pairs, waits
# for the core's init (which prints them), takes the core's key from its Fly config (the core sets it), checks the succession cert, restores the predecessor's snapshot, pulls the secrets,
# then execs Jarvis 1's entrypoint. The base is pinned by digest; moving it is a visible commit.
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY machine/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/jarvis2-machine .

FROM ghcr.io/de0ch/claude-sessions:sha-d8dda24b0a99@sha256:e29ba0b11a8789b338a873b91dbbf2c4e9662d0ed60d30688005c4d6c12a7b0a
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
#  - Jarvis 1's restore-snapshot would fetch unsigned state from the Storage Box whenever a store holds its
#    credentials: here it does nothing (the predecessor's state comes only from the snapshot the cert names);
#  - the OpenClaw runtime bundle is pinned by sha256, not only by URL.
RUN mkdir -p /opt/jarvis2 && env | grep -Ev '^(HOSTNAME|HOME|PWD|OLDPWD|SHLVL|_|TERM|USER|LOGNAME|SHELL)=' | sort > /opt/jarvis2/image.env \
 && printf '#!/bin/sh\necho "[restore-snapshot] Jarvis 2: nothing to do (jarvis2-machine restores only the snapshot the cert names)"\nexit 0\n' > /usr/local/bin/restore-snapshot \
 && chmod 755 /usr/local/bin/restore-snapshot
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
