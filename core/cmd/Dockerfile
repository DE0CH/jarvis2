# One kernel part's image (core/kernel/README.md): built from core/ with --build-arg PART=<core/cmd dir>, e.g. notary,
# identity-signer, spawner. Production builds carry no build tags (the fakefly tag gives the spawner an in-memory Fly
# and secrets an in-memory GitHub: CI only). The tests run in the images workflow's test job, not here.
FROM golang:1.25-bookworm AS build
ARG PART
WORKDIR /src
COPY . .
RUN test -n "$PART" && test -f "cmd/$PART/main.go" && CGO_ENABLED=0 go vet ./kernel/... "./cmd/$PART" && \
    CGO_ENABLED=0 go build -trimpath -o /out/part "./cmd/$PART"

# no shell, no package manager: the binary and CA roots only (the spawner calls Fly's API, secrets GitHub's)
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/part /part
USER nonroot
ENTRYPOINT ["/part"]
