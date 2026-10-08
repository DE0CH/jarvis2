FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go test ./... && CGO_ENABLED=0 go build -trimpath -o /out/core .

# no shell, no package manager: the binary and CA roots only
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/core /core
USER nonroot
ENTRYPOINT ["/core"]
