# built from the repo root: the router + the app's web export (app/dist, made by the workflow first)
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY router/ ./
RUN CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go build -trimpath -o /out/router .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/router /router
COPY web/ /web/
COPY policy/stores.json /policy/stores.json
# task templates, for the Tasks forms (the session image carries its own copy, which is what runs)
COPY tasks/ /tasks/
USER nonroot
ENTRYPOINT ["/router"]
