# syntax=docker/dockerfile:1

# Build stage: Checkmarx-approved base (Maia Apps blocks golang:*-alpine on containers-critical).
FROM chainguard/wolfi-base:latest AS build
RUN apk add --no-cache go ca-certificates-bundle
ENV CGO_ENABLED=0 GOOS=linux GOTOOLCHAIN=auto
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
# version.go embeds VERSION; both sit at the root because go:embed cannot read
# outside its own package directory.
COPY VERSION version.go ./
# --build-arg VERSION=... overrides the VERSION file.
ARG VERSION=
RUN V="${VERSION:-$(tr -d ' \t\r\n' < VERSION)}" && test -n "$V" && \
    go build -trimpath -ldflags "-s -w -X main.version=${V}" -o /out/mcp-oauth-proxy ./cmd/mcp-oauth-proxy

FROM scratch
# Public CA roots: verify Entra ID's OIDC metadata and JWKS endpoints, Microsoft
# Graph, and any https upstream. Without these every outbound call fails.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/mcp-oauth-proxy /mcp-oauth-proxy
USER 65532:65532
EXPOSE 8080 9090
ENV CONFIG_FILE=/etc/mcp-proxy/config.yaml
ENTRYPOINT ["/mcp-oauth-proxy"]
