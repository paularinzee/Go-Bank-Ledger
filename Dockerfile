# Build application binary and migration tool
FROM golang:1.24-alpine3.21 AS builder
WORKDIR /src

# Use cache mounts for faster builds
RUN --mount=type=bind,source=go.mod,target=go.mod \
    --mount=type=bind,source=go.sum,target=go.sum \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ledger ./cmd/main.go
RUN GOBIN=/out go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@v4.18.3

# Minimal runtime image
FROM alpine:3.21
WORKDIR /app

# Install timezone data if needed for the app
RUN apk add --no-cache tzdata

COPY --from=builder /out/ledger /usr/local/bin/ledger
COPY --from=builder /out/migrate /usr/local/bin/migrate
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /src/docs ./docs
COPY --from=builder /src/postgres/migrations ./postgres/migrations

# Set permissions during COPY
COPY --chmod=755 docker-entrypoint /usr/local/bin/entrypoint

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    TZ=UTC

RUN sed -i 's/\r$//' /usr/local/bin/entrypoint && \
    adduser -D -u 10001 appuser && \
    chown -R appuser:appuser /app

USER appuser
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint"]