# Root-level Dockerfile for Railway (GitHub integration builds from repo root).

FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /attest ./cmd/attest

FROM gcr.io/distroless/static-debian12
COPY --from=builder /attest /attest
EXPOSE 8080
ENTRYPOINT ["/attest"]
