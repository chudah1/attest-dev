# Multi-stage build: compile a minimal static binary, then run in distroless.

FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /attest ./cmd/attest

FROM gcr.io/distroless/static-debian12
COPY --from=builder /attest /attest
EXPOSE 8080
ENTRYPOINT ["/attest"]
