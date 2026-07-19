FROM golang:1.26-alpine AS builder

RUN apk add --no-cache nodejs npm
WORKDIR /src
COPY . .
RUN cd web && npm ci && npm run build

ARG VERSION=devel
RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags="-s -w -X main.version=$VERSION" \
    -o /kfadapter \
    ./cmd/kfadapter

FROM alpine:3.23

RUN apk add --no-cache ca-certificates tzdata \
    && mkdir -p /kfadapter/data \
    && chown -R 65532:65532 /kfadapter \
    && chmod 0700 /kfadapter/data
WORKDIR /kfadapter
ARG VERSION=devel
LABEL org.opencontainers.image.version="$VERSION"
COPY --from=builder --chown=65532:65532 /kfadapter ./kfadapter
USER 65532:65532
ENTRYPOINT ["./kfadapter"]
