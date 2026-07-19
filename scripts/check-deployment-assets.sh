#!/usr/bin/env sh
# Fail closed on the static deployment supply-chain contract before an image build.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$PROJECT_ROOT"

fail() {
    printf '%s\n' "deployment-assets: $*" >&2
    exit 1
}

require_line() {
    grep -Fqx "$1" "$2" || fail "missing required $2 entry: $1"
}

# Keep the image build intentionally small and obvious.
for requirement in \
    'FROM golang:1.26-alpine AS builder' \
    'RUN apk add --no-cache nodejs npm' \
    'COPY . .' \
    'RUN cd web && npm ci && npm run build' \
    'ARG VERSION=devel' \
    'RUN CGO_ENABLED=0 go build \' \
    '-X main.version=$VERSION' \
    'FROM alpine:3.23' \
    'RUN apk add --no-cache ca-certificates tzdata \' \
    'LABEL org.opencontainers.image.version="$VERSION"' \
    'USER 65532:65532' \
    'ENTRYPOINT ["./kfadapter"]'; do
    grep -Fq -- "$requirement" Dockerfile || fail "Dockerfile is missing $requirement"
done
if grep -Eq 'REVISION|SOURCE_DATE_EPOCH|org\.opencontainers\.image\.(source|revision|licenses)|@sha256:' Dockerfile; then
    fail "Dockerfile contains obsolete release machinery"
fi

# Publishing is a normal GHCR build on version-tag pushes.
release_workflow=.github/workflows/release-image.yml
for requirement in \
    '      - "v*"' \
    '  packages: write' \
    '      - uses: actions/checkout@v4' \
    '      - uses: docker/login-action@v3' \
    '      - uses: docker/build-push-action@v6' \
    '        run: echo "VERSION=${GITHUB_REF_NAME#v}" >> "$GITHUB_ENV"' \
    '          push: true' \
    '            ghcr.io/oshinop/kfadapter:${{ env.VERSION }}' \
    '            ghcr.io/oshinop/kfadapter:latest' \
    '            VERSION=${{ env.VERSION }}'; do
    require_line "$requirement" "$release_workflow"
done
if grep -Eq 'branches:|workflow_dispatch|id-token|concurrency:|cosign|imagetools|BUILDX_|REVISION|SOURCE_DATE_EPOCH|provenance:|attests:|platforms:' "$release_workflow"; then
    fail "release workflow contains obsolete publishing machinery"
fi

verification_workflow=.github/workflows/deployment-verify.yml
require_line '        run: docker build --build-arg VERSION=0.0.0-ci -t kfadapter:ci .' "$verification_workflow"
if grep -Eq 'setup-buildx-action|BUILDX_|REVISION|SOURCE_DATE_EPOCH' "$verification_workflow"; then
    fail "deployment verification must use the simple Docker build"
fi

# Production Compose runs the published image directly.
require_line '    image: ghcr.io/oshinop/kfadapter:latest' compose.yaml
# The external-consumer template must retain only the reusable account-bound URL
# shape, never a credential disclosure flow.
require_line "    kfadapter: 'http-file://127.0.0.1:10809/sub/<43-char-account-binding>'" deploy/dae/config.dae.template
if grep -Eiq 'one[-[:space:]]+use|reveal|capabilit' deploy/dae/config.dae.template; then
    fail "external consumer template contains subscription disclosure wording"
fi
# Secrets and reverse-engineering inputs must never enter the Docker context.
for exclusion in .git/ .github/ .env .env.\* state/ backups/ account_cred\* credentials/ secrets/ deploy/ internal/web/static/; do
    require_line "$exclusion" .dockerignore
done

# Deployment assets are templates/configuration, never credential stores.
if grep -R -n -E -- '-----BEGIN( [A-Z]+)? PRIVATE KEY-----|(^|[[:space:]])(password|token|authKey|encryptKey)[[:space:]]*:' Dockerfile compose.yaml deploy .dockerignore; then
    fail "deployment assets contain credential material"
fi

printf '%s\n' "deployment-assets: passed"
