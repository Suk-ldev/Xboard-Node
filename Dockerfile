# Build stage
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags "-s -w \
    -X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo dev) \
    -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -tags "with_quic with_utls with_wireguard with_clash_api" \
    -o xboard-node ./cmd/xboard-node

# Runtime stage — sing-box & xray-core are embedded as Go libraries
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata openvpn iproute2 && \
    ln -s /sbin/openvpn /usr/sbin/openvpn 2>/dev/null || true

COPY --from=builder /build/xboard-node /usr/local/bin/xboard-node

RUN mkdir -p /etc/xboard-node

WORKDIR /etc/xboard-node

# Config can be provided via file mount OR environment variables.
# Env var mode (no config file needed):
#   docker run -d --network=host \
#     -e apiHost=https://panel.example.com \
#     -e apiKey=YOUR_TOKEN \
#     -e nodeID=1 \
#     ghcr.io/suk-ldev/xboard-node:latest
#
# Supported env vars:
#   apiHost  / API_HOST    → panel URL
#   apiKey   / API_KEY     → server token
#   nodeID   / NODE_ID     → node ID
#   nodeType / NODE_TYPE   → node type (optional)
#   kernel   / KERNEL_TYPE → singbox (default) or xray
#   domain   / DOMAIN      → TLS domain (enables auto_tls)
#   certFile / CERT_FILE   → TLS cert path
#   keyFile  / KEY_FILE    → TLS key path
#   logLevel / LOG_LEVEL   → log level
#
# Cloudflare WARP egress (node mode only):
#   WARP_MODE         all | v6 | off (default off)
#   WARP_LICENSE_KEY  optional WARP+ subscription key
#   WARP_ENDPOINT     optional comma-separated ingress overrides
#   WARP_STATE_DIR    optional, default /etc/xboard-node/warp
#
# When WARP_MODE is enabled, mount a volume at /etc/xboard-node so the
# registered WARP device (a JSON file with private keys) survives restarts:
#   docker run -d --network=host -v xboard-data:/etc/xboard-node \
#     -e API_HOST=... -e API_KEY=... -e NODE_ID=1 -e WARP_MODE=all \
#     ghcr.io/suk-ldev/xboard-node:latest
#
# VPNGate residential egress (OpenVPN model) additionally needs:
#   --device /dev/net/tun --cap-add NET_ADMIN
# (openvpn is baked into this image; the tun device + NET_ADMIN are host-side)

ENTRYPOINT ["xboard-node"]
CMD ["-c", "/etc/xboard-node/config.yml"]
