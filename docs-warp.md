# WARP egress mode

Route node egress traffic through **Cloudflare WARP** (userspace WireGuard —
no `NET_ADMIN`, no `/dev/net/tun`, no kernel module needed). Panel
communication never goes through the tunnel; only user traffic does.

## Modes

| `WARP_MODE` | Behavior |
|-------------|----------|
| `off` (default) | Direct egress, unchanged behavior |
| `all` | Every destination goes through WARP |
| `v6` | Only IPv6 destinations go through WARP; IPv4 stays direct |

`v6` is for IPv4-only servers: the free WARP account includes an IPv6 tunnel
address, so the node can reach IPv6-only sites (and offer v6 to clients)
without native IPv6 connectivity.

Panel-defined custom routes keep priority over WARP in every mode — a panel
rule sending a domain `direct` still bypasses WARP.

## Environment variables

| Variable | Meaning |
|----------|---------|
| `WARP_MODE` | `all` / `v6` / `off` |
| `WARP_LICENSE_KEY` | Bind a WARP+ subscription (optional) |
| `WARP_ENDPOINT` | Comma-separated ingress overrides, e.g. `162.159.192.1:2408,162.159.193.1:2408` |
| `WARP_STATE_DIR` | Account state directory (default `/etc/xboard-node/warp`) |

The same settings exist as `warp:` in `config.yml` — see `config.yml.example`.

## Account persistence

On first start the node registers a WARP device (via the wgcf protocol
implementation) and stores the account — private key, addresses, peer key,
`client_id` — as JSON under the state dir:

```
/etc/xboard-node/warp/node-<node_id>.json
```

**Mount a volume there.** Rebuilding the container without the volume means
re-registering, and Cloudflare rate-limits registration from datacenter IPs
heavily (429s). With the volume, restarts reuse the stored device silently.

To import an account registered elsewhere (e.g. by wgcf CLI), set
`warp.account_file` to a JSON file with the same shape.

## Multi-node

Each node registers its **own** device (`node-<id>.json` per node). Sharing
one device between nodes breaks routing: Cloudflare replies only to the most
recent source port.

## Kernel notes

- **sing-box**: WARP is generated as a WireGuard *endpoint* (the outbound was
  removed in sing-box 1.13). `route.final` becomes `warp` in `all` mode; a
  `resolve` action fills destination IPs so the private-range blocklist and
  panel CIDR rules keep working. `v6` mode keeps `final: direct` and adds an
  `ip_version: 6 → warp` rule.
- **xray**: WARP is a `wireguard` outbound with `noKernelTun: true`. The
  bind dials the CF ingress through xray's dispatcher, so an anti-loop rule
  (UDP to CF ingress ranges via `direct`) is inserted before user rules —
  without it the tunnel deadlocks.
- User hot-updates are unaffected: only routes/inbounds hot-swap, the
  WireGuard tunnel is never rebuilt.

## Compose

`warp-compose.yml` in the repo root is a ready-to-use compose file: host
network, `./data` volume, WARP env vars wired through `.env`.

```bash
cp .env.example .env    # fill in API_HOST / API_KEY / NODE_ID / WARP_MODE
docker compose -f warp-compose.yml up -d
```

## Caveats

- Egress IP is shared across many WARP users; some sites show CAPTCHAs or
  block CF ranges.
- Userspace WireGuard costs noticeable CPU on high-throughput nodes.
- Enabling WARP constitutes acceptance of Cloudflare's ToS (the same terms
  wgcf requires on registration).
