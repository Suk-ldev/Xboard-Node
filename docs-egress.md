# Egress modes

xboard-node supports two independent egress layers that can be combined:

| Layer | What it does | Config |
|-------|--------------|--------|
| **WARP** | Cloudflare WARP (userspace WireGuard) — clean v6, CF-grade v4 | `warp:` / `WARP_*` env, admin panel |
| **VPNGate** | Residential (家宽) exits via the sdise/vpngate VLESS relay — clean residential v4 | `vpngate:` / `VG_*` env, admin panel |

Panel communication never goes through either tunnel; only user traffic does.

## Modes

| WARP | VPNGate | Behavior |
|------|---------|----------|
| `off` | `off` | Direct egress (default, unchanged behavior) |
| `v6` | `off` | Only IPv6 via WARP; v4 direct |
| `off` | `all` | All v4 egress via a residential exit |
| `v6` | `all` | v4 via residential exit, v6 via WARP |
| `all` | — | Everything via WARP (cannot be combined with vpngate) |

The `all + all` combination is rejected: WARP would swallow the residential
exit.

## VPNGate residential exit

Node exits ride the [sdise/vpngate](https://github.com/sdise/vpngate)
subscription: one VLESS+TLS+WS link per line, each routing through a fixed
entry (`saas.sin.fan:443`) whose WS path selects the volunteer node
(`/fdip=sstp://vpn:vpn@<host>:<port>?ed=2560`). No OpenVPN, no netns, no
`/dev/net/tun` — the kernel treats every link as a plain VLESS outbound and
the entry bridges to the volunteer node via SSTP.

Hard-won entry requirements (verified against the live entry):

- **SNI and WS Host must both be `snip.edgeoneai.cc.cd`** — presenting
  `saas.sin.fan` as SNI gets a 403.
- **ALPN must be `http/1.1`** for WS links (h3/h2 breaks the handshake).
- **The Go default `Go-http-client/1.1` User-Agent gets 403-challenged** by
  the Cloudflare frontend; a browser UA passes. xboard-node sends one
  automatically.
- The upstream raw files carry an unexpanded `{{EMAIL_...}}` UUID placeholder;
  the real entry UUID is bundled (entry validates it).

### Health loop

A loopback-only SOCKS probe inbound (`127.0.0.1:64510`, no auth) is generated
alongside the vpngate outbound. Every 30s the node requests
`https://my.ippure.com/v1/info` through it and folds the answer into health:

- probe fails twice in a row → switch to the next candidate (avoiding the
  last 16 used nodes),
- exit is no longer residential or its fraud score exceeds the ceiling →
  switch,
- the subscription re-downloads every 3h (same cadence as upstream).

Node switches restart the kernel process config (sing-box cannot add
outbounds on hot reload) — brief, usually < 1s.

### Seeding via environment

```bash
VG_MODE=all                 # off (default) | all
VG_SUB_URL=...              # subscription URL (default: upstream sdise raw)
VG_RESIDENTIAL_ONLY=1       # default on
VG_MAX_FRAUD=30             # 0 disables
```

The same settings live in `config.yml` under `vpngate:`. **After first boot
the admin panel owns this state** (`egress.json` in the config dir); env and
config only seed the initial values.

## WARP

Unchanged from the previous docs: `WARP_MODE` (`off`/`all`/`v6`),
`WARP_LICENSE_KEY`, `WARP_ENDPOINT`, `WARP_STATE_DIR`. Account state is
persisted under `<config_dir>/warp/node-<id>.json` — mount a volume there, CF
rate-limits re-registration from datacenter IPs. Panel-defined custom routes
keep priority over WARP in every mode.

## Admin panel

Set `ADMIN_PORT` (or `-admin-port`) to expose the built-in control panel:

- secret base path + password, generated on first boot and **logged once**,
- exit mode selection (WARP × VPNGate, validated combinations),
- subscription URL / residential-only / fraud ceiling / country filters,
- node pinning, manual switch, immediate subscription refresh,
- WARP device reset (re-register), panel password change.

All state persists in `<config_dir>/egress.json`. Mutating API calls need the
`X-Panel-Password` header; the panel page itself is served only under the
secret path (everything else 404s).

## Compose

`docker-compose.yml` in the repo root is a ready-to-use compose file: host
network, one `./data` volume (config + WARP state + vpngate cache + panel
credentials), all env vars wired through `.env`.

```bash
cp .env.example .env    # fill in API_HOST / API_KEY / NODE_ID (+ optional egress)
docker compose up -d
docker logs xboard-node 2>&1 | grep "generated credentials"
```

## Caveats

- VPNGate nodes are volunteer-operated and third-party relayed — treat the
  exit as untrusted (same warning as upstream); do not route sensitive
  traffic through it. Residential exits are for IP-reputation-sensitive
  destinations (streaming, registration, search).
- WARP egress IP is shared across many users; some sites show CAPTCHAs.
- Enabling WARP constitutes acceptance of Cloudflare's ToS.
