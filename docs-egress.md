# Egress modes

xboard-node supports two independent egress layers that can be combined:

| Layer | What it does | Config |
|-------|--------------|--------|
| **WARP** | Cloudflare WARP (userspace WireGuard) — clean v6, CF-grade v4 | `warp:` / `WARP_*` env, admin panel |
| **VPNGate** | Residential (家宽) exits via a real OpenVPN tunnel to the volunteer node — no third-party relay, no quota | `vpngate:` / `VG_*` env, admin panel |

Panel communication never goes through either tunnel; only user traffic does.

## Modes

| WARP | VPNGate | Behavior |
|------|---------|----------|
| `off` | `off` | Direct egress (default, unchanged behavior) |
| `v6` | `off` | Only IPv6 via WARP; v4 direct |
| `off` | `all` | All v4 user traffic via the OpenVPN tunnel |
| `v6` | `all` | v4 via tunnel, v6 via WARP |
| `all` | — | Everything via WARP (cannot be combined with vpngate) |

The `all + all` combination is rejected: WARP would swallow the tunnel exit.

## VPNGate residential exit (OpenVPN)

The server list comes from the official VPNGate API
(`https://www.vpngate.net/api/iphone/` — CSV with an embedded OpenVPN client
config per row). xboard-node:

1. fetches and filters the list (home-broadband only by default: the
   `public-vpn-*` / `219.100.37.0/24` university relay pool is excluded),
2. supervises an **openvpn child process** connected to the selected node
   (fixed `xboard-vg` tun device, `--pull-filter` blocks the pushed
   redirect-gateway/DNS so the host routing is untouched),
3. installs a high-metric default route through the tunnel,
4. runs a loopback **SOCKS5 proxy on 127.0.0.1:64520** whose sockets are
   pinned to the tunnel device (SO_BINDTODEVICE) — the kernel's `vpngate`
   outbound dials this proxy, so user traffic rides the tunnel while panel
   sync and the node's own listeners stay on the physical interface.

**Node switches restart only the openvpn child** — the proxy kernel is never
reloaded and user connections through the node inbound are unaffected.

Requirements: the `openvpn` binary (baked into the Docker image; install it
for bare-metal runs), `/dev/net/tun` and `NET_ADMIN` (add
`--device /dev/net/tun --cap-add NET_ADMIN` to docker run — the compose file
already has both).

### Health loop

Every 30s the node requests `https://my.ippure.com/v1/info` **through the
same SOCKS proxy** (probe path ≡ user path by construction):

- probe fails twice in a row → switch to the next candidate (avoiding the
  last 16 used nodes),
- exit fraud score exceeds the ceiling → switch,
- the server list re-downloads every hour; the top candidates are tried in
  speed order until one completes the handshake (SoftEther nodes are flaky —
  expect a few attempts).

### Seeding via environment

```bash
VG_MODE=all                 # off (default) | all
VG_SUB_URL=...              # server-list URL (default: official API)
VG_RESIDENTIAL_ONLY=1       # default on (exclude the relay pool)
VG_MAX_FRAUD=0              # probe-enforced ceiling; 0 disables
```

The same settings live in `config.yml` under `vpngate:`. **After first boot
the admin panel owns this state** (`egress.json` in the config dir); env and
config only seed the initial values.

## WARP

Unchanged: `WARP_MODE` (`off`/`all`/`v6`), `WARP_LICENSE_KEY`,
`WARP_ENDPOINT`, `WARP_STATE_DIR`. Account state is persisted under
`<config_dir>/warp/node-<id>.json` — mount a volume there, CF rate-limits
re-registration from datacenter IPs. Panel-defined custom routes keep
priority over WARP in every mode.

## Admin panel

Set `ADMIN_PORT` (or `-admin-port`) to expose the built-in control panel:

- secret base path + password, generated on first boot and **logged once**;
  both are runtime-changeable in the panel's 安全 card (path change takes
  effect immediately, old URL 404s),
- exit mode selection (WARP × VPNGate, validated combinations),
- server-list URL / residential-only / fraud ceiling / country filters,
- node pinning, manual switch, immediate list refresh,
- WARP device reset (re-register), panel password change.

All state persists in `<config_dir>/egress.json`. Mutating API calls need the
`X-Panel-Password` header; the panel page itself is served only under the
secret path (everything else 404s).

## Compose

`docker-compose.yml` in the repo root is a ready-to-use compose file: host
network, one `./data` volume, tun device + NET_ADMIN, all env vars wired
through `.env`.

```bash
cp .env.example .env    # fill in API_HOST / API_KEY / NODE_ID (+ optional egress)
docker compose up -d
docker logs xboard-node 2>&1 | grep "generated credentials"
```

## Caveats

- VPNGate nodes are volunteer-operated; treat the exit as untrusted (same
  warning as upstream). Residential exits are for IP-reputation-sensitive
  destinations.
- SoftEther handshake failures are normal on first connect; the retry loop
  walks candidates automatically. If *every* node fails with
  `Connection reset` at TLS start, the node's network (or your ISP) is
  blocking the egress — check from a different host.
- WARP egress IP is shared across many users; some sites show CAPTCHAs.
- Enabling WARP constitutes acceptance of Cloudflare's ToS.
