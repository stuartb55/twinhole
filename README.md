# twinhole

Monitoring, alerts, history, one-way sync and shared management for a pair of
Pi-hole v6 instances, in a single container with a web dashboard.

- **Monitor:** every 30 s it checks each Pi-hole's API, does a real DNS lookup over
  IPv4 and IPv6, and checks blocking state and gravity age. Every 5 minutes it
  looks up a random name that can't be cached, to prove the resolver behind each
  Pi-hole (Unbound, say) still recurses, and every hour it checks DNSSEC is being
  validated. The Overview shows each Pi-hole's upstream, its average reply time and
  how much is answered from cache.
- **Alerts:** pushed to an [ntfy](https://ntfy.sh) server, with a matching
  "recovered" message. There are no repeats while a problem lasts, and active alerts
  survive restarts.
- **History:** Pi-hole's 10-minute buckets are kept for 2 years, plus daily top-25
  domains, blocked domains and clients. On first run it imports what each Pi-hole
  still holds (about 90 days).
- **Sync:** main → secondary for groups, domains, adlists, clients, local DNS and
  CNAMEs. You preview the changes, then Apply. The secondary becomes an exact mirror,
  and group membership is matched by group name. Gravity rebuilds on the secondary
  when adlists change. With [auto-sync](#auto-sync) on, it applies the changes itself.
- **Manage:** edit domains, adlists, local DNS, CNAMEs, clients and groups. Each
  change goes to the main Pi-hole first, then the secondary.
- **Actions:** pause or enable blocking (one or both Pi-holes) and run gravity, with
  live output.

## Alerts

| Condition | Priority |
|---|---|
| API unreachable for 2 checks in a row | urgent (5) |
| DNS lookup fails or takes over 1 s (IPv4 or IPv6), 2 checks in a row | urgent (5) |
| Resolver can't look up new names (a random, uncached name fails), 2 checks in a row | urgent (5) |
| DNSSEC not validated (`dnssec-failed.org` resolves when it should fail) | default (3) |
| Blocking off for more than 10 min | default (3) |
| Gravity older than 8 days | default (3) |
| Secondary out of sync with main for more than 1 h | default (3) |
| Auto-sync held changes back for you to review | default (3) |
| Any of the above recovering | low (2) |

## Running it

You need two Pi-hole v6 instances with no web password set, and Docker on a
machine that can reach both of them.

A ready-built image is published to GitHub Container Registry for amd64 and arm64:
`ghcr.io/stuartb55/twinhole`. `latest` is the newest commit on `main`; each commit
is also tagged `sha-<short sha>`, and release tags `vX.Y.Z` give `X.Y.Z` and `X.Y`.

### With Docker Compose

Make a folder with a `.env` (copy [`.env.example`](.env.example) and edit it), a
`data` folder (see [Data](#data) for its ownership on Linux), and this `compose.yml`:

```yaml
services:
  twinhole:
    image: ghcr.io/stuartb55/twinhole:latest
    container_name: twinhole
    restart: unless-stopped
    env_file: .env
    ports:
      - "8053:8053"
    volumes:
      - ./data:/data
    read_only: true
    tmpfs:
      - /tmp
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true

networks:
  default:
    enable_ipv6: true   # for the IPv6 DNS check
```

```sh
docker compose up -d
```

Then open `http://<host>:8053`. To update: `docker compose pull && docker compose up -d`.
To follow the logs: `docker logs -f twinhole`.

If you've cloned this repo, its own `compose.yml` is the same file with a `build:`
line added, so `docker compose up -d --build` runs your local changes instead.

### With `docker run`

```sh
docker run -d --name twinhole --restart unless-stopped \
  --env-file .env -p 8053:8053 -v "$PWD/data:/data" \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
  ghcr.io/stuartb55/twinhole:latest
```

The default Docker bridge network has no IPv6, so with `docker run` either set
`PIHOLE_MAIN_IPV6=off` and `PIHOLE_SECONDARY_IPV6=off`, or attach it to a network
created with `--ipv6`.

### Data

Everything twinhole keeps (history, the event log and active alerts) is in one
SQLite database, `/data/twinhole.db` inside the container. Mount `/data` as a volume
as above so it survives updates and is easy to back up. The container runs with a
read-only root filesystem, so `/data` is the only place it writes.

The app runs as a non-root user, `twinhole` (UID:GID `1000:1000`), so on a Linux
host the data folder must be writable by that user. Create it before the first
start, otherwise Docker creates it owned by root and the app can't open its
database:

```sh
mkdir data && sudo chown 1000:1000 data
```

**Upgrading from an image before this change:** older images ran as root, so on
Linux the existing database files are root-owned. Run `sudo chown -R 1000:1000 data`
once, then pull and restart. To run as a different UID, set `user: "<uid>:<gid>"`
in `compose.yml` (or `--user` with `docker run`) and give the folder to that user.

**On macOS, don't chown the folder.** Docker on a Mac writes bind-mounted files as
your own Mac user, whatever UID the container runs as, so the folder just needs to
belong to you (`mkdir data` is enough). Changing its owner to 1000 locks your user
out, and the app fails with "attempt to write a readonly database".

## Configuration

All settings are environment variables, normally kept in `.env`.
[`.env.example`](.env.example) lists them all with comments; only the two URLs are
required.

| Variable | Default | What it does |
|---|---|---|
| `PIHOLE_MAIN_URL` | (required) | Main Pi-hole, the source of truth, e.g. `http://192.168.1.10` |
| `PIHOLE_SECONDARY_URL` | (required) | Secondary Pi-hole, synced to mirror the main one |
| `PIHOLE_MAIN_NAME`, `PIHOLE_SECONDARY_NAME` | URL host | Names shown in the dashboard and alerts |
| `PIHOLE_MAIN_DNS`, `PIHOLE_SECONDARY_DNS` | URL host, port 53 | `host:port` the DNS check queries |
| `PIHOLE_MAIN_IPV6`, `PIHOLE_SECONDARY_IPV6` | `auto` | IPv6 DNS check: `auto` asks the Pi-hole for its address, `off` skips it, or give an address |
| `NTFY_URL`, `NTFY_TOPIC` | (none) | ntfy server and topic for alerts; leave empty for no alerts |
| `NTFY_TOKEN` | (none) | Access token, if your ntfy server needs one to publish |
| `ALLOW_WRITES` | `false` | See [read-only mode](#read-only-mode) |
| `AUTO_SYNC` | `false` | See [auto-sync](#auto-sync) |
| `TZ` | `Europe/London` | Time zone for daily history and charts |

The rest (check intervals, alert thresholds, history retention) are tuning knobs
with sensible defaults, listed at the bottom of `.env.example`. Restart the
container after changing `.env`.

### Read-only mode

`ALLOW_WRITES=false` (the default) keeps monitoring, history and the sync preview
working, but refuses Apply, edits, blocking changes and gravity runs. Set it to
`true` and restart (`docker compose up -d`) to enable them.

### Auto-sync

`AUTO_SYNC=true` (with `ALLOW_WRITES=true`) makes the background check, every 15
minutes, apply any differences to the secondary itself, as if you'd pressed Apply. It
won't when that looks risky. If a change would delete more than
`AUTO_SYNC_MAX_DELETES` items (default 5), remove an adlist, or copy a main Pi-hole
that looks empty, it leaves everything as it is, sends an alert, and waits for you to
review it on the Sync page. If either Pi-hole can't be read, it does nothing.

## Things worth knowing

- **Use IP addresses in `.env`.** A passwordless Pi-hole only answers API requests
  addressed to one of its own names (its IP, `pi.hole`, its host name).
- **Local DNS and CNAME changes restart Pi-hole's DNS for about a second.** This is
  Pi-hole's own behaviour. Sync batches them into a single restart, and the 2-check
  debounce means it won't trigger an alert.
- **Nothing in the dashboard requires a login.** Anyone who can reach port 8053 can
  use it, including making changes once writes are on. Keep it on your LAN or behind
  a VPN, and don't expose it to the internet.
- **The recursion check looks up names like `twinhole-1a2b3c4d.example.com`**, one per
  Pi-hole every 5 minutes, so they appear in the query log too. NXDOMAIN is the
  expected answer.
- **The DNS check queries `example.com`** (or `DNS_PROBE_DOMAIN`) through each
  Pi-hole every 30 s, so those lookups appear in the query log, coming from the
  machine running twinhole.

## Development

```sh
uv sync
uv run pytest                          # unit tests, against an in-memory fake Pi-hole

scripts/test-piholes.sh up             # two throwaway Pi-hole v6 containers on localhost
uv run pytest -m integration           # the same flows against real Pi-holes
uv run python -m scripts.seed_test_piholes   # sample data and drift for trying the UI
scripts/test-piholes.sh down
```

Run the app locally against the test Pi-holes:

```sh
mkdir -p twinhole/static/vendor && curl -fsSL https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.js \
  -o twinhole/static/vendor/chart.umd.min.js
PIHOLE_MAIN_URL=http://127.0.0.1:18081 PIHOLE_MAIN_ID=t1 PIHOLE_MAIN_DNS=127.0.0.1:15301 \
PIHOLE_SECONDARY_URL=http://127.0.0.1:18082 PIHOLE_SECONDARY_ID=t2 PIHOLE_SECONDARY_DNS=127.0.0.1:15302 \
DB_PATH=/tmp/twinhole.db ALLOW_WRITES=true \
uv run uvicorn twinhole.app:create_app --factory --port 8053
```

Dependencies live in `pyproject.toml` and are pinned, with hashes, in `uv.lock`.
The image installs from `uv.lock` directly, so after changing `pyproject.toml` run
`uv lock` and commit both files. The build fails if they don't match.

Every pull request runs the tests and a test build of the image. Merging to `main`
publishes `latest`; pushing a `v*` tag publishes a versioned image
(`.github/workflows/image.yml`).

### Layout

| File | What it does |
|---|---|
| `twinhole/pihole.py` | Pi-hole v6 API client (including waiting out FTL restarts) |
| `twinhole/dnsprobe.py` | Real DNS lookups |
| `twinhole/monitor.py` | 30 s health checks |
| `twinhole/alerts.py` | Alert state machine and ntfy |
| `twinhole/history.py` | History import, backfill, daily top lists |
| `twinhole/sync.py` | Snapshot, diff and apply |
| `twinhole/services.py` | Sync orchestration, write-through edits, gravity runs |
| `twinhole/app.py` | Web API and background loops |
| `twinhole/static/` | The dashboard (plain HTML/JS, Chart.js) |
