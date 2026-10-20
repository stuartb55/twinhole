# twinhole

Monitoring, alerts, history, one-way sync and shared management for a pair of
Pi-hole v6 instances. It runs as one container on the Mac Mini.

- **Monitor:** every 30 s it checks each Pi-hole's API, does a real DNS lookup over
  IPv4 and IPv6, and checks blocking state and gravity age.
- **Alerts:** pushed to your ntfy server (set in `.env`), with a matching
  "recovered" message. There are no repeats while a problem lasts, and active alerts
  survive restarts.
- **History:** Pi-hole's 10-minute buckets are kept for 2 years, plus daily top-25
  domains, blocked domains and clients. On first run it imports what each Pi-hole
  still holds (about 90 days).
- **Sync:** main → secondary for groups, domains, adlists, clients, local DNS and
  CNAMEs. You preview the changes, then Apply. The secondary becomes an exact mirror,
  and group membership is matched by group name. Gravity rebuilds on the secondary
  when adlists change.
- **Manage:** edit domains, adlists, local DNS, CNAMEs, clients and groups. Each
  change goes to the main Pi-hole first, then the secondary.
- **Actions:** pause or enable blocking (one or both Pi-holes) and run gravity, with
  live output.

## Alerts

| Condition | Priority |
|---|---|
| API unreachable for 2 checks in a row | urgent (5) |
| DNS lookup fails or takes over 1 s (IPv4 or IPv6), 2 checks in a row | urgent (5) |
| Blocking off for more than 10 min | default (3) |
| Gravity older than 8 days | default (3) |
| Secondary out of sync with main for more than 1 h | default (3) |
| Any of the above recovering | low (2) |

## Running it

Runs under [Lighter](https://formulae.brew.sh/formula/lighter). Your default Docker
context stays as it is; twinhole always targets Lighter explicitly.

```sh
cp .env.example .env        # then edit it
docker --context lighter compose up -d --build
open http://localhost:8053  # or http://<mac-ip>:8053, or the Mac's tailnet address
```

To update after changing the code:

```sh
docker --context lighter compose up -d --build
```

To see what it's doing:

```sh
docker --context lighter logs -f twinhole
```

The database lives in `./data/twinhole.db`, so it survives rebuilds and is included
in Time Machine backups.

### Read-only mode

`ALLOW_WRITES=false` (the default) keeps monitoring, history and the sync preview
working, but refuses Apply, edits, blocking changes and gravity runs. Set it to
`true` and restart (`docker --context lighter compose up -d`) to enable them.

## Things worth knowing

- **Use IP addresses in `.env`.** A passwordless Pi-hole only answers API requests
  addressed to one of its own names (its IP, `pi.hole`, its host name).
- **Local DNS and CNAME changes restart Pi-hole's DNS for about a second.** This is
  Pi-hole's own behaviour. Sync batches them into a single restart, and the 2-check
  debounce means it won't trigger an alert.
- **Nothing in the dashboard requires a login.** Anyone on the LAN or tailnet can use
  it, including making changes once writes are on. Don't expose port 8053 to the
  internet.
- **The DNS check queries `example.com`** through each Pi-hole every 30 s, so those
  lookups appear in the query log, coming from the Mac.
- **twinhole runs only while Lighter does.** Lighter starts at login, but doesn't
  restart itself after a clean shutdown (`lighter start` brings it back).

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
