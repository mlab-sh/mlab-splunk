# mlab-splunk

Splunk app (`mlab/`) that enriches events with [mlab.sh](https://mlab.sh) (file hashes, URLs, CVEs, public IPs) and sends alerts to ir.mlab.sh.
Splunk Enterprise 9.4+ / 10.x; works with Enterprise Security (the alert action is an adaptive response).

Full guide, with Splunk basics, search examples and troubleshooting: [docs/GUIDE.md](docs/GUIDE.md).

## Search command

```
... | stats count by file_hash | mlab type=hash | search mlab_verdict=known_malicious
```

| `type` | Default `field` | Adds | mlab quota |
|---|---|---|---|
| `hash` | `file_hash` | `mlab_verdict`, `mlab_family`, `mlab_file_name`, `mlab_trust`, … | none |
| `url` | `url` | `mlab_host`, `mlab_findings`, `mlab_severities` | none |
| `cve` | `cve` | `mlab_cvss_score`, `mlab_epss_score`, `mlab_in_kev`, `mlab_kev_date_added`, … (vuln.mlab.sh) | none |
| `ip` | `src` | `mlab_country_code`, `mlab_as`, `mlab_tor`, `mlab_proxy`, … (public IPs only) | ip |

Every enriched result also gets `mlab_type` and `mlab_value`. Multivalue fields are skipped: `mvexpand` them first.
The command runs on the search head only, caches results 24h in `$SPLUNK_HOME/var/run/splunk/mlab-cache.db`, and pauses a kind for an hour when it hits its quota (a warning shows in the search).

## Alerts

Four scheduled searches, **shipped disabled**. Point the macros at your data first (Settings → Advanced search → Search macros):

| Saved search | Macro (default) | Severity |
|---|---|---|
| mlab - Known malicious file | `mlab_hash_events` (`index=* file_hash=*`) | high |
| mlab - Suspicious URL | `mlab_url_events` (`index=* url=*`) | medium |
| mlab - Tor exit node | `mlab_ip_events` (`index=* tag=authentication action=failure src=*`) | low |
| mlab - Known exploited CVE | `mlab_cve_events` (`index=* cve=*`) | critical |

Each one runs every 15 minutes over the last 15 and aggregates by indicator before calling mlab.sh.

## Send to ir.mlab.sh

The **Send to ir.mlab.sh** alert action (`mlab_ir`) creates one ir.mlab.sh alert per result (first 100) via `POST /api/v1/ingest/alert`.

| ir.mlab.sh field | From |
|---|---|
| `title` | result `title` / `rule_name` (ES), else the search name |
| `severity` | result `severity` / `urgency` (ES) if it is info…critical, else the action's severity |
| `external_id` | `event_id` (ES notables) |
| `dedup_key` | `splunk:<search>:<dest or host>[:<mlab_value>]` (repeats collapse into one ir alert) |
| `description` | search name, every result field, `_raw` |
| `tags` | search name + `mitre_technique_id` |
| `observables` | `src`/`dest`/`dvc` (IP or hostname), `file_hash`, `mlab_value`, `url`, `cve`, `file_path`/`file_name`, `host` |

## Install

Copy `mlab/` to `$SPLUNK_HOME/etc/apps/` (search head) and restart Splunk. Then store the secrets (admin):

```sh
# ir.mlab.sh app token (Settings → API keys in ir.mlab.sh), required by mlab_ir
curl -k -u admin https://localhost:8089/servicesNS/nobody/mlab/storage/passwords -d realm=mlab -d name=ir_token -d password=mlab_app_...
# mlab.sh API key, optional (without it, lookups are anonymous with lower quotas)
curl -k -u admin https://localhost:8089/servicesNS/nobody/mlab/storage/passwords -d realm=mlab -d name=api_key -d password=mlab_...
```

Set the ir.mlab.sh URL in the alert action of each search (or once in `mlab/local/alert_actions.conf`: `[mlab_ir]` `param.base_url = https://ir.example.com`).
Users running `| mlab` without the `list_storage_passwords` capability get anonymous lookups.

## Test

```sh
python3 -m unittest discover -s tests   # unit tests, no network
tests/splunk.sh                          # the app inside a running Splunk container (dev stack by default)
tests/appinspect.sh                      # Splunkbase AppInspect (pip install splunk-appinspect)
dev/package.sh                           # builds dist/mlab-<version>.tgz
```

CI runs all three: unit tests, AppInspect, and `tests/splunk.sh` against Splunk 9.4.4 and 10.4.3.

## Dev stack

Splunk 10.4.3 (app mounted live) + ir.mlab.sh. Needs Docker with ~6 GB RAM and `MLAB_IR_LI=<ir.mlab.sh licence>` in `.env` (optionally `MLAB_API_KEY=mlab_...`).

```sh
dev/setup.sh   # everything up, ir.mlab.sh app token and mlab.sh key stored in Splunk
dev/e2e.sh     # unit tests, | mlab on each kind, EICAR over HEC -> saved search -> ir.mlab.sh, dedup, KEV CVE
```

| | URL | Login |
|---|---|---|
| Splunk | http://localhost:8000 | `admin` / `changeme123` |
| ir.mlab.sh | http://localhost:8080 | `admin@localhost` / `adminadmin` |

Python changes are live. After editing `mlab/default/*.conf`, restart Splunk: `docker compose restart splunk`. Settings changed from the UI or REST land in `mlab/local/` (git-ignored).
Tear down: `docker compose down -v`.

## License

MIT, see [LICENSE](LICENSE). `mlab/lib/splunklib` is the [Splunk SDK for Python](https://github.com/splunk/splunk-sdk-python) 2.1.1 (Apache 2.0).
