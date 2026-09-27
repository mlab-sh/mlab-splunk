# Guide: the mlab app in Splunk

Everything needed to use, test and troubleshoot the app, with no prior Splunk knowledge.
Every search example below was run on the dev stack (Splunk 10.4.3).

1. [Splunk in 5 minutes](#1-splunk-in-5-minutes)
2. [Dev stack](#2-dev-stack)
3. [The `| mlab` command](#3-the--mlab-command)
4. [Search examples](#4-search-examples)
5. [Scheduled alerts](#5-scheduled-alerts)
6. [Sending to ir.mlab.sh](#6-sending-to-irmlabsh)
7. [Enterprise Security](#7-enterprise-security)
8. [Production install](#8-production-install)
9. [Troubleshooting](#9-troubleshooting)
10. [Repository layout](#10-repository-layout)

---

## 1. Splunk in 5 minutes

| Concept | In plain words |
|---|---|
| **Event** | One indexed log line: `_raw` (raw text), `_time`, `host`, `source`, `sourcetype`. |
| **Index** | Where events are stored (`main` by default). Always filter by index: `index=main`. |
| **Sourcetype** | The data format (`_json`, `WinEventLog`, `squid`…). It decides which fields get extracted. |
| **Fields** | Extracted **at search time**, not at index time. JSON keys become fields directly. |
| **SPL** | The search language: commands chained with `\|`, like a shell pipe. |
| **CIM** | Standard field names (`src`, `dest`, `file_hash`, `url`, `cve`, `user`…). Each product's add-on (TA) maps its fields to the CIM. The mlab app reads CIM names by default. |
| **Search head / indexers** | The search head runs searches and custom commands; indexers store data. `| mlab` runs on the search head (the one with Internet access). |
| **App** | A folder in `$SPLUNK_HOME/etc/apps/`. Here: `mlab/`. |
| **default/ vs local/** | `default/` ships with the app; `local/` is written by Splunk when a setting is changed from the UI or REST API. `local/` always wins; never edit `default/` in production. |
| **Scheduled search / alert** | A saved search run on a cron; when it returns results it triggers **alert actions** (email, script, here `mlab_ir`). |
| **REST API** | Port 8089. Everything the UI does goes through it (`curl -k -u admin:… https://localhost:8089/services/...`). |
| **HEC** | HTTP Event Collector, port 8088: send events as JSON over HTTP. Handy for tests. |

Minimal SPL:

```
index=main sourcetype=_json file_hash=*          <- search (implicitly the "search" command)
| stats count by file_hash                         <- aggregate
| where count > 1                                  <- filter on an expression
| eval x=lower(file_hash)                          <- compute a field
| table file_hash count                            <- pick columns
```

Commands used in this guide: `stats`, `eval`, `where`/`search`, `table`, `sort`, `rex` (regex to field), `mvexpand` (one row per value of a multivalue field), `makeresults` (build a test result), `tstats` (fast query on a CIM data model), `outputlookup`/`lookup` (CSV tables).

## 2. Dev stack

Requirements: Docker (~6 GB RAM), `.env` with `MLAB_IR_LI=<ir.mlab.sh licence>` and optionally `MLAB_API_KEY=mlab_...`. Keep 5 GB of disk free (both scripts check and stop otherwise).

```sh
dev/setup.sh   # starts Splunk + ir.mlab.sh, creates the ir token, stores the secrets in Splunk
dev/e2e.sh     # checks the whole chain, re-runnable; expected: "All checks passed."
```

| | URL | Login |
|---|---|---|
| Splunk Web | http://localhost:8000 | `admin` / `changeme123` |
| Splunk API | https://localhost:8089 | same |
| HEC | https://localhost:8088 | token `6d6c6162-0000-4000-8000-000000000001` |
| ir.mlab.sh | http://localhost:8080 | `admin@localhost` / `adminadmin` |

The repo's `mlab/` folder is mounted as-is in the container:

| You edit | You need to |
|---|---|
| `mlab/bin/*.py` | nothing, picked up on the next call |
| `mlab/default/*.conf` | `docker compose restart splunk` (~1 min) |
| `docker-compose.yml`, `.env` | `dev/setup.sh` |

Send a test event by hand:

```sh
curl -sk -H "Authorization: Splunk 6d6c6162-0000-4000-8000-000000000001" https://localhost:8088/services/collector/event \
  -d '{"sourcetype":"_json","event":{"file_hash":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f","dest":"web01","file_path":"/tmp/eicar.com"}}'
```

Then in Splunk Web → Search: `index=main sourcetype=_json` (time range "Last 60 minutes").

Pause / resume / wipe everything:

```sh
docker compose stop
docker compose start
docker compose down -v    # also deletes Splunk and ir.mlab.sh data
```

## 3. The `| mlab` command

```
| mlab type=<hash|url|ip|cve> [field=<field>]
```

| `type` | Default field | Adds | mlab.sh quota |
|---|---|---|---|
| `hash` | `file_hash` | `mlab_verdict` (`known_malicious`, `known_good`…), `mlab_known_malicious`, `mlab_family`, `mlab_file_name`, `mlab_product`, `mlab_trust`, `mlab_sources_hit`, `mlab_sources_answered`, `mlab_summary` | none |
| `url` | `url` | `mlab_host`, `mlab_findings` (multivalue), `mlab_severities` (multivalue) | none |
| `cve` | `cve` | `mlab_cvss_score`, `mlab_cvss_severity`, `mlab_epss_score`, `mlab_epss_percentile`, `mlab_in_kev`, `mlab_kev_date_added`, `mlab_in_eu_kev`, `mlab_risk_score` | none |
| `ip` | `src` | `mlab_country_code`, `mlab_as`, `mlab_org`, `mlab_proxy`, `mlab_hosting`, `mlab_tor` | yes |

Every enriched result also gets `mlab_type` and `mlab_value` (the value sent; hashes lower-cased).

Rules of thumb:

- **Always aggregate first** (`stats … by file_hash`): one request per distinct value instead of one per event.
- Booleans are the strings `true` / `false`: `search mlab_tor=true`.
- **Private IPs are never sent** (RFC 1918, loopback, CGNAT, link-local…): their `mlab_*` fields stay empty.
- **Multivalue fields are skipped**: `mvexpand` them first.
- **24h cache** on the search head (`$SPLUNK_HOME/var/run/splunk/mlab-cache.db`), shared by all searches.
- **Quota reached**: that type is paused for an hour, the search shows a warning and the fields stay empty. Other types keep working.
- **API key**: read from `storage/passwords` with the rights of the user running the search. Without the `list_storage_passwords` capability the search still works, anonymously (with a warning).

## 4. Search examples

### Hashes

Malicious files seen today (CIM fields):

```
index=* file_hash=* earliest=-24h
| stats count min(_time) as first_seen max(_time) as last_seen values(dest) as dest values(file_path) as file_path by file_hash
| mlab type=hash
| search mlab_verdict=known_malicious
| convert ctime(first_seen) ctime(last_seen)
```

**Sysmon** (EventID 1, process creation): the raw `Hashes` field is `SHA1=…,MD5=…,SHA256=…,IMPHASH=…`. Depending on the add-on installed, `SHA256` may already be extracted; otherwise:

```
index=sysmon EventCode=1
| rex field=Hashes "SHA256=(?<sha256>[A-Fa-f0-9]{64})"
| stats count values(Image) as image values(host) as host by sha256
| mlab type=hash field=sha256
| search mlab_verdict=known_malicious
```

MD5 and SHA256 both work: `| makeresults | eval file_hash="44d88612fea8a8f36de82e1278abb02f" | mlab type=hash` returns `known_malicious` (EICAR).

With the CIM data model (CIM app installed and the data model accelerated; much faster):

```
| tstats summariesonly=true count from datamodel=Endpoint.Filesystem by Filesystem.file_hash Filesystem.dest
| rename Filesystem.* as *
| mlab type=hash
| search mlab_verdict=known_malicious
```

Drop everything known to be legitimate (cut the noise in a hunt):

```
... | stats count by file_hash | mlab type=hash | where mlab_verdict!="known_good"
```

### IPs

Failed logins from Tor:

```
index=* tag=authentication action=failure src=* earliest=-24h
| stats count values(user) as user values(dest) as dest by src
| mlab type=ip
| search mlab_tor=true
```

Country and hosting of destination IPs (non-default field, multivalue expanded):

```
| makeresults | eval dest_ip=split("8.8.8.8,185.220.101.1,10.1.1.1", ",") | mvexpand dest_ip
| mlab type=ip field=dest_ip
| table dest_ip mlab_country_code mlab_org mlab_tor
```

Result: `8.8.8.8` → US / Google Public DNS, `185.220.101.1` → DE / Tor, `10.1.1.1` → empty (private, not sent).

Mind the IP quota: never run `type=ip` over all traffic; always narrow it down (failed auth, blocked outbound connections, top N…):

```
index=firewall action=allowed direction=outbound | stats count by dest_ip | sort - count | head 50 | mlab type=ip field=dest_ip
```

### CVEs

Vulnerability prioritisation (KEV first, then EPSS exploitation probability):

```
index=* cve=*
| stats values(dest) as dest dc(dest) as hosts by cve
| mlab type=cve
| eval priority=case(mlab_in_kev=="true","P1", mlab_epss_score>=0.1,"P2", true(),"P3")
| sort priority - hosts
| table priority cve hosts dest mlab_cvss_score mlab_epss_score mlab_in_kev mlab_kev_date_added
```

Real output: Log4Shell and CVE-2023-4863 come out P1 (KEV), CVE-2019-0001 P3 (EPSS 0.03).

With the Vulnerabilities data model:

```
| tstats count from datamodel=Vulnerabilities by Vulnerabilities.cve Vulnerabilities.dest
| rename Vulnerabilities.* as *
| stats values(dest) as dest by cve
| mlab type=cve
| search mlab_in_kev=true
```

### URLs

```
index=proxy url=*
| stats count values(src) as src by url
| mlab type=url
| search mlab_severities=high OR mlab_severities=critical
```

mlab.sh URL findings are **heuristics** (executable in the path, shortener, plaintext HTTP…), not reputation: use them to triage, not as a verdict.

### Keeping results

Write verdicts to a CSV table to reuse them without calling mlab.sh again:

```
... | stats count by file_hash | mlab type=hash
| table file_hash mlab_verdict mlab_family mlab_file_name
| outputlookup append=true mlab_hash_verdicts.csv
```

Then anywhere: `... | lookup mlab_hash_verdicts.csv file_hash OUTPUT mlab_verdict`.

## 5. Scheduled alerts

The app ships four scheduled searches, **disabled**:

| Search | Base macro | ir severity |
|---|---|---|
| mlab - Known malicious file | `mlab_hash_events` = `index=* file_hash=*` | high |
| mlab - Suspicious URL | `mlab_url_events` = `index=* url=*` | medium |
| mlab - Tor exit node | `mlab_ip_events` = `index=* tag=authentication action=failure src=*` | low |
| mlab - Known exploited CVE | `mlab_cve_events` = `index=* cve=*` | critical |

Each runs every 15 minutes over `-16m@m` → `-1m@m` (the one-minute margin covers indexing lag).

**Turning them on:**

1. **Point the macro** at your data: Settings → Advanced search → Search macros → app `mlab` → `mlab_hash_events` → e.g. `index=sysmon EventCode=1 file_hash=*`. `index=*` works but is expensive.
2. Test the search by hand: Settings → Searches, reports, and alerts → app `mlab` → the search → *Run*.
3. *Edit → Enable*.
4. To send to ir.mlab.sh: *Edit → Edit Alert → Add Actions → Send to ir.mlab.sh* (see section 6).

Triggers show up in Activity → Triggered Alerts, and:

```
index=_internal sourcetype=scheduler savedsearch_name="mlab - *" | table _time savedsearch_name status result_count alert_actions
```

Over REST (what `dev/e2e.sh` does):

```sh
S='https://localhost:8089/servicesNS/nobody/mlab/saved/searches/mlab%20-%20Known%20malicious%20file'
curl -sk -u admin:changeme123 "$S" -d disabled=0 -d actions=mlab_ir     # enable + ir action
curl -sk -u admin:changeme123 "$S/dispatch" -d trigger_actions=1 -d dispatch.earliest_time=-1h   # run now
curl -sk -u admin:changeme123 "$S" -d disabled=1 -d actions=             # back as before
```

Two traps: the action is enabled with `actions=mlab_ir` (not `action.mlab_ir=1`), and disabling the search before the job finishes makes the alert fail ("alert is invalid" in splunkd.log).

## 6. Sending to ir.mlab.sh

The **Send to ir.mlab.sh** alert action (`mlab_ir`) creates one ir.mlab.sh alert per result (at most 100 per trigger).

Settings:

| Setting | Where |
|---|---|
| ir.mlab.sh URL | in each alert's action, or once: `mlab/local/alert_actions.conf` → `[mlab_ir]` `param.base_url = https://ir.example.com` |
| App token (`mlab_app_…`) | `storage/passwords`, realm `mlab`, name `ir_token` (see section 8) |
| Default severity | in the action (info → critical) |

What each result becomes:

| ir.mlab.sh | Comes from |
|---|---|
| title | the result's `title` or `rule_name` field, else the search name |
| severity | the result's `severity` or `urgency` field if it is info…critical, else the action's |
| dedup | `splunk:<search>:<dest or host>:<mlab_value>`: same search + same host + same indicator = one ir alert, `ingest_count` goes up |
| description | search name, every result field, then `_raw` |
| tags | search name + `mitre_technique_id` |
| observables | `src`/`dest`/`dvc` (IP or hostname), `file_hash`, `mlab_value`, `url`, `cve`, `file_path`/`file_name`, `host` |

So the search controls the rendering with `eval`:

```
... | mlab type=hash | search mlab_verdict=known_malicious
| eval title="Malware ".mlab_file_name." on ".mvindex(dest,0), severity="critical", mitre_technique_id="T1204"
```

Manual send, without a scheduled alert (handy for testing):

```
| makeresults | eval file_hash="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", dest="web01"
| mlab type=hash
| eval title="mlab_ir manual test"
| sendalert mlab_ir param.severity=low
```

Where to see the outcome:

- scheduled alerts: `index=_internal sourcetype=splunkd component=sendmodalert action=mlab_ir`, with lines `mlab_ir: <search> -> created|duplicate <ir uuid>`;
- manual `sendalert`: Job → Inspect Job → search.log (not in splunkd.log).

## 7. Enterprise Security

Nothing special to do:

- `mlab_ir` shows up as an **adaptive response** (thanks to `param._cam`): add it to a correlation search, or run it by hand on a notable from Incident Review.
- On a notable, `rule_name`, `urgency` and `event_id` are picked up as the ir title, severity and `external_id`.
- The app's four searches can be converted to correlation searches (Content Management → the search → *Convert*), or their SPL pasted into an existing correlation search.
- `| mlab` works in any ES search like anywhere else.

## 8. Production install

1. Copy `mlab/` to the **search head**: `$SPLUNK_HOME/etc/apps/mlab` (search head cluster: through the deployer). Nothing goes on indexers or forwarders.
2. Restart Splunk.
3. Store the secrets (as admin):

```sh
curl -k -u admin https://SH:8089/servicesNS/nobody/mlab/storage/passwords -d realm=mlab -d name=ir_token -d password=mlab_app_...
curl -k -u admin https://SH:8089/servicesNS/nobody/mlab/storage/passwords -d realm=mlab -d name=api_key  -d password=mlab_...   # optional
```

   To change a secret: `curl -k -u admin -X DELETE https://SH:8089/servicesNS/nobody/mlab/storage/passwords/mlab:ir_token:`, then create it again.
4. Set the ir.mlab.sh URL (section 6), point the macros at your data, enable the searches you want (section 5).
5. The search head must reach `mlab.sh`, `vuln.mlab.sh` and your ir.mlab.sh over HTTPS.

## 9. Troubleshooting

| Symptom | Where to look / what to do |
|---|---|
| `Unknown search command 'mlab'` | App missing or Splunk not restarted: `splunk btool commands list mlab --debug`. |
| Empty `mlab_*` fields | The search messages (yellow banner): quota, network error, unreadable key. Private IP or multivalue field → expected. Is the right field read (`field=`)? |
| "quota reached" | Wait (one-hour pause) or set an API key. Check: `curl -H "Authorization: token $KEY" https://mlab.sh/api/v1/limit/ip`. |
| "API key not readable" | The user lacks `list_storage_passwords`: anonymous lookups. Grant the capability, or run as the scheduled search's owner. |
| Silent scheduled alert | `index=_internal sourcetype=scheduler savedsearch_name="mlab - *"`: `result_count=0` → the macro finds nothing; `alert_actions=""` → action not enabled. |
| `mlab_ir` failing | `index=_internal component=sendmodalert action=mlab_ir`: `base_url is not set`, `no ir.mlab.sh app token`, HTTP error from ir. |
| Invalid conf | `splunk btool check --app=mlab` (empty = OK). In the dev stack: `docker compose exec -u splunk splunk /opt/splunk/bin/splunk btool check --app=mlab`. |
| Start from an empty cache | Delete `$SPLUNK_HOME/var/run/splunk/mlab-cache.db`. |
| Details of one `| mlab` run | Job → Inspect Job → search.log. |

Splunk logs in the dev stack:

```sh
docker compose exec -u splunk splunk tail -f /opt/splunk/var/log/splunk/splunkd.log
```

## 10. Repository layout

```
mlab/                        the Splunk app (this is the folder you install)
  bin/mlabsh.py              mlab.sh calls, cache, quotas, secret lookup
  bin/mlab_command.py        the | mlab command
  bin/mlab_ir.py             the Send to ir.mlab.sh alert action
  default/*.conf             command, alert action, macros, scheduled searches
  default/data/ui/alerts/    the action's form in the UI
  README/*.spec              declares the action's settings
  lib/splunklib/             Splunk SDK for Python 2.1.1 (Apache 2.0), vendored
tests/                       unit tests (local fake HTTP server, no network)
dev/setup.sh, dev/e2e.sh     dev stack and end-to-end checks
docker-compose.yml           Splunk + ir.mlab.sh
```

Git ignores `mlab/local/` and `mlab/metadata/local.meta` (written by Splunk in the dev stack, including the encrypted secrets), `dev/.generated/` and `.env`.
