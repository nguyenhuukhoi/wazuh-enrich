# Wazuh Vulnerability Enrichment

Vietnamese version: [README.vi.md](README.vi.md)

Production-oriented vulnerability enrichment for Wazuh 4.14.x. The service reads Wazuh vulnerability findings from Wazuh Indexer, enriches them with CISA KEV, FIRST EPSS, PoC metadata, and Ubuntu OVAL verification, writes enriched/summary indices, and sends aggregate alerts.

This phase does not use NVD, does not call EPSS per CVE, and does not continuously query each agent.

## Production Flow

```text
Wazuh vulnerability findings
        ↓
sync KEV + EPSS + build/sync PoC feed + Ubuntu OVAL
        ↓
enrich findings
        ↓
wazuh-vuln-enriched-YYYY.MM.DD
        ↓
CVE summary + Host summary
        ↓
dashboard + aggregate alert
```

Daemon mode automatically:

- Syncs CISA KEV every 1 hour.
- Syncs EPSS every 24 hours.
- Builds PoC feed from Exploit-DB metadata when `POC_BUILD.enabled` is true.
- Syncs PoC metadata.
- Syncs Ubuntu OVAL every 24 hours to verify affected packages and fixed versions.
- Watches Wazuh inventory indices every 60 seconds and queues agents whose inventory changed.
- Waits 180 seconds before processing changed agents so Wazuh has time to update vulnerability states.
- Re-enriches only changed agents and incrementally updates the affected host/CVE summaries.
- Runs incremental enrichment every 15 minutes.
- On the first daemon start, runs one full refresh and marks `startup_full_refresh_done` in `STATE_FILE`.
- Runs full refresh every 24 hours or when feed fingerprints change.
- Runs one automatic full refresh when the current daily enriched index is empty.
- Detects new agents every 5 minutes.

## Created Indices

```text
wazuh-vuln-enriched-YYYY.MM.DD
wazuh-vuln-cve-summary-YYYY.MM.DD
wazuh-vuln-host-summary-YYYY.MM.DD
wazuh-vuln-host-cve-impact-YYYY.MM.DD
wazuh-vuln-enriched-latest
wazuh-vuln-cve-summary-latest
wazuh-vuln-host-summary-latest
wazuh-vuln-host-cve-impact-latest
```

Daily indices keep history. `*-latest` indices keep the current operational state and are what dashboards should read. Dashboards should not read `wazuh-states-vulnerabilities-*` directly.

## Wazuh-Aligned Incremental Updates

The daemon has two update paths:

```text
Wazuh inventory changed for agent N
        -> wait inventory_stabilization_seconds
        -> query Wazuh vulnerabilities only for agent N
        -> replace enriched docs only for agent N
        -> rebuild host summary only for agent N
        -> rebuild CVE summaries only for CVEs that agent N added or removed
        -> rebuild host-CVE impact rows only for agent N
```

Feed changes still trigger a full refresh because KEV, EPSS, PoC, or Ubuntu metadata can change the risk score for existing findings across every host.

```text
Inventory update -> incremental agent refresh
Feed update      -> full refresh
First startup    -> one full refresh, then mark startup_full_refresh_done
Daily fallback   -> full refresh
```

The startup full refresh creates the initial operational snapshot for dashboards. It runs once, then stores `startup_full_refresh_done: true` in `STATE_FILE`. A config reload does not run it again, and a service restart also skips it because the state file is already marked. To force this startup full refresh again, set `startup_full_refresh_done` to `false` in the state file or run `enrich-all` manually.

The daily fallback exists because the enriched indices are date-based. After midnight, `wazuh-vuln-enriched-YYYY.MM.DD` is a new index. If the daemon sees that today's enriched index has no documents and it has not already refreshed that index, it runs one full refresh and records the index name in `STATE_FILE` as `last_daily_full_refresh_index`.

Example:

```json
{
  "last_daily_full_refresh_index": "wazuh-vuln-enriched-2026.05.12"
}
```

This state key means: "the daemon already ran the once-per-day fallback full refresh for this daily index." On the next daemon loop, if the same index is still empty, the daemon will not run another full refresh. This matters because a healthy system can genuinely have zero vulnerability findings; without this guard, the daemon would see an empty index every loop and repeatedly full refresh Wazuh Indexer.

Daily fallback decision:

```text
Today's enriched index is empty + not marked in state -> run full refresh once
Today's enriched index is empty + already marked       -> skip full refresh
New day, new index name                                -> allow one fallback full refresh again
```

The inventory watcher uses a watermark in `STATE_FILE`:

```text
last_inventory_timestamp
pending_inventory_agents
last_daily_full_refresh_index
```

It does not continuously query every agent. It queries inventory indices by timestamp, extracts changed `agent.id` values, then processes due agents in bounded batches.

## Install

Install the package dependencies and clone the project into `/opt/wazuh-enrich`:

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-venv python3-pip

cd /opt
sudo git clone https://github.com/nguyenhuukhoi/wazuh-enrich.git
sudo chown -R "$USER:$USER" /opt/wazuh-enrich
cd /opt/wazuh-enrich

python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
deactivate

sudo chown -R root:root /opt/wazuh-enrich
```

If the directory already exists, update it instead:

```bash
cd /opt/wazuh-enrich
sudo chown -R "$USER:$USER" /opt/wazuh-enrich
git pull
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
deactivate
sudo chown -R root:root /opt/wazuh-enrich
```

## Configuration

Use this production layout:

```bash
sudo mkdir -p /etc/wazuh-enrich /var/lib/wazuh-enrich/cache /var/lib/wazuh-enrich/feeds
sudo cp config.yaml /etc/wazuh-enrich/config.yaml
sudo chown -R root:root /etc/wazuh-enrich /var/lib/wazuh-enrich
sudo chmod 700 /etc/wazuh-enrich
sudo chmod 600 /etc/wazuh-enrich/config.yaml
```

The default config now uses these production runtime paths:

```yaml
WAZUH_VULN_INDEX_PATTERN: wazuh-states-vulnerabilities-*
AGENT_INVENTORY_INDEX_PATTERNS:
  - wazuh-states-inventory-system-*
  - wazuh-states-inventory-packages-*
  - wazuh-states-inventory-hotfixes-*
  - wazuh-states-inventory-interfaces-*
  - wazuh-states-inventory-networks-*
INVENTORY_WATCH_TIMESTAMP_FIELDS:
  - "@timestamp"
  - event.created
  - timestamp

CACHE_DIR: /var/lib/wazuh-enrich/cache
STATE_FILE: /var/lib/wazuh-enrich/state.json

POC_BUILD:
  output_file: /var/lib/wazuh-enrich/feeds/cve_poc.csv
```

`AGENT_INVENTORY_INDEX_PATTERNS` is used to enrich real agent IP addresses in batch. Wazuh vulnerability documents can contain `agent.ip: 0.0.0.0`; the inventory indices usually contain the real `agent.host.ip`.

`INVENTORY_WATCH_TIMESTAMP_FIELDS` controls which timestamp fields are tried when detecting recently changed inventory documents. Keep `@timestamp` first unless your Wazuh Indexer stores inventory timestamps under a custom field.

Create the environment file:

```bash
sudo nano /etc/wazuh-enrich/wazuh-enrich.env
```

Example `/etc/wazuh-enrich/wazuh-enrich.env`:

```bash
WAZUH_INDEXER_URL=https://127.0.0.1:9200
WAZUH_INDEXER_USERNAME=admin
WAZUH_INDEXER_PASSWORD=your-password
WAZUH_CA_CERT=/etc/filebeat/certs/root-ca.pem
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```

Protect credentials:

```bash
sudo chown root:root /etc/wazuh-enrich/wazuh-enrich.env
sudo chmod 600 /etc/wazuh-enrich/wazuh-enrich.env
```

For labs only:

```yaml
VERIFY_SSL: false
```

Production should use:

```yaml
VERIFY_SSL: true
WAZUH_CA_CERT: /path/to/root-ca.pem
```

## PoC Feed

Default PoC build source is Exploit-DB metadata:

```yaml
POC_BUILD:
  enabled: false
  interval_seconds: 86400
  output_file: /var/lib/wazuh-enrich/feeds/cve_poc.csv
  exploitdb_csv: https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv
  # Optional extra sources:
  # nuclei_templates: https://github.com/projectdiscovery/nuclei-templates
  # poc_in_github: https://github.com/nomi-sec/PoC-in-GitHub
  # trickest_cve: https://github.com/trickest/cve
```

Enable automatic PoC feed builds:

```yaml
POC_BUILD:
  enabled: true
```

Manual build remains available:

```bash
python3 tools/build_poc_feed.py \
  --exploitdb-csv https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv \
  --output /var/lib/wazuh-enrich/feeds/cve_poc.csv
```

PoC fields written to enriched/summary docs:

```text
public_poc
poc_count
poc_references
poc_sources
```

## Ubuntu Impact Verification

Ubuntu verification is enabled by default and uses Canonical Ubuntu OVAL plus Ubuntu OSV data. OVAL gives USN/fixed-version patch data. OSV mirrors Ubuntu Security Tracker CVE records and includes known affected packages even when a security update is not yet available. The service downloads these feeds in batch, caches them locally, and never calls Canonical per CVE or per agent.

Default config:

```yaml
UBUNTU_OVAL:
  enabled: true
  max_age_hours: 24
  base_url: https://security-metadata.canonical.com/oval
  osv_enabled: true
  osv_url: https://security-metadata.canonical.com/osv/osv-all.tar.xz
  osv_max_age_hours: 24
  releases:
    - noble   # Ubuntu 24.04
    - jammy   # Ubuntu 22.04
    - focal   # Ubuntu 20.04
  urls:
    noble: https://security-metadata.canonical.com/oval/com.ubuntu.noble.usn.oval.xml.bz2
    jammy: https://security-metadata.canonical.com/oval/com.ubuntu.jammy.usn.oval.xml.bz2
    focal: https://security-metadata.canonical.com/oval/com.ubuntu.focal.usn.oval.xml.bz2
```

Fields written to enriched and summary docs:

```text
verification_status
verification_source
verification_confidence
vendor_source
vendor_advisory_url
vendor_fixed_version
vendor_severity
vendor_status
fix_available
fix_status
ubuntu_release
exploitability_status
exposure_status
patch_decision
impact_assessment
recommended_action
```

Important statuses:

- `confirmed_affected`: Wazuh finding is active and Ubuntu OVAL says the installed package version is lower than the fixed version.
- `likely_affected`: Ubuntu OVAL/OSV confirms the CVE/package, but the fixed version is missing or the installed version cannot be compared.
- `installed_version_at_or_above_fixed`: the installed version appears to be at or above the Ubuntu fixed version. Re-run Wazuh vulnerability detection if this still appears as active.
- `vendor_not_found`: Wazuh reported the CVE, but the CVE/package was not found in the cached Ubuntu OVAL feed for that release.

This makes PoC/KEV findings easier to triage because a high-priority row can now show whether Canonical confirms the host package is affected and whether a fixed version exists.

For Ubuntu kernel packages, Wazuh usually reports binary package names such as `linux-image-6.8.0-36-generic`. Canonical tracks kernel vulnerabilities primarily under source package names such as `linux`. The enricher maps common kernel binary package names back to `linux` so these CVEs do not incorrectly show as `vendor_not_found`.

Kernel patching has one important extra rule. If the vulnerable `linux-image-*` package is still installed but the host is already running a different fixed kernel, the finding is not treated as `patch_now`. It is marked as:

```text
exposure_status: non_running_kernel_installed
patch_decision: cleanup_old_kernel
```

That means the host should keep the fixed kernel as default boot and purge old vulnerable kernel packages. Wazuh may continue showing the CVE until the old `linux-image-*` / `linux-modules-*` packages are removed and inventory/vulnerability detection runs again.

Patch decision is the field to use when deciding whether to patch the system:

```text
patch_now       -> vendor confirms affected and the threat/exposure is high
patch_scheduled -> vendor confirms affected and a fixed version exists
cleanup_old_kernel -> vulnerable old kernel package is installed but is not the running kernel
monitor         -> affected or possibly affected, but exploitability is low or no fix exists yet
no_action       -> installed version is already at or above the Ubuntu fixed version
needs_review    -> Wazuh reported the finding, but vendor metadata did not confirm the package/release
```

The decision is intentionally conservative:

- `KEV=yes` means exploited in the wild and overrides a low EPSS score.
- `public_poc=yes` raises urgency only after the CVE is known to impact the system.
- `vendor_not_found` with high threat becomes `needs_review`, not automatic `patch_now`.
- Kernel findings become urgent when the vulnerable package matches the running kernel. Old non-running kernel packages are treated as cleanup work, not immediate runtime exploit impact.

## First Run

For production paths, run the first checks as root:

```bash
set -a
. /etc/wazuh-enrich/wazuh-enrich.env
set +a
cd /opt/wazuh-enrich
.venv/bin/python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml sync-feeds
```

Dry-run:

```bash
set -a
. /etc/wazuh-enrich/wazuh-enrich.env
set +a
cd /opt/wazuh-enrich
.venv/bin/python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml --dry-run --log-format text enrich-all
```

Dry-run normally does not write indices, save state, or send Telegram. To test the full alert path while keeping index/state writes disabled:

```bash
set -a
. /etc/wazuh-enrich/wazuh-enrich.env
set +a
cd /opt/wazuh-enrich
.venv/bin/python3 vuln_enricher.py \
  --config /etc/wazuh-enrich/config.yaml \
  --dry-run \
  --dry-run-send-alerts \
  --log-format text \
  enrich-all
```

Send a real Telegram test message without running enrichment:

```bash
set -a
. /etc/wazuh-enrich/wazuh-enrich.env
set +a
cd /opt/wazuh-enrich
.venv/bin/python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml test-alert
```

Run real enrichment:

```bash
set -a
. /etc/wazuh-enrich/wazuh-enrich.env
set +a
cd /opt/wazuh-enrich
.venv/bin/python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml enrich-all
```

Check indices:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/_cat/indices/wazuh-vuln-*?v"
```

## systemd

This service intentionally runs as root. The unit does not set `User=` or `Group=`, so systemd uses root by default.

Prepare root-owned runtime directories before enabling the service:

```bash
sudo chown -R root:root /etc/wazuh-enrich /var/lib/wazuh-enrich
sudo chmod 700 /etc/wazuh-enrich
sudo chmod 700 /var/lib/wazuh-enrich
```

Create service:

```bash
sudo nano /etc/systemd/system/wazuh-enrich.service
```

Content:

```ini
[Unit]
Description=Wazuh vulnerability enrichment service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/wazuh-enrich
EnvironmentFile=/etc/wazuh-enrich/wazuh-enrich.env
ExecStart=/opt/wazuh-enrich/.venv/bin/python3 /opt/wazuh-enrich/vuln_enricher.py --config /etc/wazuh-enrich/config.yaml daemon
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-enrich
sudo journalctl -u wazuh-enrich -f
```

Reload after editing `/etc/wazuh-enrich/config.yaml` or `/etc/wazuh-enrich/wazuh-enrich.env`:

```bash
sudo systemctl reload wazuh-enrich
sudo journalctl -u wazuh-enrich -n 50 --no-pager
```

Reload sends `SIGHUP` to the daemon. The process stays running, saves current state, reloads config, reconnects to Wazuh Indexer, rebuilds feed clients, and keeps the previous config if the new config is invalid. Reload does not download feeds immediately; feed sync still follows the configured schedule, ETag/Last-Modified checks, or a manual `sync-feeds` run.

## CLI

```bash
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml sync-feeds
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml build-poc-feed
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml sync-poc
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml enrich-all
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml enrich-agent --agent-id 001
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml process-inventory-updates
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml detect-new-agents
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml test-alert
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml debug-agent-ip --agent-id 001
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml run-once
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml daemon
```

Logs default to JSON. For terminal reading:

```bash
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml --log-format text --dry-run run-once
```

## Priority

```text
P0: KEV=true, or EPSS >= 0.7 and CVSS >= 8
P1: EPSS >= 0.3, or CVSS >= 8
P2: CVSS >= 6
P3: everything else
```

Risk score:

```text
(epss_score * 50) + (cvss_score * 3) + (30 if kev=true)
```

## Alerts

The service sends aggregate alerts only for meaningful signals:

- CVE is in CISA KEV.
- Priority is P0.
- EPSS crosses a configured threshold.
- New agent has P0/P1.
- CVE transitions from non-KEV to KEV.
- CVE affects many agents.

Alert config:

```yaml
ALERT_THRESHOLDS:
  epss_high: 0.7
  epss_medium: 0.3
  cve_many_agents: 25
  alert_scope: critical_real_impact
  send_all_impacted_cves: false
  send_all_alerts: false
  public_poc_only: false
  alert_interval_seconds: 0
  max_top_cves: 10
```

`alert_scope` selects which operational group Telegram sends. Default is `critical_real_impact`.

```text
critical_real_impact -> patch_now + vendor confirmed/likely affected + exploit signal
needs_review         -> high-threat CVEs where vendor/package confirmation is incomplete
patch_scheduled      -> vendor confirmed affected, patch should be planned, or old kernel cleanup is needed
all                  -> all alert-eligible CVEs
```

`send_all_alerts: false` is the production default. Alerts are deduplicated with `STATE_FILE`, so the same CVE/key is not sent every cycle.

Set this when you want every CVE currently impacting your system to be alert-eligible. This still only uses CVEs from Wazuh findings/enriched summaries, not global internet CVEs:

```yaml
ALERT_THRESHOLDS:
  send_all_impacted_cves: true
  max_top_cves: 0
```

Set this when you want every eligible alert every cycle, for example during testing or a short incident review:

```yaml
ALERT_THRESHOLDS:
  send_all_alerts: true
  max_top_cves: 0
```

Use both when you want every currently impacted CVE sent on every cycle.

Use `public_poc_only: true` when you only want CVEs with public PoC metadata in the alert. This filter is applied after Wazuh impact is known, so it means "public PoC CVEs that currently affect this system", not every public PoC CVE on the internet:

```yaml
ALERT_THRESHOLDS:
  send_all_impacted_cves: true
  send_all_alerts: true
  alert_scope: critical_real_impact
  public_poc_only: true
  alert_interval_seconds: 3600
  max_top_cves: 0
```

`alert_interval_seconds` is the minimum gap between two aggregate cycle alerts. It only applies to the normal cycle alert from `process_cycle`; new-agent baseline alerts are still sent immediately when detected. The first eligible alert after service start is sent immediately if `STATE_FILE` has no previous `last_alert_sent_by_type.cycle`. If the service is restarted and the previous cycle alert is still inside the interval window, the restart will not spam Telegram.

This option does not create a separate alert scheduler. Alerts are evaluated when enrichment/inventory processing runs. If `alert_interval_seconds` is smaller than `SCHEDULE.enrichment_seconds`, the real resend pace is still limited by the enrichment cycle.

`max_top_cves: 0` means include every matched CVE in the Telegram message. Be careful with this on large environments because Telegram messages can become noisy or exceed message limits.

Example:

```text
CRITICAL - Critical Real Impact CVEs impacting system

Summary:
- Alert scope: critical_real_impact
- Affected agents: 2
- Patch now CVEs: 2
- Needs review CVEs: 1
- Vendor confirmed affected: 2
- Fix available CVEs: 2
- P0 CVEs: 4
- KEV CVEs: 2
- Public PoC CVEs: 1
- EPSS >= 0.7: 3

Top CVEs to decide patching:
1. CVE-2025-0001 | patch=patch_now | Ubuntu=confirmed_affected | exploit=exploited_in_wild | KEV=yes | PoC=yes | EPSS=0.94 | CVSS=9.8 | hosts=72 | package=openssl | fix=yes | action=Patch now.
```

## Dashboard

Create these data views:

```text
wazuh-vuln-enriched-latest        time field: enriched_at
wazuh-vuln-cve-summary-latest     time field: updated_at
wazuh-vuln-host-cve-impact-latest time field: updated_at
```

The imported dashboard intentionally contains only the operational panels:

- Impact Filters.
- Critical Real Impact CVEs and hosts.
- Needs Review CVEs and hosts.
- Patch Scheduled CVEs and hosts.

Dashboard import is optional and separate from enrichment:

```bash
python3 dashboard/manage_saved_objects.py reimport --no-verify-ssl
```

The filter and host impact panels use `wazuh-vuln-host-cve-impact-latest`. This index has one current document per `cve_id + agent_id`, so the host table is not duplicated by package/version or by daily history. It has dropdowns for:

```text
impact_cve_id
impact_host
patch_decision
verification_status
fix_status
```

Those fields are written only for CVEs that Wazuh has detected on your agents, so the dropdowns do not list global/non-impact CVEs.
The imported controls use the `.keyword` subfields for terms aggregation.
The dashboard uses `*-latest` indices for operational views so the same CVE does not appear once per daily index. Daily indices are still written for history/trend queries.

How it works:

- `wazuh-vuln-*-YYYY.MM.DD` keeps historical snapshots.
- `wazuh-vuln-*-latest` is replaced with the current state after each successful enrichment/update.
- Dashboard panels and filters should use `*-latest`.
- Alert logic is unchanged; alerts are evaluated from the current enrichment cycle, not by scanning all daily summary indices.

The dashboard splits CVEs into three operational groups:

```text
Critical Real Impact:
patch_decision:patch_now
and vendor confirmed/likely affected
and exploited_in_wild or public_poc:true or epss_score >= 0.7

Needs Review:
patch_decision:needs_review
or vendor confirmation is incomplete while KEV/public PoC/EPSS-high is present

Patch Scheduled:
patch_decision:patch_scheduled
```

These show only CVEs that Wazuh has actually detected on your agents, not a global internet CVE list.

## Quick Checks

Critical Real Impact CVEs:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/wazuh-vuln-cve-summary-latest/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":25,"query":{"bool":{"filter":[{"term":{"patch_decision":"patch_now"}},{"terms":{"verification_status":["confirmed_affected","likely_affected"]}},{"range":{"affected_hosts_count":{"gte":1}}}],"should":[{"term":{"exploitability_status":"exploited_in_wild"}},{"term":{"public_poc":true}},{"range":{"epss_score":{"gte":0.7}}}],"minimum_should_match":1}},"sort":[{"risk_score":"desc"},{"affected_hosts_count":"desc"}]}'
```

Needs Review CVEs:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/wazuh-vuln-cve-summary-latest/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":25,"query":{"bool":{"filter":[{"range":{"affected_hosts_count":{"gte":1}}}],"should":[{"term":{"patch_decision":"needs_review"}},{"bool":{"filter":[{"terms":{"verification_status":["vendor_not_found","needs_manual_check","not_verified"]}}],"should":[{"term":{"kev":true}},{"term":{"public_poc":true}},{"range":{"epss_score":{"gte":0.7}}}],"minimum_should_match":1}}],"minimum_should_match":1}},"sort":[{"risk_score":"desc"},{"affected_hosts_count":"desc"}]}'
```

## Troubleshooting

- No findings: check `wazuh-states-vulnerabilities-*`.
- CISA blocked: set `CISA_KEV_FILE` to a local JSON mirror.
- PoC not visible: enable `POC_BUILD`, run `python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml build-poc-feed`, then `python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml enrich-all`.
- Agent IP is `0.0.0.0`: run `debug-agent-ip`, verify inventory indices have `agent.host.ip`, `host.ip`, `network.ip`, or another discovered IP field, then rerun `enrich-all`. The enricher joins those inventory indices by `agent.id`.
- Dashboard slow: use summary indices, not raw Wazuh state indices.

Quick inventory check for agent `002` from the enricher:

```bash
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml debug-agent-ip --agent-id 002
```

Equivalent direct Wazuh Indexer query:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/wazuh-states-inventory-system-*,wazuh-states-inventory-interfaces-*,wazuh-states-inventory-networks-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":5,"query":{"term":{"agent.id":"002"}},"_source":["agent.id","agent.name","agent.host.ip","host.ip","network.*","related.ip","interface.*"]}'
```

## Tests

```bash
python3 -m pytest -q
python3 -m py_compile config.py feed_sync.py risk.py alerts.py state.py summary.py wazuh_client.py vuln_enricher.py
```
