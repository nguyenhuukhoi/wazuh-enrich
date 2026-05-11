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
- Runs full refresh every 24 hours or when feed fingerprints change.
- Detects new agents every 5 minutes.

## Created Indices

```text
wazuh-vuln-enriched-YYYY.MM.DD
wazuh-vuln-cve-summary-YYYY.MM.DD
wazuh-vuln-host-summary-YYYY.MM.DD
wazuh-vuln-host-cve-impact-YYYY.MM.DD
```

Dashboards should read these indices, not `wazuh-states-vulnerabilities-*` directly.

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
Daily fallback   -> full refresh
```

The inventory watcher uses a watermark in `STATE_FILE`:

```text
last_inventory_timestamp
pending_inventory_agents
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
```

Important statuses:

- `confirmed_affected`: Wazuh finding is active and Ubuntu OVAL says the installed package version is lower than the fixed version.
- `likely_affected`: Ubuntu OVAL/OSV confirms the CVE/package, but the fixed version is missing or the installed version cannot be compared.
- `installed_version_at_or_above_fixed`: the installed version appears to be at or above the Ubuntu fixed version. Re-run Wazuh vulnerability detection if this still appears as active.
- `vendor_not_found`: Wazuh reported the CVE, but the CVE/package was not found in the cached Ubuntu OVAL feed for that release.

This makes PoC/KEV findings easier to triage because a high-priority row can now show whether Canonical confirms the host package is affected and whether a fixed version exists.

For Ubuntu kernel packages, Wazuh usually reports binary package names such as `linux-image-6.8.0-36-generic`. Canonical tracks kernel vulnerabilities primarily under source package names such as `linux`. The enricher maps common kernel binary package names back to `linux` so these CVEs do not incorrectly show as `vendor_not_found`.

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

Example:

```text
CRITICAL - Exploited CVEs detected

Summary:
- Affected agents: 2
- P0 CVEs: 4
- KEV CVEs: 2
- Public PoC CVEs: 1
- EPSS >= 0.7: 3

Top CVEs:
1. CVE-2025-0001 | KEV=yes | PoC=yes | EPSS=0.94 | CVSS=9.8 | hosts=72 | package=openssl
```

## Dashboard

Create these data views:

```text
wazuh-vuln-enriched-*       time field: enriched_at
wazuh-vuln-cve-summary-*    time field: updated_at
wazuh-vuln-host-cve-impact-* time field: updated_at
```

The imported dashboard intentionally contains only the operational panels:

- Impact Filters.
- Public PoC CVEs Impacting This System.
- Hosts Affected by Public PoC CVEs.

Dashboard import is optional and separate from enrichment:

```bash
python3 dashboard/manage_saved_objects.py reimport --no-verify-ssl
```

The filter and host impact panels use `wazuh-vuln-host-cve-impact-*`. This index has one document per `cve_id + agent_id`, so the host table is not duplicated by package/version. It has two dropdowns:

```text
impact_cve_id
impact_host
```

Those fields are only written for findings where `public_poc:true`, so the dropdowns do not list global/non-impact CVEs.
The imported controls use the `.keyword` subfields for terms aggregation.
The enriched data view uses `enriched_at` as its time field so host impact tables show the latest enrichment state instead of hiding older findings by `detected_at`.

The CVE summary panel reads `wazuh-vuln-cve-summary-*` with:

```text
public_poc:true and affected_hosts_count > 0
```

This shows only public-PoC CVEs that Wazuh has actually detected on your agents, not a global internet PoC list.

## Quick Checks

Public PoC CVEs impacting this system:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/wazuh-vuln-cve-summary-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":25,"query":{"bool":{"filter":[{"term":{"public_poc":true}},{"range":{"affected_hosts_count":{"gte":1}}}]}},"sort":[{"risk_score":"desc"},{"affected_hosts_count":"desc"}]}'
```

Hosts affected by public PoC CVEs:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/wazuh-vuln-enriched-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":100,"query":{"term":{"public_poc":true}},"sort":[{"risk_score":"desc"}]}'
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
