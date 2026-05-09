# Wazuh Vulnerability Enrichment

Vietnamese version: [README.vi.md](README.vi.md)

Production-oriented vulnerability enrichment for Wazuh 4.14.x. The service reads Wazuh vulnerability findings from Wazuh Indexer, enriches them with CISA KEV, FIRST EPSS, and PoC metadata, writes enriched/summary indices, and sends aggregate alerts.

This phase does not use NVD, does not call EPSS per CVE, and does not continuously query each agent.

## Production Flow

```text
Wazuh vulnerability findings
        ↓
sync KEV + EPSS + build/sync PoC feed
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
- Runs incremental enrichment every 15 minutes.
- Runs full refresh every 24 hours or when feed fingerprints change.
- Detects new agents every 5 minutes.

## Created Indices

```text
wazuh-vuln-enriched-YYYY.MM.DD
wazuh-vuln-cve-summary-YYYY.MM.DD
wazuh-vuln-host-summary-YYYY.MM.DD
```

Dashboards should read these indices, not `wazuh-states-vulnerabilities-*` directly.

## Install

```bash
sudo mkdir -p /opt/wazuh-enrich
sudo chown -R "$USER:$USER" /opt/wazuh-enrich
cd /opt/wazuh-enrich

python3.10 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Create:

```bash
sudo nano /etc/wazuh-enrich.env
```

Example:

```bash
WAZUH_INDEXER_URL=https://127.0.0.1:9200
WAZUH_INDEXER_USERNAME=admin
WAZUH_INDEXER_PASSWORD=your-password
WAZUH_CA_CERT=/etc/filebeat/certs/root-ca.pem
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
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
  output_file: feeds/cve_poc.csv
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
  --output feeds/cve_poc.csv
```

PoC fields written to enriched/summary docs:

```text
public_poc
poc_count
poc_references
poc_sources
```

## First Run

Load env:

```bash
set -a
. /etc/wazuh-enrich.env
set +a
```

Sync feeds:

```bash
python3 vuln_enricher.py sync-feeds
```

Dry-run:

```bash
python3 vuln_enricher.py --dry-run --log-format text enrich-all
```

Run real enrichment:

```bash
python3 vuln_enricher.py enrich-all
```

Check indices:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/_cat/indices/wazuh-vuln-*?v"
```

## systemd

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
EnvironmentFile=/etc/wazuh-enrich.env
ExecStart=/opt/wazuh-enrich/.venv/bin/python3 /opt/wazuh-enrich/vuln_enricher.py daemon
Restart=always
RestartSec=10
User=wazuh-enrich
Group=wazuh-enrich

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
python3 vuln_enricher.py sync-feeds
python3 vuln_enricher.py build-poc-feed
python3 vuln_enricher.py sync-poc
python3 vuln_enricher.py enrich-all
python3 vuln_enricher.py enrich-agent --agent-id 001
python3 vuln_enricher.py detect-new-agents
python3 vuln_enricher.py run-once
python3 vuln_enricher.py daemon
```

Logs default to JSON. For terminal reading:

```bash
python3 vuln_enricher.py --log-format text --dry-run run-once
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
wazuh-vuln-enriched-*       time field: detected_at
wazuh-vuln-cve-summary-*    time field: updated_at
wazuh-vuln-host-summary-*   time field: updated_at
```

Important panels:

- Public PoC CVEs Impacting This System.
- Hosts Affected by Public PoC CVEs.
- CVE Impact Overview.
- Host Impact Overview.
- P0/KEV/Public PoC metrics.

Dashboard import is optional and separate from enrichment:

```bash
python3 dashboard/manage_saved_objects.py reimport --no-verify-ssl
```

## Quick Checks

Public PoC CVEs:

```bash
curl -sk -u "$WAZUH_INDEXER_USERNAME:$WAZUH_INDEXER_PASSWORD" \
  "$WAZUH_INDEXER_URL/wazuh-vuln-cve-summary-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":25,"query":{"term":{"public_poc":true}},"sort":[{"risk_score":"desc"}]}'
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
- PoC not visible: enable `POC_BUILD`, run `build-poc-feed`, then `enrich-all`.
- Dashboard slow: use summary indices, not raw Wazuh state indices.

## Tests

```bash
python3 -m pytest -q
python3 -m py_compile config.py feed_sync.py risk.py alerts.py state.py summary.py wazuh_client.py vuln_enricher.py
```
