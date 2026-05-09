# Wazuh Vulnerability Enrichment Dashboard

This dashboard is designed for OpenSearch Dashboards and Wazuh Dashboard. It reads only enriched and summary indices:

- `wazuh-vuln-enriched-*`
- `wazuh-vuln-cve-summary-*`
- `wazuh-vuln-host-summary-*`

Do not build panels directly on `wazuh-states-vulnerabilities-*` for daily operations. The enricher already performs batch reads from the raw Wazuh vulnerability inventory and writes compact summary indices.

## Quick Import

Import the ready-made saved objects file:

```text
dashboard/wazuh-vuln-enrichment.ndjson
```

Steps:

1. Open Wazuh Dashboard or OpenSearch Dashboards.
2. Go to `Stack Management` or `Dashboards Management`.
3. Open `Saved Objects`.
4. Click `Import`.
5. Select `dashboard/wazuh-vuln-enrichment.ndjson`.
6. Enable overwrite if you are re-importing an updated version.
7. Open dashboard `Wazuh Vulnerability Enrichment Overview`.

The import creates:

- Data views/index patterns for enriched, CVE summary, and host summary indices.
- Dropdown controls for public PoC CVE, priority, KEV, and affected host.
- Metric cards for active findings, unique CVEs, P0, KEV, public PoC, and vulnerable agents.
- Public PoC CVEs impacting this system.
- Hosts affected by public PoC CVEs, including host, package, installed version, EPSS, CVSS, and recommended action.
- CVE and host impact saved searches.
- KEV CVE table.
- Priority/year/package charts.

After importing, refresh the field list for each data view if a table shows unknown fields:

- `wazuh-vuln-enriched-*`
- `wazuh-vuln-cve-summary-*`
- `wazuh-vuln-host-summary-*`

You can rebuild the NDJSON after editing dashboard definitions:

```bash
python3 dashboard/build_saved_objects.py
```

## Delete Or Reimport

You can manage imported saved objects with:

```bash
export WAZUH_DASHBOARD_URL="https://127.0.0.1:443"
export WAZUH_INDEXER_USERNAME="admin"
export WAZUH_INDEXER_PASSWORD="your-password"
```

List matching saved objects:

```bash
python3 dashboard/manage_saved_objects.py list --no-verify-ssl
```

Preview deletion:

```bash
python3 dashboard/manage_saved_objects.py delete --dry-run --no-verify-ssl
```

Delete the imported dashboard, panel objects, and related data views:

```bash
python3 dashboard/manage_saved_objects.py delete --no-verify-ssl
```

Delete and import again:

```bash
python3 dashboard/manage_saved_objects.py reimport --no-verify-ssl
```

If you imported into a non-default tenant, add:

```bash
--tenant global
```

## Index Patterns

Create these data views:

| Data view | Time field |
| --- | --- |
| `wazuh-vuln-enriched-*` | `detected_at` |
| `wazuh-vuln-cve-summary-*` | `updated_at` |
| `wazuh-vuln-host-summary-*` | `updated_at` |

## Required Controls

The import includes an `Impact Filters` control panel. It contains:

- `Public PoC CVE impacting system`: dropdown on `cve_id`, filtered by `public_poc:true`.
- `Priority`: dropdown on `priority`.
- `KEV`: dropdown on `kev`.
- `Affected host`: dropdown on `agent_name`.

Optional extra controls to add manually:

- `cve_year`: 2024, 2025, 2026.
- `agent_id`: search box.
- `os_name`: dropdown.
- `epss_score`: range slider.
- `cvss_score`: range slider.
- `package_name` or `affected_packages`: search box.
- `detected_at`, `first_detected_at`, `last_detected_at`: time picker.

## Overview Cards

Use metric visualizations:

- Total agents: unique count of `agent_id` on `wazuh-vuln-enriched-*`
- Vulnerable agents: unique count of `agent_id` on `wazuh-vuln-host-summary-*`
- Total active CVE findings: count on `wazuh-vuln-enriched-*`
- Unique CVEs: unique count of `cve_id` on `wazuh-vuln-cve-summary-*`
- P0 CVEs: count where `priority:P0`
- P1 CVEs: count where `priority:P1`
- KEV CVEs: count where `kev:true`
- EPSS >= 0.7 CVEs: count where `epss_score >= 0.7`
- New CVEs in last 24h: count where `first_detected_at >= now-24h`
- New CVEs in last 7d: count where `first_detected_at >= now-7d`

## Tables

### CVE Impact Overview

Data view: `wazuh-vuln-cve-summary-*`

Columns:

- `cve_id`
- `priority`
- `kev`
- `epss_score`
- `epss_percentile`
- `public_poc`
- `poc_count`
- `cvss_score`
- `affected_hosts_count`
- `affected_packages`
- `first_detected_at`
- `last_detected_at`
- `reason`

Sort by `risk_score` descending, then `affected_hosts_count` descending.

### Public PoC CVEs Impacting This System

Data view: `wazuh-vuln-cve-summary-*`

Filter:

- `public_poc:true`

Columns:

- `cve_id`
- `priority`
- `kev`
- `public_poc`
- `poc_count`
- `epss_score`
- `cvss_score`
- `affected_hosts_count`
- `affected_packages`
- `poc_references`
- `reason`

This table answers: which public-PoC CVEs currently affect the system?

### Hosts Affected By Public PoC CVEs

Data view: `wazuh-vuln-enriched-*`

Filter:

- `public_poc:true`

Columns:

- `cve_id`
- `priority`
- `kev`
- `public_poc`
- `poc_count`
- `agent_id`
- `agent_name`
- `agent_ip`
- `os_name`
- `os_version`
- `package_name`
- `package_version`
- `epss_score`
- `cvss_score`
- `detected_at`
- `poc_references`
- `recommended_action`

This table answers: which hosts and packages are affected by CVEs that already have public PoC metadata?

### Host Impact Overview

Data view: `wazuh-vuln-host-summary-*`

Columns:

- `agent_id`
- `agent_name`
- `agent_ip`
- `os_name`
- `os_version`
- `total_cves`
- `p0_count`
- `p1_count`
- `kev_count`
- `highest_epss`
- `highest_cvss`
- `top_packages`
- `last_scan_time`

Sort by `p0_count` descending, then `kev_count` descending, then `highest_epss` descending.

## Drill Downs

### CVE Drill Down

Filter `wazuh-vuln-enriched-*` by selected `cve_id`.

Show:

- `cve_id`, `kev`, `epss_score`, `cvss_score`, `priority`, `reason`
- PoC status: `public_poc`, `poc_count`, `poc_references`, `poc_sources`
- Affected hosts: `agent_id`, `agent_name`, `agent_ip`, `os_name`, `os_version`
- Package: `package_name`, `package_version`, `package_architecture`, `package_type`
- `detected_at`
- `recommended_action`

### Host Drill Down

Filter `wazuh-vuln-enriched-*` by selected `agent_id`.

Show:

- Host info: `agent_id`, `agent_name`, `agent_ip`
- OS info: `os_name`, `os_version`
- Total CVEs, CVEs by `priority`, KEV CVEs, high EPSS CVEs
- Packages affected by count
- Timeline over `detected_at`

## Visualizations

- Metric cards
- CVE summary table
- Host summary table
- CVE count by year: terms on `cve_year`
- CVE count by priority: terms on `priority`
- KEV trend: date histogram on `last_detected_at`, filter `kev:true`
- Top affected hosts: terms on `agent_name`, metric count or `total_cves`
- Top affected packages: terms on `package_name` or `affected_packages`
- New findings over time: date histogram on `detected_at`
- Public PoC CVEs: metric/table filtered by `public_poc:true`
