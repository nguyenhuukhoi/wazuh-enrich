# Wazuh Vulnerability Enrichment Dashboard

This dashboard is designed for OpenSearch Dashboards and Wazuh Dashboard. It reads only enriched and summary indices:

- `wazuh-vuln-enriched-*`
- `wazuh-vuln-cve-summary-*`
- `wazuh-vuln-host-summary-*`

Do not build panels directly on `wazuh-states-vulnerabilities-*` for daily operations. The enricher already performs batch reads from the raw Wazuh vulnerability inventory and writes compact summary indices.

## Index Patterns

Create these data views:

| Data view | Time field |
| --- | --- |
| `wazuh-vuln-enriched-*` | `detected_at` |
| `wazuh-vuln-cve-summary-*` | `updated_at` |
| `wazuh-vuln-host-summary-*` | `updated_at` |

## Required Controls

Create filter controls for:

- `cve_year`: 2024, 2025, 2026
- `cve_id`: search box
- `agent_name`: search box
- `agent_id`: search box
- `os_name`: dropdown
- `priority`: dropdown
- `kev`: yes/no
- `epss_score`: range slider
- `cvss_score`: range slider
- `package_name` or `affected_packages`: search box
- `detected_at`, `first_detected_at`, `last_detected_at`: time picker

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
- `cvss_score`
- `affected_hosts_count`
- `affected_packages`
- `first_detected_at`
- `last_detected_at`
- `reason`

Sort by `risk_score` descending, then `affected_hosts_count` descending.

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
