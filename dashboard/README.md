# Wazuh Vulnerability Enrichment Dashboard

This dashboard is intentionally small. It keeps only the two views needed to answer the operational question: which public-PoC CVEs are impacting this system, and which hosts/packages are affected?

It reads only:

- `wazuh-vuln-cve-summary-*`
- `wazuh-vuln-enriched-*`
- `wazuh-vuln-host-cve-impact-*`

Do not build these panels directly on `wazuh-states-vulnerabilities-*` for daily operations.

## Import

Import:

```text
dashboard/wazuh-vuln-enrichment.ndjson
```

The import creates 7 saved objects:

- Data view: `wazuh-vuln-cve-summary-*`
- Data view: `wazuh-vuln-enriched-*` with time field `enriched_at`
- Data view: `wazuh-vuln-host-cve-impact-*`
- Visualization: `Impact Filters`
- Search: `Public PoC CVEs Impacting This System`
- Search: `Hosts Affected by Public PoC CVEs`
- Dashboard: `Wazuh Vulnerability Enrichment Overview`

Rebuild the NDJSON after editing definitions:

```bash
python3 dashboard/build_saved_objects.py
```

## Delete Or Reimport

```bash
export WAZUH_DASHBOARD_URL="https://127.0.0.1:443"
export WAZUH_INDEXER_USERNAME="admin"
export WAZUH_INDEXER_PASSWORD="your-password"
```

List:

```bash
python3 dashboard/manage_saved_objects.py list --no-verify-ssl
```

Delete and import again:

```bash
python3 dashboard/manage_saved_objects.py reimport --no-verify-ssl
```

If you imported into a non-default tenant, add:

```bash
--tenant global
```

## Panels

### Impact Filters

Data view: `wazuh-vuln-host-cve-impact-*`

Controls:

- `Public PoC CVE impacting system`: dropdown on `impact_cve_id.keyword`.
- `Host impacted by public PoC`: dropdown on `impact_host.keyword`.
- `Ubuntu verification status`: dropdown on `verification_status.keyword`.
- `Fix status`: dropdown on `fix_status.keyword`.

These fields are only written when `public_poc:true`, so the dropdowns only contain public-PoC CVEs and hosts currently affected by them.

### Public PoC CVEs Impacting This System

Data view: `wazuh-vuln-cve-summary-*`

Filters:

- `public_poc:true`
- `affected_hosts_count >= 1`

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
- `verification_status`
- `fix_available`
- `vendor_fixed_version`
- `vendor_advisory_url`
- `vendor_severity`
- `poc_references`
- `reason`

### Hosts Affected By Public PoC CVEs

Data view: `wazuh-vuln-host-cve-impact-*`

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
- `affected_packages`
- `affected_package_versions`
- `verification_status`
- `fix_available`
- `vendor_fixed_version`
- `vendor_advisory_url`
- `vendor_severity`
- `finding_count`
- `epss_score`
- `cvss_score`
- `last_detected_at`
- `poc_references`
- `recommended_action`

## Agent IP

The enricher ignores placeholder IPs like `0.0.0.0`. It first tries the vulnerability document, then joins Wazuh inventory documents by `agent.id`.

```text
agent.ip
agent.host.ip
host.ip
network.ip
interface.ip
related.ip
```

The default inventory indices are:

```text
wazuh-states-inventory-system-*
wazuh-states-inventory-interfaces-*
wazuh-states-inventory-networks-*
```

If `agent_ip` is still empty or `0.0.0.0` after `enrich-all`, check that those inventory indices contain a real `agent.host.ip` for the agent.

## Deduplication

The host impact table reads `wazuh-vuln-host-cve-impact-*`, which has one document per `cve_id + agent_id`. Package names and versions are aggregated into list fields, so one CVE affecting the same host through multiple packages does not create duplicate host rows.

## Time Field

The imported `wazuh-vuln-enriched-*` data view uses `enriched_at` as the time field. This keeps the host impact table aligned with the latest enrichment run. If it uses `detected_at`, the dashboard time picker can hide hosts whose vulnerability was detected earlier than the selected time range even though the host is still affected.
