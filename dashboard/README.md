# Wazuh Vulnerability Enrichment Dashboard

This dashboard is intentionally small. It keeps only the views needed to answer the operational question: which dangerous CVEs are impacting this system, can they be exploited, did the vendor confirm impact, and should the system be patched now?

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
- Search: `Dangerous CVEs Impacting This System`
- Search: `Hosts Affected by Dangerous CVEs`
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

- `Dangerous CVE impacting system`: dropdown on `impact_cve_id.keyword`.
- `Host impacted by dangerous CVE`: dropdown on `impact_host.keyword`.
- `Ubuntu verification status`: dropdown on `verification_status.keyword`.
- `Fix status`: dropdown on `fix_status.keyword`.
- `Patch decision`: dropdown on `patch_decision.keyword`.

These fields come from `wazuh-vuln-host-cve-impact-*`, which has one row per impacted CVE/host pair.

### Dangerous CVEs Impacting This System

Data view: `wazuh-vuln-cve-summary-*`

Filters:

- `affected_hosts_count >= 1`
- query: `patch_decision:patch_now or patch_decision:needs_review or kev:true or public_poc:true or epss_score >= 0.7`

Columns:

- `cve_id`
- `patch_decision`
- `impact_assessment`
- `verification_status`
- `exploitability_status`
- `kev`
- `public_poc`
- `fix_available`
- `vendor_fixed_version`
- `recommended_action`
- `affected_hosts_count`
- `affected_packages`
- `priority`
- `epss_score`
- `cvss_score`
- `exposure_status`
- `vendor_fixed_version`
- `vendor_advisory_url`
- `vendor_severity`
- `vendor_status`
- `poc_references`
- `reason`
- `recommended_action`

### Hosts Affected By Dangerous CVEs

Data view: `wazuh-vuln-host-cve-impact-*`

Query:

- `patch_decision:patch_now or patch_decision:needs_review or kev:true or public_poc:true or epss_score >= 0.7`

Columns:

- `cve_id`
- `patch_decision`
- `impact_assessment`
- `verification_status`
- `exploitability_status`
- `kev`
- `public_poc`
- `fix_available`
- `vendor_fixed_version`
- `recommended_action`
- `agent_id`
- `agent_name`
- `agent_ip`
- `affected_packages`
- `affected_package_versions`
- `priority`
- `epss_score`
- `cvss_score`
- `os_name`
- `os_version`
- `exposure_status`
- `vendor_fixed_version`
- `vendor_advisory_url`
- `vendor_severity`
- `vendor_status`
- `finding_count`
- `last_detected_at`
- `poc_count`
- `poc_references`

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
