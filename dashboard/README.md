# Wazuh Vulnerability Enrichment Dashboard

This dashboard is intentionally small. It keeps only the views needed to answer the operational question: which dangerous CVEs are impacting this system, can they be exploited, did the vendor confirm impact, and should the system be patched now?

It reads only:

- `wazuh-vuln-cve-summary-latest`
- `wazuh-vuln-enriched-latest`
- `wazuh-vuln-host-cve-impact-latest`

Do not build these panels directly on `wazuh-states-vulnerabilities-*` for daily operations.
Do not point operational panels at `wazuh-vuln-*-*` wildcard daily indices, or the same CVE can appear once per day.

## Import

Import:

```text
dashboard/wazuh-vuln-enrichment.ndjson
```

The import creates 11 saved objects:

- Data view: `wazuh-vuln-cve-summary-latest`
- Data view: `wazuh-vuln-enriched-latest` with time field `enriched_at`
- Data view: `wazuh-vuln-host-cve-impact-latest`
- Visualization: `Impact Filters`
- Search: `Critical Real Impact CVEs`
- Search: `Hosts - Critical Real Impact`
- Search: `Needs Review CVEs`
- Search: `Hosts - Needs Review`
- Search: `Patch Scheduled CVEs`
- Search: `Hosts - Patch Scheduled`
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

Data view: `wazuh-vuln-host-cve-impact-latest`

Controls:

- `Dangerous CVE impacting system`: dropdown on `impact_cve_id.keyword`.
- `Host impacted by dangerous CVE`: dropdown on `impact_host.keyword`.
- `Ubuntu verification status`: dropdown on `verification_status.keyword`.
- `Fix status`: dropdown on `fix_status.keyword`.
- `Patch decision`: dropdown on `patch_decision.keyword`.

These fields come from `wazuh-vuln-host-cve-impact-latest`, which has one row per impacted CVE/host pair.

### Critical Real Impact

Data view: `wazuh-vuln-cve-summary-latest`

Filters:

- `affected_hosts_count >= 1`
- query: `patch_decision:patch_now and (verification_status:confirmed_affected or verification_status:likely_affected) and (exploitability_status:exploited_in_wild or public_poc:true or epss_score >= 0.7)`

This is the default alert scope. It means vendor confirms impact and there is an exploit signal.

### Needs Review

Data view: `wazuh-vuln-cve-summary-latest`

Filters:

- `affected_hosts_count >= 1`
- query: `patch_decision:needs_review or ((verification_status:vendor_not_found or verification_status:needs_manual_check or verification_status:not_verified) and (kev:true or public_poc:true or epss_score >= 0.7))`

This means the CVE has a strong threat signal, but vendor/package confirmation is incomplete.

### Patch Scheduled

Data view: `wazuh-vuln-cve-summary-latest`

Filters:

- `affected_hosts_count >= 1`
- query: `patch_decision:patch_scheduled or patch_decision:cleanup_old_kernel`

This means vendor confirms affected and patching should be planned, but it is not classified as immediate critical impact. It also includes `cleanup_old_kernel`, where an old vulnerable Ubuntu kernel package is still installed but is not the running kernel.

### Columns

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

### Host Tables

Data view: `wazuh-vuln-host-cve-impact-latest`

The three host tables mirror the same three CVE groups:

- `Hosts - Critical Real Impact`
- `Hosts - Needs Review`
- `Hosts - Patch Scheduled`

Each search panel is full-width on its own row so long fields such as `recommended_action`, `vendor_advisory_url`, and package lists stay readable.

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

The host impact table reads `wazuh-vuln-host-cve-impact-latest`, which has one document per `cve_id + agent_id`. Package names and versions are aggregated into list fields, so one CVE affecting the same host through multiple packages does not create duplicate host rows. Daily indices keep history, but the dashboard uses `latest` so one CVE does not appear once per daily index.

## Time Field

The imported `wazuh-vuln-enriched-latest` data view uses `enriched_at` as the time field. This keeps the host impact table aligned with the latest enrichment run. If it uses `detected_at`, the dashboard time picker can hide hosts whose vulnerability was detected earlier than the selected time range even though the host is still affected.
