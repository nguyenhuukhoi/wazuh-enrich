# Wazuh Vulnerability Enrichment Dashboard

This dashboard is intentionally small. It keeps only the two views needed to answer the operational question: which public-PoC CVEs are impacting this system, and which hosts/packages are affected?

It reads only:

- `wazuh-vuln-cve-summary-*`
- `wazuh-vuln-enriched-*`

Do not build these panels directly on `wazuh-states-vulnerabilities-*` for daily operations.

## Import

Import:

```text
dashboard/wazuh-vuln-enrichment.ndjson
```

The import creates 5 saved objects:

- Data view: `wazuh-vuln-cve-summary-*`
- Data view: `wazuh-vuln-enriched-*`
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
- `poc_references`
- `reason`

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

## Agent IP

The enricher ignores placeholder IPs like `0.0.0.0` and tries these fields in order:

```text
agent.ip
agent.host.ip
host.ip
related.ip
```

If `agent_ip` is still empty after `enrich-all`, the raw Wazuh vulnerability document does not contain a real agent IP in those fields.
