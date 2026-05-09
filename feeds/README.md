# PoC Feed Directory

Place the generated `cve_poc.csv` here and set:

```bash
export POC_FEED_FILE="/opt/wazuh-enrich/feeds/cve_poc.csv"
```

The expected CSV format is:

```csv
cve,url,source
CVE-2026-0001,https://example.com/research-or-repo,Trusted Source
```

Use metadata links only. Do not store exploit code or cloned PoC repositories on production Wazuh infrastructure.
