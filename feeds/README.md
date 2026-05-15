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

## Workaround Files

`cve_workarounds.yaml` contains curated workaround metadata:

```yaml
workarounds:
  - cve_id: CVE-2026-31431
    workaround_id: copy-fail-algif-aead
    review_status: needs_review
    executor: ansible
    playbook: playbooks/cve_2026_31431_copy_fail.yml
```

You can build candidate metadata from vendor pages:

```bash
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml build-workaround-feed --cve CVE-2026-31431
python3 vuln_enricher.py --config /etc/wazuh-enrich/config.yaml build-workaround-feed --from-latest-impact
```

Review every candidate before using it. The collector does not verify or apply mitigation.

`workaround_results.json` is written by Ansible after apply/verify:

```json
[
  {
    "agent_id": "001",
    "cve_id": "CVE-2026-31431",
    "verify_status": "passed",
    "checks": {
      "kmod_fixed_or_manual_disable": true,
      "algif_aead_not_loaded": true
    }
  }
]
```

Set:

```yaml
WORKAROUND_FEED_FILE: /var/lib/wazuh-enrich/feeds/cve_workarounds.yaml
WORKAROUND_RESULT_FILE: /var/lib/wazuh-enrich/feeds/workaround_results.json
```
