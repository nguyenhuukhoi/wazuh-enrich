from pathlib import Path

from config import load_config


def test_poc_build_output_becomes_poc_feed_file(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    output_file = tmp_path / "feeds" / "cve_poc.csv"
    config_path.write_text(
        f"""
WAZUH_INDEXER_URL: https://127.0.0.1:9200
WAZUH_INDEXER_USERNAME: admin
WAZUH_INDEXER_PASSWORD: secret
WAZUH_CA_CERT: ""
VERIFY_SSL: false
WAZUH_VULN_INDEX_PATTERN: wazuh-states-vulnerabilities-*
ENRICHED_INDEX_PREFIX: wazuh-vuln-enriched
CACHE_DIR: {tmp_path / "cache"}
STATE_FILE: {tmp_path / "cache" / "state.json"}
PAGE_SIZE: 2000
BULK_SIZE: 1000
ALERT_THRESHOLDS: {{}}
POC_BUILD:
  enabled: true
  output_file: {output_file}
""",
        encoding="utf-8",
    )

    settings = load_config(str(config_path))

    assert settings.poc_feed_file == Path(output_file)
    assert settings.poc_build["enabled"] is True
    assert settings.sca_workaround_enabled is False
    assert settings.wazuh_sca_index_pattern == "wazuh-states-sca-*"
    assert settings.sca_workaround_query == "workaround CVE"
    assert settings.host_cve_impact_index_prefix == "wazuh-vuln-host-cve-impact"
    assert settings.agent_inventory_index_patterns == [
        "wazuh-states-inventory-system-*",
        "wazuh-states-inventory-packages-*",
        "wazuh-states-inventory-hotfixes-*",
        "wazuh-states-inventory-interfaces-*",
        "wazuh-states-inventory-networks-*",
    ]
    assert settings.inventory_watch_timestamp_fields == ["@timestamp", "event.created", "timestamp"]
