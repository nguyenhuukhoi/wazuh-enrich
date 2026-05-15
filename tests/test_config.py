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
WORKAROUND_FEED_FILE: {tmp_path / "feeds" / "cve_workarounds.yaml"}
WORKAROUND_RESULT_FILE: {tmp_path / "feeds" / "workaround_results.json"}
WORKAROUND_VERIFICATION_PRIORITY: ansible_first
WORKAROUND_COLLECTOR:
  enabled: true
  output_file: {tmp_path / "feeds" / "cve_workarounds.yaml"}
  sources:
    - ubuntu
  max_cves_per_run: 25
""",
        encoding="utf-8",
    )

    settings = load_config(str(config_path))

    assert settings.poc_feed_file == Path(output_file)
    assert settings.workaround_feed_file == tmp_path / "feeds" / "cve_workarounds.yaml"
    assert settings.workaround_result_file == tmp_path / "feeds" / "workaround_results.json"
    assert settings.workaround_verification_priority == "ansible_first"
    assert settings.poc_build["enabled"] is True
    assert settings.workaround_collector["enabled"] is True
    assert settings.workaround_collector["output_file"] == str(tmp_path / "feeds" / "cve_workarounds.yaml")
    assert settings.workaround_collector["sources"] == ["ubuntu"]
    assert settings.workaround_collector["max_cves_per_run"] == 25
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
