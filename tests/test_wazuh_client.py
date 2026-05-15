from types import SimpleNamespace

from wazuh_client import WazuhIndexerClient


def test_looks_like_ip_field_accepts_wazuh_inventory_ip_fields():
    assert WazuhIndexerClient._looks_like_ip_field("agent.host.ip", {"ip": {}})
    assert WazuhIndexerClient._looks_like_ip_field("host.ip", {"keyword": {}})
    assert WazuhIndexerClient._looks_like_ip_field("network.ip", {"ip": {}})
    assert WazuhIndexerClient._looks_like_ip_field("interface.ip", {"keyword": {}})
    assert WazuhIndexerClient._looks_like_ip_field("related.ip", {"text": {}})


def test_looks_like_ip_field_rejects_unrelated_fields():
    assert not WazuhIndexerClient._looks_like_ip_field("package.name", {"keyword": {}})
    assert not WazuhIndexerClient._looks_like_ip_field("host.os.name", {"keyword": {}})


def test_sca_workaround_results_parse_cve_from_check_title():
    client = object.__new__(WazuhIndexerClient)
    client.settings = SimpleNamespace(
        sca_workaround_enabled=True,
        wazuh_sca_index_pattern="wazuh-states-sca-*",
        sca_workaround_query="workaround CVE",
        scroll_ttl="5m",
        page_size=2000,
    )
    client._scroll_sources = lambda index, body, ignore_unavailable=False: iter(
        [
            {
                "agent": {"id": "001"},
                "policy": {"id": "ubuntu-workarounds"},
                "check": {
                    "id": "100001",
                    "title": "workaround:CVE-2026-31431:algif_aead_not_loaded",
                    "result": "passed",
                },
            }
        ]
    )

    records = client.sca_workaround_results()

    assert records[("001", "CVE-2026-31431")]["mitigation_status"] == "mitigated"
    assert records[("001", "CVE-2026-31431")]["workaround_verified"] is True
    assert records[("001", "CVE-2026-31431")]["workaround_check_passed"] == 1


def test_sca_workaround_query_body_can_scan_workaround_policy():
    client = object.__new__(WazuhIndexerClient)
    body = client._sca_workaround_query_body("workaround CVE")

    should = body["query"]["bool"]["should"]
    assert any("bool" in item for item in should)
    assert "_source" not in body


def test_sca_workaround_results_accepts_succeeded_result():
    client = object.__new__(WazuhIndexerClient)
    client.settings = SimpleNamespace(
        sca_workaround_enabled=True,
        wazuh_sca_index_pattern="wazuh-states-sca-*",
        sca_workaround_query="workaround CVE",
        scroll_ttl="5m",
        page_size=2000,
    )
    client._scroll_sources = lambda index, body, ignore_unavailable=False: iter(
        [
            {
                "agent": {"id": "001"},
                "policy": {"id": "ubuntu-workaround-verification"},
                "check": {
                    "id": "100001",
                    "title": "workaround:CVE-2026-31431:algif_aead_manual_disable_config",
                    "status": "succeeded",
                },
            }
        ]
    )

    records = client.sca_workaround_results()

    assert records[("001", "CVE-2026-31431")]["mitigation_status"] == "mitigated"


def test_sca_workaround_results_parse_alternate_nested_fields():
    client = object.__new__(WazuhIndexerClient)
    client.settings = SimpleNamespace(
        sca_workaround_enabled=True,
        wazuh_sca_index_pattern="wazuh-states-sca-*",
        sca_workaround_query="workaround CVE",
        scroll_ttl="5m",
        page_size=2000,
    )
    client._scroll_sources = lambda index, body, ignore_unavailable=False: iter(
        [
            {
                "data": {
                    "agent": {"id": "002"},
                    "policy": {"id": "ubuntu-workaround-verification"},
                    "check": {
                        "id": "100001",
                        "title": "workaround:CVE-2026-31431:algif_aead_manual_disable_config",
                        "result": "passed",
                    },
                }
            }
        ]
    )

    records = client.sca_workaround_results()

    assert records[("002", "CVE-2026-31431")]["mitigation_status"] == "mitigated"
