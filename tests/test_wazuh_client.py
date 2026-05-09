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
