from feed_sync import EpssRecord, PocRecord
from feed_sync import UbuntuOvalRecord
from risk import calculate_risk_score, classify_priority, deb_version_compare, first_valid_ip, normalize_finding, verify_ubuntu_impact


def test_priority_p0_for_kev():
    priority, reason = classify_priority(True, 0.01, 4.3)

    assert priority == "P0"
    assert "CISA KEV" in reason


def test_priority_p0_for_high_epss_and_cvss():
    priority, reason = classify_priority(False, 0.71, 8.8)

    assert priority == "P0"
    assert "EPSS" in reason


def test_priority_p1_for_high_cvss():
    priority, reason = classify_priority(False, 0.01, 9.8)

    assert priority == "P1"
    assert "CVSS" in reason


def test_risk_score_formula():
    assert calculate_risk_score(True, 0.7, 9.0) == 92.0


def test_normalize_finding_handles_missing_optional_fields():
    source = {
        "agent": {"id": "001", "name": "ubuntu-1"},
        "host": {"os": {"name": "Ubuntu", "version": "24.04"}},
        "vulnerability": {
            "id": "CVE-2025-0001",
            "score": {"base": 9.8},
            "detected_at": "2026-05-09T00:00:00Z",
        },
        "package": {"name": "openssl", "version": "1.2.3"},
    }

    doc = normalize_finding(
        source,
        kev_cves={"CVE-2025-0001"},
        epss_records={"CVE-2025-0001": EpssRecord(score=0.94, percentile=0.99)},
    )

    assert doc is not None
    assert doc["cve_year"] == 2025
    assert doc["priority"] == "P0"
    assert doc["kev"] is True
    assert doc["package_name"] == "openssl"
    assert doc["public_poc"] is False


def test_normalize_finding_adds_public_poc_fields():
    source = {
        "agent": {"id": "001", "name": "ubuntu-1"},
        "vulnerability": {"id": "CVE-2026-0001", "score": {"base": 7.8}},
        "package": {"name": "sudo", "version": "1.9"},
    }

    doc = normalize_finding(
        source,
        kev_cves=set(),
        epss_records={},
        poc_records={
            "CVE-2026-0001": PocRecord(
                count=1,
                references=("https://example.com/poc",),
                sources=("internal",),
            )
        },
    )

    assert doc is not None
    assert doc["public_poc"] is True
    assert doc["impact_cve_id"] == "CVE-2026-0001"
    assert doc["impact_agent_id"] == "001"
    assert doc["impact_host"] == "ubuntu-1"
    assert doc["poc_count"] == 1
    assert doc["poc_references"] == ["https://example.com/poc"]
    assert "public PoC available" in doc["reason"]


def test_normalize_finding_skips_unspecified_agent_ip_for_host_ip_fallback():
    source = {
        "agent": {"id": "002", "name": "ubuntu-2", "ip": "0.0.0.0"},
        "host": {"ip": ["10.10.10.25"], "os": {"name": "Ubuntu"}},
        "vulnerability": {"id": "CVE-2026-0002", "score": {"base": 5.0}},
        "package": {"name": "kernel", "version": "1"},
    }

    doc = normalize_finding(source, kev_cves=set(), epss_records={})

    assert doc is not None
    assert doc["agent_ip"] == "10.10.10.25"


def test_normalize_finding_uses_inventory_metadata_for_agent_ip():
    source = {
        "agent": {"id": "002", "name": "ubuntu-2", "ip": "0.0.0.0"},
        "vulnerability": {"id": "CVE-2026-0003", "score": {"base": 5.0}},
        "package": {"name": "kernel", "version": "1"},
    }

    doc = normalize_finding(
        source,
        kev_cves=set(),
        epss_records={},
        agent_metadata={"002": {"agent_ip": "10.10.10.26", "os_name": "Ubuntu", "os_version": "24.04"}},
    )

    assert doc is not None
    assert doc["agent_ip"] == "10.10.10.26"
    assert doc["os_name"] == "Ubuntu"
    assert doc["os_version"] == "24.04"


def test_first_valid_ip_prefers_ipv4_over_ipv6_link_local():
    source = {
        "network": {"ip": ["fe80::f816:3eff:feac:c25d", "2.11.3.143"]},
    }

    assert first_valid_ip(source, ["network.ip"]) == "2.11.3.143"


def test_first_valid_ip_ignores_ipv6_link_local_when_it_is_the_only_ip():
    source = {"network": {"ip": "fe80::f816:3eff:feac:c25d"}}

    assert first_valid_ip(source, ["network.ip"]) == ""


def test_deb_version_compare_handles_ubuntu_revisions():
    assert deb_version_compare("3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.5") < 0
    assert deb_version_compare("3.0.13-0ubuntu3.5", "3.0.13-0ubuntu3.5") == 0
    assert deb_version_compare("1:2.0-1", "2.0-1") > 0


def test_verify_ubuntu_impact_confirms_affected_when_installed_version_is_lower():
    records = {
        ("noble", "CVE-2026-0001", "openssl"): UbuntuOvalRecord(
            cve_id="CVE-2026-0001",
            release="noble",
            package_name="openssl",
            fixed_version="3.0.13-0ubuntu3.5",
            severity="High",
            advisory_url="https://ubuntu.com/security/notices/USN-9999-1",
        )
    }

    result = verify_ubuntu_impact(
        "CVE-2026-0001",
        "Ubuntu",
        "24.04",
        "openssl",
        "3.0.13-0ubuntu3.4",
        records,
    )

    assert result["verification_status"] == "confirmed_affected"
    assert result["fix_available"] is True
    assert result["vendor_fixed_version"] == "3.0.13-0ubuntu3.5"


def test_normalize_finding_adds_ubuntu_verification_fields():
    source = {
        "agent": {"id": "001", "name": "ubuntu-1"},
        "host": {"os": {"name": "Ubuntu", "version": "24.04"}},
        "vulnerability": {"id": "CVE-2026-0001", "score": {"base": 7.8}},
        "package": {"name": "openssl", "version": "3.0.13-0ubuntu3.4"},
    }
    records = {
        ("noble", "CVE-2026-0001", "openssl"): UbuntuOvalRecord(
            cve_id="CVE-2026-0001",
            release="noble",
            package_name="openssl",
            fixed_version="3.0.13-0ubuntu3.5",
        )
    }

    doc = normalize_finding(source, kev_cves=set(), epss_records={}, ubuntu_records=records)

    assert doc is not None
    assert doc["verification_status"] == "confirmed_affected"
    assert doc["ubuntu_release"] == "noble"
