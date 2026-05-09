from feed_sync import EpssRecord
from risk import calculate_risk_score, classify_priority, normalize_finding


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
