from workaround import build_mitigation_records, load_workaround_feed, load_workaround_results


def test_load_workaround_feed_and_ansible_results(tmp_path):
    feed = tmp_path / "cve_workarounds.yaml"
    feed.write_text(
        """
workarounds:
  - cve_id: CVE-2026-31431
    workaround_id: copy-fail-algif-aead
    title: Copy Fail algif_aead mitigation
    source_url: https://ubuntu.com/blog/copy-fail-vulnerability-fixes-available
    executor: ansible
    playbook: playbooks/cve_2026_31431_copy_fail.yml
""",
        encoding="utf-8",
    )
    results = tmp_path / "workaround_results.json"
    results.write_text(
        """
[
  {
    "agent_id": "001",
    "cve_id": "CVE-2026-31431",
    "workaround_id": "copy-fail-algif-aead",
    "source": "ansible",
    "apply_status": "applied",
    "verify_status": "passed",
    "verified_at": "2026-05-15T10:30:00Z",
    "checks": {
      "kmod_fixed_or_manual_disable": true,
      "algif_aead_not_loaded": true
    },
    "evidence": {
      "kmod_version": "31+20240202-2ubuntu7.2"
    }
  }
]
""",
        encoding="utf-8",
    )

    records = build_mitigation_records(load_workaround_feed(feed), load_workaround_results(results))

    fallback = records[("*", "CVE-2026-31431")]
    assert fallback["workaround_available"] is True
    assert fallback["mitigation_status"] == "unknown"

    record = records[("001", "CVE-2026-31431")]
    assert record["mitigation_status"] == "mitigated"
    assert record["workaround_verified"] is True
    assert record["workaround_check_passed"] == 2
    assert record["workaround_id"] == "copy-fail-algif-aead"
    assert record["workaround_source_url"].startswith("https://ubuntu.com")


def test_failed_check_overrides_mitigated_status(tmp_path):
    results = tmp_path / "workaround_results.json"
    results.write_text(
        """
[
  {
    "agent_id": "001",
    "cve_id": "CVE-2026-31431",
    "verify_status": "passed",
    "checks": {
      "kmod_fixed_or_manual_disable": true,
      "algif_aead_not_loaded": false
    }
  }
]
""",
        encoding="utf-8",
    )

    records = load_workaround_results(results)

    assert records[("001", "CVE-2026-31431")]["mitigation_status"] == "not_mitigated"
    assert records[("001", "CVE-2026-31431")]["workaround_check_failed"] == 1
