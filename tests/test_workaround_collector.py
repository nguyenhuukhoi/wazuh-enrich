from workaround_collector import build_workaround_feed, collect_ubuntu_from_html


def test_collect_ubuntu_mitigation_link_from_cve_page():
    html = """
    <h1>CVE-2026-31431</h1>
    <h2>Mitigation</h2>
    <p>Please see the following link for mitigation information:
    https://ubuntu.com/blog/copy-fail-vulnerability-fixes-available</p>
    <h2>Status</h2>
    """

    candidates = collect_ubuntu_from_html("CVE-2026-31431", html, "https://ubuntu.com/security/CVE-2026-31431")

    assert len(candidates) == 1
    assert candidates[0].cve_id == "CVE-2026-31431"
    assert candidates[0].source == "Ubuntu Security"
    assert candidates[0].source_url == "https://ubuntu.com/blog/copy-fail-vulnerability-fixes-available"
    assert candidates[0].review_status == "needs_review"


def test_build_workaround_feed_merges_existing_approved_record(tmp_path):
    output = tmp_path / "cve_workarounds.yaml"
    output.write_text(
        """
workarounds:
  - cve_id: CVE-2026-31431
    workaround_id: manual-approved
    source_url: https://ubuntu.com/blog/copy-fail-vulnerability-fixes-available
    review_status: approved
    playbook: playbooks/manual.yml
""",
        encoding="utf-8",
    )

    count = build_workaround_feed(["CVE-2026-31431"], output, sources=[], fetch_linked_pages=False)

    assert count == 1
    assert "manual-approved" in output.read_text(encoding="utf-8")
    assert "playbooks/manual.yml" in output.read_text(encoding="utf-8")
