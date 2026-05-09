from tools.build_poc_feed import PocEntry, nuclei_entries, trickest_entries, write_csv


def test_nuclei_entries_extract_cve_and_reference(tmp_path):
    template = tmp_path / "nuclei-templates" / "http" / "cves" / "2026" / "CVE-2026-0001.yaml"
    template.parent.mkdir(parents=True)
    template.write_text(
        """
id: CVE-2026-0001
info:
  name: Example
  classification:
    cve-id: CVE-2026-0001
  reference:
    - https://example.com/advisory
""",
        encoding="utf-8",
    )

    entries = list(nuclei_entries(tmp_path / "nuclei-templates"))

    assert entries[0].cve == "CVE-2026-0001"
    assert entries[0].url == "https://example.com/advisory"
    assert entries[0].source == "ProjectDiscovery nuclei-templates"


def test_trickest_entries_extract_first_url(tmp_path):
    markdown = tmp_path / "cve" / "2026" / "CVE-2026-0001.md"
    markdown.parent.mkdir(parents=True)
    markdown.write_text("[PoC](https://example.com/poc)\n", encoding="utf-8")

    entries = list(trickest_entries(tmp_path / "cve"))

    assert entries[0].cve == "CVE-2026-0001"
    assert entries[0].url == "https://example.com/poc"
    assert entries[0].source == "trickest/cve"


def test_write_csv_deduplicates_rows(tmp_path):
    output = tmp_path / "cve_poc.csv"
    count = write_csv(
        [
            PocEntry("CVE-2026-0001", "https://example.com/poc", "test"),
            PocEntry("CVE-2026-0001", "https://example.com/poc", "test"),
        ],
        output,
    )

    assert count == 1
    assert output.read_text(encoding="utf-8").count("CVE-2026-0001") == 1
