import zipfile

from tools.build_poc_feed import PocEntry, build_poc_feed, nuclei_entries, source_directory, trickest_entries, write_csv


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


def test_build_poc_feed_from_nuclei_source(tmp_path):
    template = tmp_path / "nuclei-templates" / "CVE-2026-0002.yaml"
    template.parent.mkdir(parents=True)
    template.write_text(
        """
id: CVE-2026-0002
info:
  name: Example
  classification:
    cve-id: CVE-2026-0002
""",
        encoding="utf-8",
    )
    output = tmp_path / "cve_poc.csv"

    count = build_poc_feed(output=output, nuclei_templates=str(tmp_path / "nuclei-templates"))

    assert count == 1
    assert "CVE-2026-0002" in output.read_text(encoding="utf-8")


def test_source_directory_supports_zip_archive(tmp_path):
    source_root = tmp_path / "repo-main"
    source_root.mkdir()
    (source_root / "CVE-2026-0003.md").write_text("https://example.com/poc\n", encoding="utf-8")
    archive = tmp_path / "repo.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.write(source_root / "CVE-2026-0003.md", "repo-main/CVE-2026-0003.md")

    with source_directory(str(archive)) as extracted:
        entries = list(trickest_entries(extracted))

    assert entries[0].cve == "CVE-2026-0003"
