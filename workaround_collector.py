import html
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urljoin
from urllib.request import Request, urlopen

import yaml


LOG = logging.getLogger(__name__)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>)\"']+", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")
SECTION_HEADING_RE = re.compile(r"^\s*(description|mitigation|status|notes|references|severity)\s*$", re.IGNORECASE)
MITIGATION_KEYWORDS = (
    "mitigation",
    "workaround",
    "disable",
    "disabled",
    "blacklist",
    "configuration",
    "upgrade",
    "update",
    "install",
)
NOISE_KEYWORDS = (
    "newsletter",
    "preferences",
    "successfully updated",
    "contacting us",
    "unsubscribe",
)


@dataclass(frozen=True)
class WorkaroundCandidate:
    cve_id: str
    workaround_id: str
    title: str
    source: str
    source_url: str
    notes: str
    collector: str
    confidence: str = "medium"
    review_status: str = "needs_review"
    executor: str = "ansible"
    playbook: str = ""
    collected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def as_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "workaround_id": self.workaround_id,
            "title": self.title,
            "source": self.source,
            "source_url": self.source_url,
            "collector": self.collector,
            "confidence": self.confidence,
            "review_status": self.review_status,
            "executor": self.executor,
            "playbook": self.playbook,
            "notes": self.notes,
            "collected_at": self.collected_at,
        }


def normalize_cve(cve_id: str) -> str:
    cve = str(cve_id or "").strip().upper()
    if not CVE_RE.match(cve):
        raise ValueError(f"Invalid CVE ID: {cve_id}")
    return cve


def build_workaround_feed(
    cves: Iterable[str],
    output: Path,
    *,
    existing_feed: Path | None = None,
    sources: Iterable[str] | None = None,
    timeout: int = 30,
    fetch_linked_pages: bool = True,
) -> int:
    enabled_sources = {source.lower() for source in sources} if sources is not None else {"ubuntu"}
    existing = load_existing_workarounds(existing_feed or output)
    candidates: list[dict[str, Any]] = list(existing)

    for cve in sorted({normalize_cve(cve_id) for cve_id in cves if str(cve_id).strip()}):
        found: list[WorkaroundCandidate] = []
        if "ubuntu" in enabled_sources:
            found.extend(collect_ubuntu_workarounds(cve, timeout=timeout, fetch_linked_pages=fetch_linked_pages))
        for candidate in found:
            candidates.append(candidate.as_dict())

    unique = dedupe_workarounds(candidates)
    write_workaround_feed(unique, output)
    return len(unique)


def collect_ubuntu_workarounds(
    cve_id: str,
    *,
    timeout: int = 30,
    fetch_linked_pages: bool = True,
    base_url: str = "https://ubuntu.com/security",
) -> list[WorkaroundCandidate]:
    cve = normalize_cve(cve_id)
    page_url = f"{base_url.rstrip('/')}/{cve}"
    try:
        raw = read_text(page_url, timeout=timeout)
    except Exception as exc:
        LOG.warning("ubuntu_workaround_fetch_failed cve=%s url=%s error=%s", cve, page_url, exc)
        return []
    candidates = collect_ubuntu_from_html(cve, raw, page_url)
    if not fetch_linked_pages:
        return candidates

    enriched: list[WorkaroundCandidate] = []
    for candidate in candidates:
        if candidate.source_url == page_url:
            enriched.append(candidate)
            continue
        try:
            linked_raw = read_text(candidate.source_url, timeout=timeout)
        except Exception as exc:
            LOG.debug("ubuntu_workaround_link_fetch_failed cve=%s url=%s error=%s", cve, candidate.source_url, exc)
            enriched.append(candidate)
            continue
        linked_notes = extract_relevant_notes(html_to_text(linked_raw), max_chars=900)
        if not linked_notes:
            enriched.append(candidate)
            continue
        enriched.append(
            WorkaroundCandidate(
                cve_id=candidate.cve_id,
                workaround_id=candidate.workaround_id,
                title=candidate.title,
                source=candidate.source,
                source_url=candidate.source_url,
                notes=linked_notes,
                collector=candidate.collector,
                confidence=candidate.confidence,
                review_status=candidate.review_status,
                executor=candidate.executor,
                playbook=candidate.playbook,
                collected_at=candidate.collected_at,
            )
        )
    return enriched


def collect_ubuntu_from_html(cve_id: str, raw_html: str, page_url: str) -> list[WorkaroundCandidate]:
    cve = normalize_cve(cve_id)
    text = html_to_text(raw_html)
    mitigation = extract_section(text, "Mitigation")
    notes = mitigation or extract_relevant_notes(text)
    if not notes:
        return []
    if not has_mitigation_signal(notes):
        return []

    urls = [urljoin(page_url, url.rstrip(".,;")) for url in URL_RE.findall(notes)]
    source_url = urls[0] if urls else page_url
    return [
        WorkaroundCandidate(
            cve_id=cve,
            workaround_id=f"ubuntu-{cve.lower()}-{slugify(source_url)}",
            title=f"Ubuntu workaround candidate for {cve}",
            source="Ubuntu Security",
            source_url=source_url,
            notes=compact_text(notes, max_chars=900),
            collector="ubuntu_cve_page",
            confidence="medium" if urls else "low",
            review_status="needs_review",
            executor="ansible",
        )
    ]


def load_existing_workarounds(path: Path | None) -> list[dict[str, Any]]:
    if not path or not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    records = data.get("workarounds", data) if isinstance(data, dict) else data
    if not isinstance(records, list):
        return []
    return [dict(item) for item in records if isinstance(item, dict)]


def write_workaround_feed(records: list[dict[str, Any]], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {"workarounds": sorted(records, key=lambda item: (str(item.get("cve_id", "")), str(item.get("source_url", ""))))}
    output.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=False), encoding="utf-8")


def dedupe_workarounds(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[tuple[str, str], dict[str, Any]] = {}
    for item in records:
        cve = str(item.get("cve_id", "")).strip().upper()
        if not CVE_RE.match(cve):
            continue
        normalized = {key: value for key, value in item.items() if value not in (None, "")}
        normalized["cve_id"] = cve
        source_url = str(normalized.get("source_url", normalized.get("source", ""))).strip()
        key = (cve, source_url or str(normalized.get("workaround_id", "")))
        previous = deduped.get(key, {})
        deduped[key] = {**normalized, **previous} if previous.get("review_status") == "approved" else {**previous, **normalized}
    return list(deduped.values())


def read_text(url: str, timeout: int = 30) -> str:
    request = Request(
        url,
        headers={"User-Agent": "wazuh-enrich-workaround-collector/1.0"},
    )
    with urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def html_to_text(raw_html: str) -> str:
    text = re.sub(r"(?i)<br\s*/?>", "\n", raw_html or "")
    text = re.sub(
        r"(?is)<a\s+[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
        lambda match: f"{match.group(2)} {match.group(1)}",
        text,
    )
    text = re.sub(r"(?i)</(p|div|li|h[1-6]|tr|section)>", "\n", text)
    text = TAG_RE.sub(" ", text)
    text = html.unescape(text)
    lines = [compact_text(line, max_chars=2000) for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def extract_section(text: str, heading: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    in_section = False
    sections: list[str] = []
    collected: list[str] = []
    for line in lines:
        if line.lower() == heading.lower():
            if collected:
                sections.append(compact_text(" ".join(collected), max_chars=1200))
                collected = []
            in_section = True
            continue
        if in_section and SECTION_HEADING_RE.match(line):
            if collected:
                sections.append(compact_text(" ".join(collected), max_chars=1200))
                collected = []
            in_section = False
            continue
        if in_section:
            collected.append(line)
    if collected:
        sections.append(compact_text(" ".join(collected), max_chars=1200))
    if not sections:
        return ""
    with_url = [section for section in sections if URL_RE.search(section) and has_mitigation_signal(section)]
    if with_url:
        return max(with_url, key=len)
    with_signal = [section for section in sections if has_mitigation_signal(section)]
    return max(with_signal or sections, key=len)


def extract_relevant_notes(text: str, max_chars: int = 700) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    relevant = [line for line in lines if has_mitigation_signal(line) and not is_noise(line)]
    return compact_text(" ".join(relevant[:8]), max_chars=max_chars)


def has_mitigation_signal(text: str) -> bool:
    lowered = (text or "").lower()
    return any(keyword in lowered for keyword in MITIGATION_KEYWORDS)


def is_noise(text: str) -> bool:
    lowered = (text or "").lower()
    return any(keyword in lowered for keyword in NOISE_KEYWORDS)


def compact_text(value: str, max_chars: int = 500) -> str:
    compacted = re.sub(r"\s+", " ", value or "").strip()
    compacted = re.sub(
        r"(?i)^in these regular emails you will find the latest updates about\s+",
        "",
        compacted,
    )
    compacted = re.sub(r"(?i)^your preferences have been successfully updated\.\s*", "", compacted)
    if len(compacted) <= max_chars:
        return compacted
    return compacted[: max_chars - 3].rstrip() + "..."


def slugify(value: str) -> str:
    cleaned = re.sub(r"^https?://", "", value.lower())
    cleaned = re.sub(r"[^a-z0-9]+", "-", cleaned).strip("-")
    return cleaned[:80] or "source"
