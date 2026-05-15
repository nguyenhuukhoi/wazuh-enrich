import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


ENV_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)\}")


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return ENV_PATTERN.sub(lambda match: os.getenv(match.group(1), ""), value)
    if isinstance(value, dict):
        return {key: _expand_env(val) for key, val in value.items()}
    if isinstance(value, list):
        return [_expand_env(item) for item in value]
    return value


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    wazuh_indexer_url: str
    wazuh_indexer_username: str
    wazuh_indexer_password: str
    wazuh_ca_cert: str
    verify_ssl: bool
    wazuh_vuln_index_pattern: str
    wazuh_sca_index_pattern: str
    sca_workaround_enabled: bool
    sca_workaround_query: str
    agent_inventory_index_patterns: list[str]
    inventory_watch_timestamp_fields: list[str]
    enriched_index_prefix: str
    cve_summary_index_prefix: str
    host_summary_index_prefix: str
    host_cve_impact_index_prefix: str
    cache_dir: Path
    state_file: Path
    page_size: int
    bulk_size: int
    request_timeout_seconds: int
    scroll_ttl: str
    cisa_kev_url: str
    cisa_kev_file: Path | None
    epss_url: str
    poc_feed_file: Path | None
    workaround_feed_file: Path | None
    workaround_result_file: Path | None
    workaround_verification_priority: str
    telegram_bot_token: str
    telegram_chat_id: str
    alert_thresholds: dict[str, Any]
    schedule: dict[str, int]
    poc_build: dict[str, Any]
    workaround_collector: dict[str, Any]
    ubuntu_oval: dict[str, Any]

    @property
    def ssl_verify_value(self) -> bool | str:
        if not self.verify_ssl:
            return False
        return self.wazuh_ca_cert or True


def load_config(path: str = "config.yaml") -> Settings:
    config_path = Path(path)
    with config_path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    cfg = _expand_env(raw)

    required = [
        "WAZUH_INDEXER_URL",
        "WAZUH_INDEXER_USERNAME",
        "WAZUH_INDEXER_PASSWORD",
        "WAZUH_VULN_INDEX_PATTERN",
        "ENRICHED_INDEX_PREFIX",
        "CACHE_DIR",
        "STATE_FILE",
        "PAGE_SIZE",
        "BULK_SIZE",
        "ALERT_THRESHOLDS",
    ]
    missing = [key for key in required if cfg.get(key) in (None, "")]
    if missing:
        raise ValueError(f"Missing required config values: {', '.join(missing)}")

    cache_dir = Path(cfg["CACHE_DIR"])
    state_file = Path(cfg["STATE_FILE"])
    cache_dir.mkdir(parents=True, exist_ok=True)
    state_file.parent.mkdir(parents=True, exist_ok=True)

    return Settings(
        wazuh_indexer_url=cfg["WAZUH_INDEXER_URL"].rstrip("/"),
        wazuh_indexer_username=cfg["WAZUH_INDEXER_USERNAME"],
        wazuh_indexer_password=cfg["WAZUH_INDEXER_PASSWORD"],
        wazuh_ca_cert=cfg.get("WAZUH_CA_CERT", ""),
        verify_ssl=_as_bool(cfg.get("VERIFY_SSL", True)),
        wazuh_vuln_index_pattern=cfg["WAZUH_VULN_INDEX_PATTERN"],
        wazuh_sca_index_pattern=cfg.get("WAZUH_SCA_INDEX_PATTERN", "wazuh-states-sca-*"),
        sca_workaround_enabled=_as_bool(cfg.get("SCA_WORKAROUND_ENABLED", False)),
        sca_workaround_query=str(cfg.get("SCA_WORKAROUND_QUERY", "workaround CVE")),
        agent_inventory_index_patterns=_as_list(
            cfg.get(
                "AGENT_INVENTORY_INDEX_PATTERNS",
                [
                    "wazuh-states-inventory-system-*",
                    "wazuh-states-inventory-packages-*",
                    "wazuh-states-inventory-hotfixes-*",
                    "wazuh-states-inventory-interfaces-*",
                    "wazuh-states-inventory-networks-*",
                ],
            )
        ),
        inventory_watch_timestamp_fields=_as_list(
            cfg.get("INVENTORY_WATCH_TIMESTAMP_FIELDS", ["@timestamp", "event.created", "timestamp"])
        ),
        enriched_index_prefix=cfg["ENRICHED_INDEX_PREFIX"],
        cve_summary_index_prefix=cfg.get("CVE_SUMMARY_INDEX_PREFIX", "wazuh-vuln-cve-summary"),
        host_summary_index_prefix=cfg.get("HOST_SUMMARY_INDEX_PREFIX", "wazuh-vuln-host-summary"),
        host_cve_impact_index_prefix=cfg.get("HOST_CVE_IMPACT_INDEX_PREFIX", "wazuh-vuln-host-cve-impact"),
        cache_dir=cache_dir,
        state_file=state_file,
        page_size=int(cfg["PAGE_SIZE"]),
        bulk_size=int(cfg["BULK_SIZE"]),
        request_timeout_seconds=int(cfg.get("REQUEST_TIMEOUT_SECONDS", 30)),
        scroll_ttl=str(cfg.get("SCROLL_TTL", "5m")),
        cisa_kev_url=cfg.get(
            "CISA_KEV_URL",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        ),
        cisa_kev_file=Path(cfg["CISA_KEV_FILE"]) if cfg.get("CISA_KEV_FILE") else None,
        epss_url=cfg.get("EPSS_URL", "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"),
        poc_feed_file=Path(cfg["POC_FEED_FILE"]) if cfg.get("POC_FEED_FILE") else _poc_build_output(cfg),
        workaround_feed_file=Path(cfg["WORKAROUND_FEED_FILE"]) if cfg.get("WORKAROUND_FEED_FILE") else None,
        workaround_result_file=Path(cfg["WORKAROUND_RESULT_FILE"]) if cfg.get("WORKAROUND_RESULT_FILE") else None,
        workaround_verification_priority=_normalize_workaround_priority(
            cfg.get("WORKAROUND_VERIFICATION_PRIORITY", "sca_first")
        ),
        telegram_bot_token=cfg.get("TELEGRAM_BOT_TOKEN", ""),
        telegram_chat_id=cfg.get("TELEGRAM_CHAT_ID", ""),
        alert_thresholds=cfg["ALERT_THRESHOLDS"],
        schedule={key: int(val) for key, val in cfg.get("SCHEDULE", {}).items()},
        poc_build=_normalize_poc_build(cfg.get("POC_BUILD", {})),
        workaround_collector=_normalize_workaround_collector(cfg.get("WORKAROUND_COLLECTOR", {})),
        ubuntu_oval=_normalize_ubuntu_oval(cfg.get("UBUNTU_OVAL", {})),
    )


def _normalize_poc_build(raw: dict[str, Any]) -> dict[str, Any]:
    cfg = dict(raw or {})
    cfg["enabled"] = _as_bool(cfg.get("enabled", False))
    cfg["interval_seconds"] = int(cfg.get("interval_seconds", 86400) or 86400)
    if cfg.get("output_file"):
        cfg["output_file"] = str(cfg["output_file"])
    for key in ["exploitdb_csv", "nuclei_templates", "poc_in_github", "trickest_cve"]:
        if cfg.get(key) in ("", None):
            cfg[key] = None
    return cfg


def _normalize_workaround_collector(raw: dict[str, Any]) -> dict[str, Any]:
    cfg = dict(raw or {})
    cfg["enabled"] = _as_bool(cfg.get("enabled", False))
    cfg["interval_seconds"] = int(cfg.get("interval_seconds", 86400) or 86400)
    cfg["max_cves_per_run"] = int(cfg.get("max_cves_per_run", 100) or 100)
    cfg["timeout_seconds"] = int(cfg.get("timeout_seconds", 30) or 30)
    cfg["fetch_linked_pages"] = _as_bool(cfg.get("fetch_linked_pages", True))
    cfg["sources"] = _as_list(cfg.get("sources", ["ubuntu"]))
    cfg["include_patch_decisions"] = _as_list(
        cfg.get("include_patch_decisions", ["patch_now", "needs_review", "patch_scheduled"])
    )
    if cfg.get("output_file"):
        cfg["output_file"] = str(cfg["output_file"])
    return cfg


def _normalize_workaround_priority(value: Any) -> str:
    priority = str(value or "sca_first").strip().lower()
    if priority not in {"sca_first", "ansible_first"}:
        raise ValueError("WORKAROUND_VERIFICATION_PRIORITY must be sca_first or ansible_first")
    return priority


def _normalize_ubuntu_oval(raw: dict[str, Any]) -> dict[str, Any]:
    cfg = dict(raw or {})
    cfg["enabled"] = _as_bool(cfg.get("enabled", False))
    cfg["releases"] = _as_list(cfg.get("releases", ["noble"]))
    cfg["max_age_hours"] = int(cfg.get("max_age_hours", 24) or 24)
    cfg["base_url"] = str(cfg.get("base_url") or "https://security-metadata.canonical.com/oval")
    cfg["osv_enabled"] = _as_bool(cfg.get("osv_enabled", cfg["enabled"]))
    cfg["osv_url"] = str(cfg.get("osv_url") or "https://security-metadata.canonical.com/osv/osv-all.tar.xz")
    cfg["osv_max_age_hours"] = int(cfg.get("osv_max_age_hours", cfg["max_age_hours"]) or cfg["max_age_hours"])
    cfg["urls"] = cfg.get("urls", {}) or {}
    return cfg


def _poc_build_output(cfg: dict[str, Any]) -> Path | None:
    poc_build = _normalize_poc_build(cfg.get("POC_BUILD", {}))
    if poc_build.get("enabled") and poc_build.get("output_file"):
        return Path(str(poc_build["output_file"]))
    return None


def _as_list(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return [item.strip() for item in str(value).split(",") if item.strip()]
