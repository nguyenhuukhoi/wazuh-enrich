import logging
import sys
from typing import Any

import requests

from risk import epss_bucket
from state import StateStore
from summary import build_cve_summary

LOG = logging.getLogger(__name__)

PATCH_DECISION_ORDER = {
    "patch_now": 0,
    "workaround_active": 1,
    "needs_review": 2,
    "patch_scheduled": 3,
    "cleanup_old_kernel": 4,
    "monitor": 5,
    "no_action": 6,
}
ALERT_SCOPES = {"critical_real_impact", "needs_review", "patch_scheduled", "all"}
HOST_MATCH_FIELDS = {"agent_id", "agent_name", "agent_ip", "host"}


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def as_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, ""):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def normalize_cve_id(value: Any) -> str:
    return str(value or "").strip().upper()


def normalize_match_value(value: Any) -> str:
    return str(value or "").strip().lower()


def finding_dedup_key(doc: dict[str, Any]) -> str:
    return "|".join(
        [
            str(doc.get("cve_id", "")),
            str(doc.get("agent_id", "")),
            str(doc.get("package_name", "")),
            str(doc.get("package_version", "")),
        ]
    )


class AlertManager:
    def __init__(
        self,
        bot_token: str,
        chat_id: str,
        thresholds: dict[str, Any],
        state: StateStore,
        timeout: int = 30,
        dry_run: bool = False,
    ):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.thresholds = thresholds
        self.state = state
        self.timeout = timeout
        self.dry_run = dry_run
        self.send_all_alerts = as_bool(thresholds.get("send_all_alerts", False))
        self.send_all_impacted_cves = as_bool(thresholds.get("send_all_impacted_cves", False))
        self.public_poc_only = as_bool(thresholds.get("public_poc_only", False))
        self.alert_interval_seconds = as_int(thresholds.get("alert_interval_seconds", 0), 0)
        self.alert_scope = str(thresholds.get("alert_scope", "critical_real_impact")).strip().lower()
        if self.alert_scope not in ALERT_SCOPES:
            LOG.warning("invalid_alert_scope scope=%s fallback=critical_real_impact", self.alert_scope)
            self.alert_scope = "critical_real_impact"
        self.muted_alerts = self._parse_muted_alerts(thresholds)

    def process_cycle(self, enriched_docs: list[dict[str, Any]], cve_summaries: list[dict[str, Any]]) -> None:
        if self._cycle_alert_throttled():
            return
        alert_docs, alert_summaries = self._alert_inputs(enriched_docs, cve_summaries)
        alert_state_backup = {
            "alert_dedup_keys": dict(self.state.data.get("alert_dedup_keys", {})),
            "last_kev_status_by_cve": dict(self.state.data.get("last_kev_status_by_cve", {})),
            "last_epss_threshold_by_cve": dict(self.state.data.get("last_epss_threshold_by_cve", {})),
        }
        interesting = self._new_interesting_cves(alert_summaries)
        delivered = True
        if interesting:
            if self.send_message(self._format_critical_alert(interesting, alert_docs)) is not False:
                self.state.mark_alert_type_sent("cycle")
            else:
                delivered = False
                self.state.data.update(alert_state_backup)

        if delivered:
            for doc in alert_docs:
                if doc.get("priority") in {"P0", "P1"}:
                    key = f"finding|{finding_dedup_key(doc)}"
                    if not self.state.was_alert_sent(key):
                        self.state.mark_alert_sent(key)

    def process_new_agent_baseline(self, agent_id: str, agent_name: str, enriched_docs: list[dict[str, Any]]) -> None:
        epss_high = float(self.thresholds.get("epss_high", 0.7))
        alert_docs = self._filter_muted_docs(enriched_docs)
        cve_summaries = [
            cve
            for cve in build_cve_summary(alert_docs)
            if self._scope_matches(cve, epss_high) and (not self.public_poc_only or cve.get("public_poc"))
        ]
        if not cve_summaries:
            return
        key = f"new-agent|{agent_id}|baseline|{self.alert_scope}"
        if not self.send_all_alerts and self.state.was_alert_sent(key):
            return
        if not self.send_all_alerts:
            self.state.mark_alert_sent(key)
        cve_summaries = sorted(
            cve_summaries,
            key=lambda doc: (
                PATCH_DECISION_ORDER.get(str(doc.get("patch_decision", "monitor")), 99),
                -float(doc.get("risk_score", 0.0)),
            ),
        )
        sent = self.send_message(
            self._format_critical_alert(
                cve_summaries,
                alert_docs,
                extra_summary_lines=[f"- New agent baseline: {agent_id} {agent_name}".rstrip()],
            )
        )
        if sent is False and not self.send_all_alerts:
            self.state.data.setdefault("alert_dedup_keys", {}).pop(key, None)

    @staticmethod
    def _parse_muted_alerts(thresholds: dict[str, Any]) -> list[dict[str, str]]:
        raw_items: list[Any] = []
        for key in ("muted_alerts", "suppress_alerts", "suppressed_alerts"):
            value = thresholds.get(key)
            if isinstance(value, list):
                raw_items.extend(value)
        for cve in thresholds.get("muted_cves", []) or []:
            raw_items.append({"cve_id": cve})

        rules = []
        for item in raw_items:
            if isinstance(item, str):
                item = {"cve_id": item}
            if not isinstance(item, dict):
                continue
            cve_id = normalize_cve_id(item.get("cve_id") or item.get("cve"))
            if not cve_id:
                continue
            rule = {"cve_id": cve_id}
            for field in HOST_MATCH_FIELDS:
                value = normalize_match_value(item.get(field))
                if value:
                    rule[field] = value
            rules.append(rule)
        return rules

    def _alert_inputs(
        self,
        enriched_docs: list[dict[str, Any]],
        cve_summaries: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        if not self.muted_alerts:
            return enriched_docs, cve_summaries

        filtered_summaries = [cve for cve in cve_summaries if not self._is_cve_globally_muted(cve)]
        if not enriched_docs:
            return enriched_docs, filtered_summaries

        filtered_docs = self._filter_muted_docs(enriched_docs)
        if len(filtered_docs) != len(enriched_docs):
            return filtered_docs, build_cve_summary(filtered_docs)
        return filtered_docs, filtered_summaries

    def _filter_muted_docs(self, docs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not self.muted_alerts:
            return docs
        return [doc for doc in docs if not self._is_doc_muted(doc)]

    def _is_cve_globally_muted(self, cve: dict[str, Any]) -> bool:
        cve_id = normalize_cve_id(cve.get("cve_id"))
        return any(rule["cve_id"] == cve_id and not self._rule_has_host_scope(rule) for rule in self.muted_alerts)

    def _is_doc_muted(self, doc: dict[str, Any]) -> bool:
        cve_id = normalize_cve_id(doc.get("cve_id"))
        for rule in self.muted_alerts:
            if rule["cve_id"] != cve_id:
                continue
            if not self._rule_has_host_scope(rule):
                return True
            if self._host_rule_matches(rule, doc):
                return True
        return False

    @staticmethod
    def _rule_has_host_scope(rule: dict[str, str]) -> bool:
        return any(field in rule for field in HOST_MATCH_FIELDS)

    @staticmethod
    def _host_rule_matches(rule: dict[str, str], doc: dict[str, Any]) -> bool:
        if "agent_id" in rule and normalize_match_value(doc.get("agent_id")) != rule["agent_id"]:
            return False
        if "agent_name" in rule and normalize_match_value(doc.get("agent_name")) != rule["agent_name"]:
            return False
        if "agent_ip" in rule and normalize_match_value(doc.get("agent_ip")) != rule["agent_ip"]:
            return False
        if "host" in rule:
            host_values = {
                normalize_match_value(doc.get("agent_id")),
                normalize_match_value(doc.get("agent_name")),
                normalize_match_value(doc.get("agent_ip")),
                normalize_match_value(doc.get("impact_host")),
            }
            return rule["host"] in host_values
        return True

    def _cycle_alert_throttled(self) -> bool:
        if self.alert_interval_seconds <= 0:
            return False
        elapsed, last_sent = self.state.alert_interval_elapsed("cycle", self.alert_interval_seconds)
        if elapsed:
            return False
        LOG.info(
            "alert_interval_skip type=cycle last_sent=%s interval_seconds=%s",
            last_sent.isoformat() if last_sent else "",
            self.alert_interval_seconds,
        )
        return True

    def _new_interesting_cves(self, cve_summaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        selected = []
        epss_high = float(self.thresholds.get("epss_high", 0.7))
        epss_medium = float(self.thresholds.get("epss_medium", 0.3))
        many_agents = int(self.thresholds.get("cve_many_agents", 25))
        for cve in cve_summaries:
            if self.public_poc_only and not cve.get("public_poc"):
                continue
            cve_id = str(cve.get("cve_id", ""))
            if not self._scope_matches(cve, epss_high):
                continue
            kev = bool(cve.get("kev"))
            epss = float(cve.get("epss_score", 0.0))
            priority = cve.get("priority")
            hosts = int(cve.get("affected_hosts_count", 0))

            kev_transition, _prev_kev = self.state.update_kev_status(cve_id, kev)
            bucket_changed, _prev_bucket = self.state.update_epss_bucket(cve_id, epss_bucket(epss))

            keys = []
            if self.alert_scope != "all":
                keys.append(f"cve-scope|{self.alert_scope}|{cve_id}")
            if self.send_all_impacted_cves and hosts > 0:
                keys.append(f"cve-impacted|{cve_id}")
            if kev:
                keys.append(f"cve-kev|{cve_id}|{kev}")
            if kev_transition:
                keys.append(f"cve-kev-transition|{cve_id}|true")
            if priority == "P0":
                keys.append(f"cve-priority|{cve_id}|P0")
            if epss >= epss_high:
                keys.append(f"cve-epss|{cve_id}|{epss_bucket(epss)}")
            elif epss >= epss_medium and bucket_changed:
                keys.append(f"cve-epss|{cve_id}|{epss_bucket(epss)}")
            if hosts >= many_agents:
                keys.append(f"cve-many-agents|{cve_id}|{hosts // many_agents}")

            if self.send_all_alerts:
                if keys:
                    selected.append(cve)
                continue

            new_keys = [key for key in keys if not self.state.was_alert_sent(key)]
            if new_keys:
                for key in new_keys:
                    self.state.mark_alert_sent(key)
                selected.append(cve)

        return sorted(
            selected,
            key=lambda doc: (
                PATCH_DECISION_ORDER.get(str(doc.get("patch_decision", "monitor")), 99),
                -float(doc.get("risk_score", 0.0)),
            ),
        )

    def _format_critical_alert(
        self,
        cves: list[dict[str, Any]],
        enriched_docs: list[dict[str, Any]],
        extra_summary_lines: list[str] | None = None,
    ) -> str:
        epss_high = float(self.thresholds.get("epss_high", 0.7))
        max_top = int(self.thresholds.get("max_top_cves", 10))
        top_cves = cves if max_top <= 0 else cves[:max_top]
        cve_ids = {str(cve.get("cve_id", "")) for cve in cves}
        affected_agent_ids = {
            str(doc.get("agent_id"))
            for doc in enriched_docs
            if doc.get("agent_id") and str(doc.get("cve_id", "")) in cve_ids
        }
        affected_fallback = sum(int(cve.get("affected_hosts_count", 0)) for cve in cves)
        affected_label = "Affected agents" if affected_agent_ids else "Affected host-CVE pairs"
        affected_value = len(affected_agent_ids) if affected_agent_ids else affected_fallback
        lines = [
            f"CRITICAL - {self._scope_label()} CVEs impacting system",
            "",
            "Summary:",
            f"- Alert scope: {self.alert_scope}",
            *(extra_summary_lines or []),
            f"- {affected_label}: {affected_value}",
            f"- Patch now CVEs: {len([cve for cve in cves if cve.get('patch_decision') == 'patch_now'])}",
            f"- Needs review CVEs: {len([cve for cve in cves if cve.get('patch_decision') == 'needs_review'])}",
            f"- Vendor confirmed affected: {len([cve for cve in cves if cve.get('verification_status') in {'confirmed_affected', 'likely_affected'}])}",
            f"- Fix available CVEs: {len([cve for cve in cves if cve.get('fix_available')])}",
            f"- P0 CVEs: {len([cve for cve in cves if cve.get('priority') == 'P0'])}",
            f"- KEV CVEs: {len([cve for cve in cves if cve.get('kev')])}",
            f"- Public PoC CVEs: {len([cve for cve in cves if cve.get('public_poc')])}",
            f"- EPSS >= {epss_high}: {len([cve for cve in cves if float(cve.get('epss_score', 0.0)) >= epss_high])}",
            "",
            "Top CVEs to decide patching:",
        ]
        lines.extend(self._format_summary_line(index + 1, cve) for index, cve in enumerate(top_cves))
        return "\n".join(lines)

    def _scope_matches(self, cve: dict[str, Any], epss_high: float) -> bool:
        if self.alert_scope == "all":
            return True

        patch = str(cve.get("patch_decision", ""))
        verification = str(cve.get("verification_status", ""))
        exploitability = str(cve.get("exploitability_status", ""))
        epss = float(cve.get("epss_score", 0.0))
        has_exploit_signal = exploitability == "exploited_in_wild" or bool(cve.get("public_poc")) or epss >= epss_high

        if self.alert_scope == "critical_real_impact":
            return (
                patch == "patch_now"
                and verification in {"confirmed_affected", "likely_affected"}
                and has_exploit_signal
            )
        if self.alert_scope == "needs_review":
            return patch == "needs_review" or (
                verification in {"vendor_not_found", "needs_manual_check", "not_verified"}
                and (bool(cve.get("kev")) or bool(cve.get("public_poc")) or epss >= epss_high)
            )
        if self.alert_scope == "patch_scheduled":
            return patch in {"patch_scheduled", "cleanup_old_kernel", "workaround_active"}
        return False

    def _scope_label(self) -> str:
        labels = {
            "critical_real_impact": "Critical Real Impact",
            "needs_review": "Needs Review",
            "patch_scheduled": "Patch Scheduled",
            "all": "Dangerous",
        }
        return labels.get(self.alert_scope, "Critical Real Impact")

    @staticmethod
    def _format_summary_line(index: int, cve: dict[str, Any]) -> str:
        packages = cve.get("affected_packages") or []
        package = packages[0] if packages else "-"
        action = str(cve.get("recommended_action", "")).strip()
        if len(action) > 120:
            action = f"{action[:117]}..."
        return (
            f"{index}. {cve.get('cve_id')} | patch={cve.get('patch_decision', 'monitor')} "
            f"| Ubuntu={cve.get('verification_status', 'not_verified')} "
            f"| mitigation={cve.get('mitigation_status', 'unknown')} "
            f"| exploit={cve.get('exploitability_status', 'unknown')} "
            f"| KEV={'yes' if cve.get('kev') else 'no'} | PoC={'yes' if cve.get('public_poc') else 'no'} "
            f"| EPSS={float(cve.get('epss_score', 0.0)):.2f} "
            f"| CVSS={float(cve.get('cvss_score', 0.0)):.1f} "
            f"| hosts={cve.get('affected_hosts_count', 0)} | package={package} "
            f"| fix={'yes' if cve.get('fix_available') else 'no'}"
            + (f" | action={action}" if action else "")
        )

    @staticmethod
    def _format_cve_line(index: int, doc: dict[str, Any]) -> str:
        return (
            f"{index}. {doc.get('cve_id')} | {doc.get('priority')} "
            f"| KEV={'yes' if doc.get('kev') else 'no'} "
            f"| EPSS={float(doc.get('epss_score', 0.0)):.2f} "
            f"| CVSS={float(doc.get('cvss_score', 0.0)):.1f} "
            f"| package={doc.get('package_name', '-')}"
        )

    def send_message(self, message: str) -> bool:
        if self.dry_run:
            print("\n=== DRY RUN ALERT ===", file=sys.stderr)
            print(message, file=sys.stderr)
            print("=== END DRY RUN ALERT ===\n", file=sys.stderr)
            LOG.info("dry_run_alert rendered=true")
            return True
        if not self.bot_token or not self.chat_id:
            LOG.warning("telegram_not_configured alert_skipped=true")
            return False
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        response = requests.post(
            url,
            json={"chat_id": self.chat_id, "text": message},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return True
