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

    def process_cycle(self, enriched_docs: list[dict[str, Any]], cve_summaries: list[dict[str, Any]]) -> None:
        if self._cycle_alert_throttled():
            return
        interesting = self._new_interesting_cves(cve_summaries)
        if interesting:
            self.send_message(self._format_critical_alert(interesting, enriched_docs))
            self.state.mark_alert_type_sent("cycle")

        for doc in enriched_docs:
            if doc.get("priority") in {"P0", "P1"}:
                key = f"finding|{finding_dedup_key(doc)}"
                if not self.state.was_alert_sent(key):
                    self.state.mark_alert_sent(key)

    def process_new_agent_baseline(self, agent_id: str, agent_name: str, enriched_docs: list[dict[str, Any]]) -> None:
        epss_high = float(self.thresholds.get("epss_high", 0.7))
        cve_summaries = [
            cve
            for cve in build_cve_summary(enriched_docs)
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
        self.send_message(
            self._format_critical_alert(
                cve_summaries,
                enriched_docs,
                extra_summary_lines=[f"- New agent baseline: {agent_id} {agent_name}".rstrip()],
            )
        )

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

    def send_message(self, message: str) -> None:
        if self.dry_run:
            print("\n=== DRY RUN ALERT ===", file=sys.stderr)
            print(message, file=sys.stderr)
            print("=== END DRY RUN ALERT ===\n", file=sys.stderr)
            LOG.info("dry_run_alert rendered=true")
            return
        if not self.bot_token or not self.chat_id:
            LOG.warning("telegram_not_configured alert_skipped=true")
            return
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        response = requests.post(
            url,
            json={"chat_id": self.chat_id, "text": message},
            timeout=self.timeout,
        )
        response.raise_for_status()
