import logging
from typing import Any

import requests

from risk import epss_bucket
from state import StateStore

LOG = logging.getLogger(__name__)


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

    def process_cycle(self, enriched_docs: list[dict[str, Any]], cve_summaries: list[dict[str, Any]]) -> None:
        interesting = self._new_interesting_cves(cve_summaries)
        if interesting:
            self.send_message(self._format_critical_alert(interesting))

        for doc in enriched_docs:
            if doc.get("priority") in {"P0", "P1"}:
                key = f"finding|{finding_dedup_key(doc)}"
                if not self.state.was_alert_sent(key):
                    self.state.mark_alert_sent(key)

    def process_new_agent_baseline(self, agent_id: str, agent_name: str, enriched_docs: list[dict[str, Any]]) -> None:
        priority_docs = [doc for doc in enriched_docs if doc.get("priority") in {"P0", "P1"}]
        if not priority_docs:
            return
        key = f"new-agent|{agent_id}|baseline-p0-p1"
        if self.state.was_alert_sent(key):
            return
        self.state.mark_alert_sent(key)
        top = sorted(priority_docs, key=lambda doc: float(doc.get("risk_score", 0.0)), reverse=True)[:10]
        lines = [
            "CRITICAL - New agent baseline has high-risk CVEs",
            "",
            "Summary:",
            f"- Agent: {agent_id} {agent_name}".rstrip(),
            f"- P0/P1 findings: {len(priority_docs)}",
            f"- Unique CVEs: {len({doc.get('cve_id') for doc in priority_docs})}",
            "",
            "Top CVEs:",
        ]
        lines.extend(self._format_cve_line(index + 1, doc) for index, doc in enumerate(top))
        self.send_message("\n".join(lines))

    def _new_interesting_cves(self, cve_summaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        selected = []
        epss_high = float(self.thresholds.get("epss_high", 0.7))
        epss_medium = float(self.thresholds.get("epss_medium", 0.3))
        many_agents = int(self.thresholds.get("cve_many_agents", 25))
        for cve in cve_summaries:
            cve_id = str(cve.get("cve_id", ""))
            kev = bool(cve.get("kev"))
            epss = float(cve.get("epss_score", 0.0))
            priority = cve.get("priority")
            hosts = int(cve.get("affected_hosts_count", 0))

            kev_transition, _prev_kev = self.state.update_kev_status(cve_id, kev)
            bucket_changed, _prev_bucket = self.state.update_epss_bucket(cve_id, epss_bucket(epss))

            keys = []
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

            new_keys = [key for key in keys if not self.state.was_alert_sent(key)]
            if new_keys:
                for key in new_keys:
                    self.state.mark_alert_sent(key)
                selected.append(cve)

        return sorted(selected, key=lambda doc: float(doc.get("risk_score", 0.0)), reverse=True)

    def _format_critical_alert(self, cves: list[dict[str, Any]]) -> str:
        epss_high = float(self.thresholds.get("epss_high", 0.7))
        max_top = int(self.thresholds.get("max_top_cves", 10))
        affected_agents = sum(int(cve.get("affected_hosts_count", 0)) for cve in cves)
        lines = [
            "CRITICAL - Exploited CVEs detected",
            "",
            "Summary:",
            f"- Affected agents: {affected_agents}",
            f"- P0 CVEs: {len([cve for cve in cves if cve.get('priority') == 'P0'])}",
            f"- KEV CVEs: {len([cve for cve in cves if cve.get('kev')])}",
            f"- EPSS >= {epss_high}: {len([cve for cve in cves if float(cve.get('epss_score', 0.0)) >= epss_high])}",
            "",
            "Top CVEs:",
        ]
        lines.extend(self._format_summary_line(index + 1, cve) for index, cve in enumerate(cves[:max_top]))
        return "\n".join(lines)

    @staticmethod
    def _format_summary_line(index: int, cve: dict[str, Any]) -> str:
        packages = cve.get("affected_packages") or []
        package = packages[0] if packages else "-"
        return (
            f"{index}. {cve.get('cve_id')} | KEV={'yes' if cve.get('kev') else 'no'} "
            f"| EPSS={float(cve.get('epss_score', 0.0)):.2f} "
            f"| CVSS={float(cve.get('cvss_score', 0.0)):.1f} "
            f"| hosts={cve.get('affected_hosts_count', 0)} | package={package}"
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
            LOG.info("dry_run_alert message=%s", message)
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
