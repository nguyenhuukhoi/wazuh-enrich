import logging
from datetime import datetime, timezone
from typing import Any, Iterable

import requests

from risk import first_path

LOG = logging.getLogger(__name__)


class WazuhManagerApiClient:
    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        verify: bool | str = True,
        timeout: int = 30,
        page_limit: int = 500,
    ):
        if not url:
            raise ValueError("WAZUH_API_URL is required for SCA sync")
        if not username or not password:
            raise ValueError("WAZUH_API_USERNAME and WAZUH_API_PASSWORD are required for SCA sync")
        self.url = url.rstrip("/")
        self.username = username
        self.password = password
        self.verify = verify
        self.timeout = timeout
        self.page_limit = page_limit
        self.session = requests.Session()
        self._token: str | None = None

    def authenticate(self) -> str:
        response = self.session.post(
            f"{self.url}/security/user/authenticate",
            params={"raw": "true"},
            auth=(self.username, self.password),
            verify=self.verify,
            timeout=self.timeout,
        )
        response.raise_for_status()
        token = response.text.strip()
        if token.startswith("{"):
            payload = response.json()
            token = str(first_path(payload, ["data.token", "token"], ""))
        if not token:
            raise RuntimeError("Wazuh API authentication did not return a token")
        self._token = token
        return token

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self._token:
            self.authenticate()
        response = self.session.get(
            f"{self.url}/{path.lstrip('/')}",
            params=params or {},
            headers={"Authorization": f"Bearer {self._token}"},
            verify=self.verify,
            timeout=self.timeout,
        )
        if response.status_code == 401:
            self.authenticate()
            response = self.session.get(
                f"{self.url}/{path.lstrip('/')}",
                params=params or {},
                headers={"Authorization": f"Bearer {self._token}"},
                verify=self.verify,
                timeout=self.timeout,
            )
        response.raise_for_status()
        return response.json()

    def iter_items(self, path: str, params: dict[str, Any] | None = None) -> Iterable[dict[str, Any]]:
        offset = 0
        base = dict(params or {})
        while True:
            query = {**base, "limit": self.page_limit, "offset": offset}
            payload = self.get(path, query)
            data = payload.get("data") if isinstance(payload, dict) else {}
            items = data.get("affected_items", []) if isinstance(data, dict) else []
            if not items:
                break
            for item in items:
                if isinstance(item, dict):
                    yield item
            total = int(data.get("total_affected_items", 0) or 0)
            offset += len(items)
            if total and offset >= total:
                break
            if len(items) < self.page_limit:
                break

    def sca_policy_docs_for_agents(
        self,
        agents: list[dict[str, str]],
        policy_query: str = "workaround",
    ) -> list[dict[str, Any]]:
        docs: list[dict[str, Any]] = []
        synced_at = datetime.now(timezone.utc).isoformat()
        for agent in agents:
            agent_id = str(agent.get("agent_id") or agent.get("id") or "")
            if not agent_id:
                continue
            agent_name = str(agent.get("agent_name") or agent.get("name") or "")
            try:
                policies = list(self.iter_items(f"/sca/{agent_id}"))
            except Exception as exc:
                LOG.warning("wazuh_api_sca_policies_failed agent_id=%s error=%s", agent_id, exc)
                continue
            selected_policies = [policy for policy in policies if _matches_policy(policy, policy_query)]
            for policy in selected_policies:
                policy_id = _policy_id(policy)
                if not policy_id:
                    continue
                try:
                    checks = list(self.iter_items(f"/sca/{agent_id}/checks/{policy_id}"))
                except Exception as exc:
                    LOG.warning("wazuh_api_sca_checks_failed agent_id=%s policy_id=%s error=%s", agent_id, policy_id, exc)
                    continue
                for check in checks:
                    if not _matches_check(check, policy_query) and not _matches_policy(policy, policy_query):
                        continue
                    docs.append(_sca_doc(agent_id, agent_name, policy, check, synced_at))
        LOG.info("wazuh_api_sca_docs_loaded agents=%s docs=%s", len(agents), len(docs))
        return docs


def _matches_policy(policy: dict[str, Any], query: str) -> bool:
    text = " ".join(
        str(first_path(policy, [path], ""))
        for path in ["policy_id", "id", "name", "description", "file", "hash_file"]
    ).lower()
    needles = [part.lower() for part in str(query or "workaround").split() if part.strip()]
    return any(needle in text for needle in needles) or "workaround" in text


def _matches_check(check: dict[str, Any], query: str) -> bool:
    text = " ".join(
        str(first_path(check, [path], ""))
        for path in ["id", "title", "description", "rationale", "remediation", "result", "status"]
    ).lower()
    needles = [part.lower() for part in str(query or "workaround").split() if part.strip()]
    return any(needle in text for needle in needles) or "workaround:" in text or "cve-" in text


def _policy_id(policy: dict[str, Any]) -> str:
    return str(first_path(policy, ["policy_id", "id", "name"], "")).strip()


def _sca_doc(
    agent_id: str,
    agent_name: str,
    policy: dict[str, Any],
    check: dict[str, Any],
    synced_at: str,
) -> dict[str, Any]:
    policy_id = _policy_id(policy)
    check_id = str(first_path(check, ["id", "check_id"], "")).strip()
    result = str(first_path(check, ["result", "status"], "")).strip()
    return {
        "agent": {"id": agent_id, "name": agent_name},
        "policy": {
            "id": policy_id,
            "name": str(first_path(policy, ["name", "title"], policy_id)),
            "description": str(first_path(policy, ["description"], "")),
            "raw": policy,
        },
        "check": {
            "id": check_id,
            "title": str(first_path(check, ["title"], "")),
            "description": str(first_path(check, ["description"], "")),
            "rationale": str(first_path(check, ["rationale"], "")),
            "remediation": str(first_path(check, ["remediation"], "")),
            "result": result,
            "status": result,
            "raw": check,
        },
        "result": result,
        "status": result,
        "synced_at": synced_at,
    }
