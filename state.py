import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOG = logging.getLogger(__name__)


DEFAULT_STATE: dict[str, Any] = {
    "seen_agents": [],
    "last_processed_timestamp": None,
    "last_kev_status_by_cve": {},
    "last_epss_threshold_by_cve": {},
    "alert_dedup_keys": {},
    "feed_fingerprints": {},
}


class StateStore:
    def __init__(self, path: Path):
        self.path = path
        self.data = self.load()

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return json.loads(json.dumps(DEFAULT_STATE))
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                loaded = json.load(handle)
            state = json.loads(json.dumps(DEFAULT_STATE))
            state.update(loaded)
            return state
        except (json.JSONDecodeError, OSError) as exc:
            LOG.warning("state_load_failed path=%s error=%s", self.path, exc)
            return json.loads(json.dumps(DEFAULT_STATE))

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(self.data, handle, indent=2, sort_keys=True)
        tmp.replace(self.path)

    def mark_agent_seen(self, agent_id: str) -> None:
        seen = set(self.data.setdefault("seen_agents", []))
        seen.add(str(agent_id))
        self.data["seen_agents"] = sorted(seen)

    def is_agent_seen(self, agent_id: str) -> bool:
        return str(agent_id) in set(self.data.get("seen_agents", []))

    def mark_alert_sent(self, key: str) -> None:
        self.data.setdefault("alert_dedup_keys", {})[key] = datetime.now(timezone.utc).isoformat()

    def was_alert_sent(self, key: str) -> bool:
        return key in self.data.get("alert_dedup_keys", {})

    def set_last_processed_timestamp(self, timestamp: str | None) -> None:
        if timestamp:
            self.data["last_processed_timestamp"] = timestamp

    def update_kev_status(self, cve_id: str, kev: bool) -> tuple[bool, bool | None]:
        current = bool(kev)
        previous = self.data.setdefault("last_kev_status_by_cve", {}).get(cve_id)
        self.data["last_kev_status_by_cve"][cve_id] = current
        return previous is not None and previous is False and current is True, previous

    def update_epss_bucket(self, cve_id: str, bucket: str) -> tuple[bool, str | None]:
        previous = self.data.setdefault("last_epss_threshold_by_cve", {}).get(cve_id)
        self.data["last_epss_threshold_by_cve"][cve_id] = bucket
        return previous is not None and previous != bucket, previous
