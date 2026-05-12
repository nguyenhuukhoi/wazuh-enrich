from datetime import datetime, timedelta, timezone

from state import StateStore


def test_inventory_pending_agents_become_due_after_stabilization(tmp_path):
    state = StateStore(tmp_path / "state.json")
    queued_at = (datetime.now(timezone.utc) - timedelta(seconds=300)).isoformat()

    state.queue_inventory_agent("002", queued_at)

    assert state.due_inventory_agents(stabilization_seconds=180, limit=10) == ["002"]
    state.clear_pending_inventory_agent("002")
    assert state.due_inventory_agents(stabilization_seconds=180, limit=10) == []


def test_last_inventory_timestamp_is_saved(tmp_path):
    state = StateStore(tmp_path / "state.json")

    state.set_last_inventory_timestamp("2026-05-11T00:00:00Z")

    assert state.data["last_inventory_timestamp"] == "2026-05-11T00:00:00Z"


def test_alert_interval_elapsed_uses_last_alert_type_timestamp(tmp_path):
    state = StateStore(tmp_path / "state.json")
    old = (datetime.now(timezone.utc) - timedelta(seconds=7200)).isoformat()
    state.data["last_alert_sent_by_type"] = {"cycle": old}

    elapsed, last_sent = state.alert_interval_elapsed("cycle", 3600)

    assert elapsed is True
    assert last_sent is not None


def test_alert_interval_blocks_recent_alert_type_timestamp(tmp_path):
    state = StateStore(tmp_path / "state.json")
    recent = datetime.now(timezone.utc).isoformat()
    state.data["last_alert_sent_by_type"] = {"cycle": recent}

    elapsed, last_sent = state.alert_interval_elapsed("cycle", 3600)

    assert elapsed is False
    assert last_sent is not None
