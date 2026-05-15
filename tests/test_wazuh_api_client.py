from wazuh_api_client import WazuhManagerApiClient


def test_sca_policy_docs_for_agents_builds_index_docs():
    api = object.__new__(WazuhManagerApiClient)
    api.iter_items = lambda path, params=None: iter(
        [
            {
                "policy_id": "ubuntu-workaround-verification",
                "name": "Ubuntu workaround verification",
            }
        ]
        if path == "/sca/001"
        else [
            {
                "id": "100001",
                "title": "workaround:CVE-2026-31431:algif_aead_manual_disable_config",
                "result": "passed",
            }
        ]
    )

    docs = api.sca_policy_docs_for_agents(
        [{"agent_id": "001", "agent_name": "ubuntu-1"}],
        policy_query="workaround",
    )

    assert len(docs) == 1
    assert docs[0]["agent"]["id"] == "001"
    assert docs[0]["policy"]["id"] == "ubuntu-workaround-verification"
    assert docs[0]["check"]["title"].startswith("workaround:CVE-2026-31431")
    assert docs[0]["result"] == "passed"
