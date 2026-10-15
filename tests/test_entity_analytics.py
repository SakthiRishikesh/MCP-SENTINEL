"""Entity behaviour analytics (UEBA): learning window, novelty detection, kill-chain, API."""

from __future__ import annotations

from monitoring import entity
from sentinel.types import Capability, Sensitivity
from tests.helpers import call, headers
from workflow.analyzer import SequentialAnalyzer, WorkflowState


def _train(profile, n, **kw):
    base = {"agent_id": "claude-ai", "server_id": "srv-1", "exposed_name": "fs__read",
            "capability": Capability.READ, "sensitivity": Sensitivity.LOW}
    base.update(kw)
    for _ in range(n):
        entity.record(profile, allowed=True, recent_calls_last_minute=1, **base)
    return profile


def test_learning_window_suppresses_novelty():
    p = entity.normalize(None, "alice")
    _train(p, entity.LEARN_MIN - 1)
    # still learning: a brand-new sensitive capability is not yet an anomaly
    a = entity.assess(p, agent_id="claude-ai", server_id="srv-9", exposed_name="vault__get",
                      capability=Capability.SECRET_ACCESS, sensitivity=Sensitivity.CRITICAL)
    assert a.learning and a.evidence == []


def test_new_sensitive_capability_flagged_after_learning():
    p = entity.normalize(None, "alice")
    _train(p, entity.LEARN_MIN)
    a = entity.assess(p, agent_id="claude-ai", server_id="srv-1", exposed_name="vault__get",
                      capability=Capability.SECRET_ACCESS, sensitivity=Sensitivity.CRITICAL)
    names = {n for n, _, _ in a.evidence}
    assert "entity_new_sensitive_capability" in names and not a.learning


def test_new_agent_is_flagged_as_possible_token_reuse():
    p = entity.normalize(None, "alice")
    _train(p, entity.LEARN_MIN)
    a = entity.assess(p, agent_id="totally-new-agent", server_id="srv-1", exposed_name="fs__read",
                      capability=Capability.READ, sensitivity=Sensitivity.LOW)
    assert "entity_new_agent" in {n for n, _, _ in a.evidence}


def test_volume_spike_detected():
    p = entity.normalize(None, "alice")
    _train(p, entity.LEARN_MIN)  # peak_minute_rate stays at 1
    a = entity.assess(p, agent_id="claude-ai", server_id="srv-1", exposed_name="fs__read",
                      capability=Capability.READ, sensitivity=Sensitivity.LOW, recent_calls_last_minute=40)
    assert "entity_volume_spike" in {n for n, _, _ in a.evidence}


def test_known_behaviour_is_quiet():
    p = entity.normalize(None, "alice")
    _train(p, entity.LEARN_MIN + 5)
    a = entity.assess(p, agent_id="claude-ai", server_id="srv-1", exposed_name="fs__read",
                      capability=Capability.READ, sensitivity=Sensitivity.LOW, recent_calls_last_minute=1)
    assert a.evidence == [] and not a.learning


def test_summary_reports_established_and_rate():
    p = entity.normalize(None, "alice")
    _train(p, 10)
    _train(p, 2, capability=Capability.SECRET_ACCESS, sensitivity=Sensitivity.CRITICAL, exposed_name="vault__get")
    s = entity.summary(p)
    assert s["established"] and s["calls"] == 12 and s["sensitive_calls"] == 2 and s["sensitive_rate"] == round(2 / 12, 3)


def test_sequence_flags_untrusted_then_sensitive_non_adjacent():
    # untrusted content was ingested earlier; a WRITE happened in between; now a secret access
    state = WorkflowState(
        workflow_id="w", capabilities=[Capability.EXTERNAL_LOOKUP.value, Capability.WRITE.value],
        flow_roles=["UNTRUSTED_SOURCE"], untrusted_injection_seen=True,
    )
    finding = SequentialAnalyzer().analyze(state, "vault_get", Capability.SECRET_ACCESS, "", data_class=None)  # type: ignore[arg-type]
    assert "untrusted_then_sensitive" in {n for n, _, _ in finding.signals}


def test_entities_api_builds_a_profile(client):
    hdrs = headers("ANALYST")
    for _ in range(3):
        call(client, "wf-ent", "search_logs", {"query": "x"}, hdrs)
    rows = client.get("/v1/entities").json()
    me = next((r for r in rows if r["subject"] == "user-123"), None)
    assert me is not None and me["calls"] >= 1
    detail = client.get("/v1/entities/user-123")
    assert detail.status_code == 200 and detail.json()["subject"] == "user-123"
    assert client.get("/v1/entities/nobody").status_code == 404
