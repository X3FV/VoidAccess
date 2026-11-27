"""Tests for analysis/deep_investigation.py (multi-hop pivot passes).

Everything under test is pure: pivot selection, query building, the budget and
the report block.  The network orchestration lives in the CLI and is not
exercised here.
"""

from __future__ import annotations

from analysis import deep_investigation as deep


def _entity(entity_type: str, value: str, confidence: float = 1.0, priority: float = 0.0):
    return {
        "entity_type": entity_type,
        "value": value,
        "confidence": confidence,
        "priority_score": priority,
    }


def test_pivot_ranking_prefers_handles_over_weak_iocs():
    entities = [
        _entity("IP_ADDRESS", "45.9.20.1", 0.7),
        _entity("ONION_URL", "http://abcdef.onion/thread/9", 0.9),
        _entity("THREAT_ACTOR_HANDLE", "lockbit_supp", 0.6),
    ]
    pivots = deep.select_pivots(entities, limit=3)
    assert [pivot.entity_type for pivot in pivots] == [
        "THREAT_ACTOR_HANDLE",
        "ONION_URL",
        "IP_ADDRESS",
    ]


def test_context_entities_are_never_pivots():
    entities = [
        _entity("DATE", "2026-01-01"),
        _entity("PERSON_NAME", "John Smith"),
        _entity("BREACH_NAME", "Canva.com"),
        _entity("THREAT_ACTOR_HANDLE", "lockbit_supp"),
    ]
    assert [pivot.value for pivot in deep.select_pivots(entities, limit=5)] == [
        "lockbit_supp"
    ]


def test_generic_and_noise_values_are_skipped():
    assert deep.is_pivot_candidate("THREAT_ACTOR_HANDLE", "support") is False
    assert deep.is_pivot_candidate("EMAIL_ADDRESS", "a@b") is False
    assert deep.is_pivot_candidate("ICQ_NUMBER", "123456789") is False
    assert deep.is_pivot_candidate("TELEGRAM_HANDLE", "lockbit_supp") is True


def test_value_already_in_the_query_is_not_a_pivot():
    entities = [_entity("RANSOMWARE_GROUP", "LockBit")]
    assert deep.select_pivots(entities, base_query="lockbit ransomware", limit=3) == []


def test_excluded_values_are_not_re_pivoted():
    entities = [_entity("THREAT_ACTOR_HANDLE", "LockBit_Supp")]
    assert deep.select_pivots(entities, excluded={"lockbit_supp"}, limit=3) == []


def test_selection_deduplicates_case_insensitively_keeping_the_strongest():
    entities = [
        _entity("THREAT_ACTOR_HANDLE", "LockBit_Supp", 0.6),
        _entity("THREAT_ACTOR_HANDLE", "lockbit_supp", 0.9),
    ]
    pivots = deep.select_pivots(entities, limit=3)
    assert len(pivots) == 1
    assert pivots[0].confidence == 0.9


def test_selection_respects_the_limit():
    entities = [_entity("THREAT_ACTOR_HANDLE", f"actor{i}") for i in range(10)]
    assert len(deep.select_pivots(entities, limit=2)) == 2
    assert deep.select_pivots(entities, limit=0) == []


def test_build_pivot_query_uses_onion_host_and_strips_at():
    onion = deep.Pivot(
        entity_type="ONION_URL", value="http://abcdef.onion/thread/9?x=1", score=1.0
    )
    assert deep.build_pivot_query(onion) == "abcdef.onion"

    handle = deep.Pivot(entity_type="TELEGRAM_HANDLE", value="@lockbit_supp", score=1.0)
    assert deep.build_pivot_query(handle) == "lockbit_supp"

    phrase = deep.Pivot(entity_type="RANSOMWARE_GROUP", value="Silent Group", score=1.0)
    assert deep.build_pivot_query(phrase) == '"Silent Group"'


def test_budget_never_exceeds_the_run_cap():
    budget = deep.DeepBudget(max_pages=5)
    assert budget.spend(4) == 4
    assert budget.spend(4) == 1
    assert budget.spend(4) == 0
    assert budget.pages_used == 5
    assert budget.remaining() == 0


def test_deep_limits_are_bounded(monkeypatch):
    monkeypatch.setenv(deep.ENV_HOPS, "99")
    monkeypatch.setenv(deep.ENV_PIVOTS_PER_HOP, "0")
    monkeypatch.setenv(deep.ENV_PAGES_PER_PIVOT, "not-a-number")
    monkeypatch.setenv(deep.ENV_MAX_PAGES, "7")
    limits = deep.deep_limits()
    assert limits["hops"] == 5                                   # clamped to the range
    assert limits["pivots_per_hop"] == 1                         # clamped up to the minimum
    assert limits["pages_per_pivot"] == deep.DEEP_PAGES_PER_PIVOT_DEFAULT
    assert limits["max_pages"] == 7


def test_deep_limits_defaults(monkeypatch):
    for name in (
        deep.ENV_HOPS,
        deep.ENV_PIVOTS_PER_HOP,
        deep.ENV_PAGES_PER_PIVOT,
        deep.ENV_MAX_PAGES,
    ):
        monkeypatch.delenv(name, raising=False)
    assert deep.deep_limits() == {
        "hops": deep.DEEP_HOPS_DEFAULT,
        "pivots_per_hop": deep.DEEP_PIVOTS_PER_HOP_DEFAULT,
        "pages_per_pivot": deep.DEEP_PAGES_PER_PIVOT_DEFAULT,
        "max_pages": deep.DEEP_MAX_PAGES_DEFAULT,
    }


def test_summarize_hops_totals_and_shape():
    hops = [
        {"hop": 1, "pages": 3, "entities": 5, "pivots": [{"value": "a"}, {"value": "b"}]},
        {"hop": 2, "pages": 2, "entities": 1, "pivots": [{"value": "c"}]},
    ]
    block = deep.summarize_hops(hops, {"hops": 2, "max_pages": 20})
    assert block["enabled"] is True
    assert block["hops_requested"] == 2
    assert block["hops_run"] == 2
    assert block["pivots_investigated"] == 3
    assert block["pages_added"] == 5
    assert block["entities_added"] == 6
    assert block["limits"] == {"hops": 2, "max_pages": 20}
    assert block["hops"] == hops
