"""Tests for sources/breach_lookup.py (XposedOrNot + LeakCheck)."""

from __future__ import annotations

import re

import pytest
from aioresponses import aioresponses

from sources import breach_lookup as bl
from tests.conftest import make_results, FakeEntity

_XON_RE = re.compile(r"https://api\.xposedornot\.com/v1/check-email/.*")
_LEAK_RE = re.compile(r"https://leakcheck\.io/api/public.*")


async def test_xposedornot_found_with_stealer_log():
    with aioresponses() as m:
        m.get(_XON_RE, status=200, payload={
            "breaches": [["Canva", "Adobe", "AlienStealerLogs"]],
            "email": "x@y.com",
            "status": "success",
        })
        res = await bl.query_xposedornot("x@y.com")
    assert res["found"] is True
    assert res["source"] == "xposedornot"
    assert res["breach_count"] == 3
    assert res["stealer_log_exposure"] is True
    assert "Adobe" in res["breach_names"]


async def test_xposedornot_not_found():
    with aioresponses() as m:
        m.get(_XON_RE, status=200, payload={"Error": "Not found", "email": None})
        res = await bl.query_xposedornot("nobody@nowhere.tld")
    assert res["found"] is False
    assert res["source"] == "xposedornot_not_found"
    assert res["breach_count"] == 0


async def test_xposedornot_rate_limited():
    with aioresponses() as m:
        m.get(_XON_RE, status=429)
        res = await bl.query_xposedornot("x@y.com")
    assert res["found"] is False
    assert res["source"] == "xposedornot_rate_limited"


async def test_leakcheck_found():
    with aioresponses() as m:
        m.get(_LEAK_RE, status=200, payload={
            "success": True,
            "found": 3,
            "fields": ["password", "username"],
            "sources": [
                {"name": "Canva.com", "date": "2019-05"},
                {"name": "Adobe", "date": "2013-10"},
            ],
        })
        res = await bl.query_leakcheck("x@y.com")
    assert res["found"] is True
    assert res["source"] == "leakcheck"
    assert res["breach_count"] == 3
    assert "Canva.com" in res["sources"]
    assert "password" in res["fields"]


async def test_leakcheck_no_success():
    with aioresponses() as m:
        m.get(_LEAK_RE, status=200, payload={"success": False, "error": "not found"})
        res = await bl.query_leakcheck("x@y.com")
    assert res["found"] is False
    assert res["source"] == "leakcheck_not_found"


async def test_enrich_breach_entities_corroborated():
    """An email found in BOTH corpora is tagged corroborated and both statuses are ok_1."""
    with aioresponses() as m:
        m.get(_XON_RE, status=200, payload={
            "breaches": [["Canva", "StealerLogs"]], "status": "success",
        })
        m.get(_LEAK_RE, status=200, payload={
            "success": True, "found": 2,
            "sources": [{"name": "Canva.com", "date": "2019-05"}], "fields": ["password"],
        })
        results = make_results(FakeEntity("EMAIL_ADDRESS", "victim@corp.example"))
        _, stats = await bl.enrich_breach_entities(results, "inv-1")

    assert stats["xposedornot"] == "ok_1_results"
    assert stats["leakcheck"] == "ok_1_results"
    assert stats["xon_breached"] == 1
    assert stats["leakcheck_breached"] == 1
    assert stats["stealer_log_exposed"] == 1
    assert stats["corroborated"] == 1


async def test_enrich_breach_entities_no_emails():
    results = make_results(FakeEntity("IP_ADDRESS", "1.2.3.4"))
    _, stats = await bl.enrich_breach_entities(results, "inv-1")
    assert stats["xposedornot"] == "ok_0_results"
    assert stats["leakcheck"] == "ok_0_results"
    assert stats["emails_checked"] == 0


async def test_check_breach_exposure_confidence_delta():
    with aioresponses() as m:
        m.get(_XON_RE, status=200, payload={"breaches": [["Canva"]], "status": "success"})
        m.get(_LEAK_RE, status=200, payload={"success": True, "found": 1, "sources": [{"name": "Canva.com"}]})
        rep = await bl.check_breach_exposure("a@b.com")
    # 0.12 (xon) + 0.08 (leakcheck) + 0.10 (corroborated) = 0.30
    assert rep["corroborated"] is True
    assert round(rep["confidence_delta"], 2) == 0.30
    assert "breach_corroborated" in rep["tags"]


# ---------------------------------------------------------------------------
# Handle lookups (usernames, not addresses)
# ---------------------------------------------------------------------------


def test_normalise_handle_platform_forms():
    assert bl._normalise_handle("@LockBit_Ops") == "LockBit_Ops"
    assert bl._normalise_handle("https://t.me/LockBit_Ops") == "LockBit_Ops"
    assert bl._normalise_handle("user#1234") == "user"
    assert bl._normalise_handle("@someone:matrix.example") == "someone"


def test_invalid_handles_are_rejected():
    assert bl._is_valid_handle("support") is False      # role account
    assert bl._is_valid_handle("ab") is False           # shorter than 3
    assert bl._is_valid_handle("123456789") is False    # a number is not a username
    assert bl._is_valid_handle("lockbit_ops") is True


async def test_leakcheck_handle_found():
    """The public API detects the search type from the value; a handle works."""
    with aioresponses() as m:
        m.get(_LEAK_RE, status=200, payload={
            "success": True,
            "found": 2,
            "fields": ["username", "password"],
            "sources": [
                {"name": "Canva.com", "date": "2019-05"},
                {"name": "StealerLogs", "date": "2024-01"},
            ],
        })
        res = await bl.query_leakcheck_handle("@LockBit_Ops")
    assert res["found"] is True
    assert res["source"] == "leakcheck"
    assert res["handle"] == "LockBit_Ops"
    assert res["breach_count"] == 2
    assert res["breaches"][0] == {"name": "Canva.com", "date": "2019-05"}
    assert res["stealer_log_exposure"] is True


async def test_check_handle_breach_exposure_tags():
    with aioresponses() as m:
        m.get(_LEAK_RE, status=200, payload={
            "success": True,
            "found": 1,
            "fields": ["username"],
            "sources": [{"name": "StealerLogs2026", "date": "2026-02"}],
        })
        rep = await bl.check_handle_breach_exposure("lockbit_ops")
    assert rep["found"] is True
    assert rep["stealer_log"] is True
    assert "handle_breached" in rep["tags"]
    assert "feed:leakcheck" in rep["tags"]
    # 0.08 (found) + 0.10 (stealer-log corpus)
    assert round(rep["confidence_delta"], 2) == 0.18


async def test_check_handle_breach_exposure_skips_role_accounts():
    # No HTTP call: an invalid handle never reaches the network.
    rep = await bl.check_handle_breach_exposure("support")
    assert rep["found"] is False
    assert rep["status"] == "leakcheck_not_found"


async def test_enrich_breach_entities_checks_handles():
    """One handle seen under two entity types is one lookup, both types flagged."""
    with aioresponses() as m:
        m.get(_LEAK_RE, status=200, payload={
            "success": True,
            "found": 1,
            "fields": ["username"],
            "sources": [{"name": "Canva.com", "date": "2019-05"}],
        })
        results = make_results(
            FakeEntity("THREAT_ACTOR_HANDLE", "lockbit_ops"),
            FakeEntity("TELEGRAM_HANDLE", "@lockbit_ops"),
        )
        _, stats = await bl.enrich_breach_entities(results, "inv-1")

    assert stats["emails_checked"] == 0
    assert stats["handles_checked"] == 1
    assert stats["handles_breached"] == 1
    assert stats["leakcheck_handle"] == "ok_1_results"
    assert stats["breach_edges"] == 0  # no DATABASE_URL in unit tests


def test_breach_export_rows_dedupes_and_sorts():
    entities = [
        {"id": "a", "entity_type": "EMAIL_ADDRESS", "value": "victim@corp.example"},
        {"id": "b", "entity_type": "BREACH_NAME", "value": "Canva.com",
         "corroborating_sources": '["feed:leakcheck"]'},
        {"id": "c", "entity_type": "EMAIL_ADDRESS", "value": "other@corp.example"},
    ]
    relationships = [
        {"entity_a_id": "a", "entity_b_id": "b", "relationship_type": "EXPOSED_IN",
         "confidence": 0.9},
        {"entity_a_id": "a", "entity_b_id": "b", "relationship_type": "EXPOSED_IN",
         "confidence": 0.9},
        {"entity_a_id": "a", "entity_b_id": "c", "relationship_type": "CO_APPEARED_ON",
         "confidence": 0.5},
    ]
    rows = bl.breach_export_rows(entities, relationships)
    assert rows == [{
        "identifier": "victim@corp.example",
        "identifier_type": "EMAIL_ADDRESS",
        "breach": "Canva.com",
        "confidence": 0.9,
        "sources": '["feed:leakcheck"]',
    }]


def test_persist_breach_findings_creates_graph_and_is_idempotent(db_engine):
    import uuid

    from db.models import Entity, EntityRelationship, Investigation, Page
    from db.session import get_session

    inv_id = uuid.uuid4()
    with get_session() as session:
        session.add(Investigation(id=inv_id, query="lockbit"))
        page = Page(url="http://forum.onion/thread/1", investigation_id=inv_id)
        session.add(page)
        session.flush()
        session.add(
            Entity(
                page_id=page.id,
                investigation_id=inv_id,
                entity_type="THREAT_ACTOR_HANDLE",
                value="lockbit_ops",
                canonical_value="lockbit_ops",
                confidence=0.8,
            )
        )
        session.commit()

    finding = {
        "entity_types": ["THREAT_ACTOR_HANDLE"],
        "value": "lockbit_ops",
        "source": "leakcheck",
        "breaches": [
            {"name": "Canva.com", "date": "2019-05"},
            {"name": "StealerLogs", "date": None},
        ],
        "confidence": 0.95,
    }

    assert bl._persist_breach_findings([finding], inv_id) == 2

    with get_session() as session:
        nodes = session.query(Entity).filter_by(entity_type="BREACH_NAME").all()
        assert {node.value for node in nodes} == {"Canva.com", "StealerLogs"}
        # One synthetic provenance page for the source, not one per breach.
        assert len({str(node.page_id) for node in nodes}) == 1
        rels = (
            session.query(EntityRelationship)
            .filter_by(relationship_type="EXPOSED_IN")
            .all()
        )
        assert len(rels) == 2
        assert all(str(rel.investigation_id) == str(inv_id) for rel in rels)

    # Re-running enrichment must not duplicate the graph.
    assert bl._persist_breach_findings([finding], inv_id) == 0
