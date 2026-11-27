"""analysis/deep_investigation.py — bounded multi-hop pivot passes.

``voidaccess investigate "<query>" --deep-investigation`` runs the normal
pipeline and then, before enrichment and graph construction, re-enters
search → scrape → extract on the highest-signal entities the first pass found:
an actor handle, a C2 ``.onion``, a wallet or a mail address that appeared in
the results gets its own targeted hunt.  Each pass is a *hop*; pivots found on
one hop can become the next hop's pivots, which is what makes a run multi-hop.

Everything here is pure and deterministic — pivot selection, query building,
budget accounting and the report block — so it is testable without network,
Tor, an LLM or a database.  The network orchestration lives in
``voidaccess_cli/commands/investigate.py`` and calls into this module.

The limits are deliberately small by default: this is the heaviest mode the
engine has, and a Raspberry Pi (or any single-box self-host) must stay usable.
Every one of them is env-overridable, and the budget is a hard cap on pages
fetched by *all* deep passes of one run, not per hop.

Public interface
----------------
deep_limits()                                          → dict[str, int]
is_pivot_candidate(entity_type, value)                 → bool
pivot_score(entity, base_query)                        → float | None
select_pivots(entities, excluded, base_query, limit)    → list[Pivot]
build_pivot_query(pivot, base_query)                   → str
DeepBudget(max_pages)                                  → budget
summarize_hops(hops, limits)                           → dict
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# What is worth a second pass
# ---------------------------------------------------------------------------
# Weight = how much a targeted search on this value tends to add.  A handle is
# the strongest pivot in dark-web work (it names the actor); an onion URL or a
# wallet finds the infrastructure and the money next to it.  Context entities
# (dates, places, organisations) are excluded entirely: searching them burns the
# budget and returns the same pages the first pass already had.
PIVOT_WEIGHTS: dict[str, float] = {
    "THREAT_ACTOR_HANDLE": 1.00,
    "RANSOMWARE_GROUP": 0.95,
    "ONION_URL": 0.90,
    "MALWARE_FAMILY": 0.85,
    "PGP_KEY_BLOCK": 0.80,
    "TELEGRAM_HANDLE": 0.80,
    "DISCORD_HANDLE": 0.75,
    "MATRIX_HANDLE": 0.70,
    "XMPP_JID": 0.70,
    "SESSION_ID": 0.70,
    "TOX_ID": 0.70,
    "WICKR_ID": 0.70,
    "WIRE_HANDLE": 0.70,
    "ICQ_NUMBER": 0.65,
    "EMAIL_ADDRESS": 0.70,
    "DOMAIN": 0.65,
    "ENS_DOMAIN": 0.60,
    "IP_ADDRESS": 0.60,
    "IPV6_ADDRESS": 0.55,
    "BITCOIN_ADDRESS": 0.60,
    "ETHEREUM_ADDRESS": 0.60,
    "MONERO_ADDRESS": 0.60,
    "LITECOIN_ADDRESS": 0.55,
    "ZCASH_ADDRESS": 0.55,
    "DOGECOIN_ADDRESS": 0.50,
    "XRP_ADDRESS": 0.50,
    "SOLANA_ADDRESS": 0.50,
    "TRON_ADDRESS": 0.50,
    "BITCOIN_CASH_ADDRESS": 0.50,
    "DASH_ADDRESS": 0.50,
    "CVE_NUMBER": 0.45,
    "EXPLOIT_DB_ID": 0.40,
}

# Explicitly never a pivot, even if a weight were added above by mistake.
NON_PIVOT_TYPES = frozenset({
    "DATE", "LOCATION", "PERSON_NAME", "ORGANIZATION_NAME", "PHONE_NUMBER",
    "BREACH_NAME", "COMBO_LIST_ENTRY", "CRYPTO_SEED_PHRASE", "IPFS_CID",
    "MAC_ADDRESS", "PASTE_URL", "YARA_RULE", "NUCLEI_TEMPLATE",
    "MITRE_TACTIC", "MITRE_TECHNIQUE", "CVE", "FILE_HASH_MD5",
    "FILE_HASH_SHA1", "FILE_HASH_SHA256",
})

_HANDLE_TYPES = frozenset({
    "THREAT_ACTOR_HANDLE", "TELEGRAM_HANDLE", "DISCORD_HANDLE", "MATRIX_HANDLE",
    "XMPP_JID", "TOX_ID", "SESSION_ID", "WIRE_HANDLE", "WICKR_ID",
})

# Generic role accounts: a targeted search on "support" or "admin" returns
# noise, and each hop costs a Pi real time.
GENERIC_HANDLES = frozenset({
    "admin", "administrator", "support", "help", "info", "contact", "root",
    "user", "users", "test", "guest", "moderator", "staff", "service", "null",
    "none", "unknown", "example",
})

MIN_PIVOT_LENGTH = 4
MAX_PIVOT_LENGTH = 256

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

ENV_HOPS = "VOIDACCESS_DEEP_HOPS"
ENV_PIVOTS_PER_HOP = "VOIDACCESS_DEEP_PIVOTS"
ENV_PAGES_PER_PIVOT = "VOIDACCESS_DEEP_PAGES_PER_PIVOT"
ENV_MAX_PAGES = "VOIDACCESS_DEEP_MAX_PAGES"

DEEP_HOPS_DEFAULT = 2
DEEP_PIVOTS_PER_HOP_DEFAULT = 3
DEEP_PAGES_PER_PIVOT_DEFAULT = 4
DEEP_MAX_PAGES_DEFAULT = 20

_HOPS_RANGE = (1, 5)
_PIVOTS_RANGE = (1, 10)
_PAGES_PER_PIVOT_RANGE = (1, 15)
_MAX_PAGES_RANGE = (1, 100)


def _env_int(name: str, default: int, low: int, high: int) -> int:
    """*name* as an int clamped to [low, high]; *default* on anything unusable."""
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(low, min(high, value))


def deep_limits() -> dict[str, int]:
    """The per-run limits for deep investigation, env-overridable.

    ``max_pages`` is the cap for the whole run (every hop, every pivot), so
    raising the hop count cannot multiply the fetch cost past it.
    """
    return {
        "hops": _env_int(ENV_HOPS, DEEP_HOPS_DEFAULT, *_HOPS_RANGE),
        "pivots_per_hop": _env_int(
            ENV_PIVOTS_PER_HOP, DEEP_PIVOTS_PER_HOP_DEFAULT, *_PIVOTS_RANGE
        ),
        "pages_per_pivot": _env_int(
            ENV_PAGES_PER_PIVOT, DEEP_PAGES_PER_PIVOT_DEFAULT, *_PAGES_PER_PIVOT_RANGE
        ),
        "max_pages": _env_int(ENV_MAX_PAGES, DEEP_MAX_PAGES_DEFAULT, *_MAX_PAGES_RANGE),
    }


# ---------------------------------------------------------------------------
# Pivot selection
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Pivot:
    """One entity to hunt on its own, and why it was chosen."""

    entity_type: str
    value: str
    score: float
    confidence: float = 1.0


def _field(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, Mapping):
        return item.get(key, default)
    return getattr(item, key, default)


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _entity_type_of(item: Any) -> str:
    return str(_field(item, "entity_type", "") or "").strip().upper()


def _value_of(item: Any) -> str:
    return str(_field(item, "value", "") or "").strip()


def _host_of(value: str) -> str:
    text = value.strip()
    if "://" not in text:
        text = "http://" + text
    try:
        return (urlparse(text).hostname or "").strip().lower()
    except ValueError:
        return ""


def _looks_like_noise(value: str) -> bool:
    """True for values a search engine cannot usefully be asked for."""
    if not (MIN_PIVOT_LENGTH <= len(value) <= MAX_PIVOT_LENGTH):
        return True
    if not re.search(r"[A-Za-z0-9]", value):
        return True
    # A bare integer is an ICQ number, a port, a year — not a lead.
    if value.isdigit():
        return True
    return False


def is_pivot_candidate(entity_type: str, value: str) -> bool:
    """True when *value* of *entity_type* is worth its own targeted pass."""
    etype = str(entity_type or "").strip().upper()
    text = str(value or "").strip()
    if not etype or etype in NON_PIVOT_TYPES or etype not in PIVOT_WEIGHTS:
        return False
    if _looks_like_noise(text):
        return False
    if etype in _HANDLE_TYPES:
        handle = text.lstrip("@").lower()
        if handle in GENERIC_HANDLES:
            return False
    return True


def pivot_score(entity: Any, base_query: str = "") -> float | None:
    """The pivot score of *entity*, or ``None`` when it is not a candidate.

    ``weight + 0.15 x confidence + 0.10 x priority``.  The confidence term keeps
    a twice-seen handle ahead of a one-off mention of the same type; the
    priority term reuses the shared ranking so deep mode and the report agree on
    which entities matter.  A value already in the query adds nothing (the first
    pass searched it already) and is skipped.
    """
    etype = _entity_type_of(entity)
    value = _value_of(entity)
    if not is_pivot_candidate(etype, value):
        return None
    if base_query and len(value) >= MIN_PIVOT_LENGTH:
        if value.lower() in base_query.lower():
            return None
    confidence = max(0.0, min(1.0, _number(_field(entity, "confidence", 0.0), 0.0)))
    priority = max(0.0, min(1.0, _number(_field(entity, "priority_score", 0.0), 0.0)))
    return PIVOT_WEIGHTS[etype] + 0.15 * confidence + 0.10 * priority


def select_pivots(
    entities: Iterable[Any],
    excluded: Iterable[str] = (),
    base_query: str = "",
    limit: int = DEEP_PIVOTS_PER_HOP_DEFAULT,
) -> list[Pivot]:
    """The top *limit* pivots from *entities*.

    *excluded* holds values already investigated (lowercased), so a hop never
    chases what an earlier hop already covered — that is the loop protection.
    Values are deduplicated case-insensitively: two entity rows for the same
    handle are one pivot.  Deterministic: score descending, then value.
    """
    if limit <= 0:
        return []
    done = {str(value).strip().lower() for value in excluded or ()}
    best: dict[str, Pivot] = {}
    for entity in entities or ():
        score = pivot_score(entity, base_query)
        if score is None:
            continue
        value = _value_of(entity)
        key = value.lower()
        if key in done:
            continue
        confidence = max(0.0, min(1.0, _number(_field(entity, "confidence", 0.0), 0.0)))
        candidate = Pivot(
            entity_type=_entity_type_of(entity),
            value=value,
            score=round(score, 6),
            confidence=round(confidence, 6),
        )
        current = best.get(key)
        if current is None or (candidate.score, candidate.entity_type) > (
            current.score, current.entity_type
        ):
            best[key] = candidate
    ordered = sorted(best.values(), key=lambda p: (-p.score, p.value.lower()))
    return ordered[:limit]


def build_pivot_query(pivot: Pivot, base_query: str = "") -> str:
    """The search string for one pivot.

    An ``.onion`` is searched by host — the path is specific to one page and no
    engine indexes it.  Handles lose a leading ``@``; everything else is used
    verbatim, quoted only when it contains whitespace (a name) so the engine
    looks for the phrase rather than the words separately.
    """
    value = str(pivot.value or "").strip()
    if pivot.entity_type.upper() == "ONION_URL":
        host = _host_of(value)
        if host:
            return host
    if value.startswith("@") and pivot.entity_type.upper() in _HANDLE_TYPES:
        value = value.lstrip("@")
    if re.search(r"\s", value):
        return f'"{value}"'
    return value


# ---------------------------------------------------------------------------
# Budget and reporting
# ---------------------------------------------------------------------------


@dataclass
class DeepBudget:
    """Pages this run may still fetch during deep passes.

    ``spend`` grants what is left of *requested*, never more, so the total can
    never exceed ``max_pages`` however many hops or pivots there are.
    """

    max_pages: int
    pages_used: int = 0

    def remaining(self) -> int:
        return max(0, int(self.max_pages) - int(self.pages_used))

    def spend(self, requested: int) -> int:
        grant = max(0, min(int(requested), self.remaining()))
        self.pages_used += grant
        return grant


def summarize_hops(hops: list[dict], limits: dict[str, int]) -> dict[str, Any]:
    """The ``deep_investigation`` block of the report payload."""
    hop_list = [hop for hop in (hops or ()) if isinstance(hop, Mapping)]
    pivots = [
        pivot
        for hop in hop_list
        for pivot in (hop.get("pivots") or ())
        if isinstance(pivot, Mapping)
    ]
    return {
        "enabled": True,
        "hops_requested": int(limits.get("hops", 0) or 0),
        "hops_run": len(hop_list),
        "pivots_investigated": len(pivots),
        "pages_added": sum(int(hop.get("pages", 0) or 0) for hop in hop_list),
        "entities_added": sum(int(hop.get("entities", 0) or 0) for hop in hop_list),
        "limits": dict(limits),
        "hops": hop_list,
    }


__all__ = [
    "DEEP_HOPS_DEFAULT",
    "DEEP_MAX_PAGES_DEFAULT",
    "DEEP_PAGES_PER_PIVOT_DEFAULT",
    "DEEP_PIVOTS_PER_HOP_DEFAULT",
    "DeepBudget",
    "GENERIC_HANDLES",
    "NON_PIVOT_TYPES",
    "PIVOT_WEIGHTS",
    "Pivot",
    "build_pivot_query",
    "deep_limits",
    "is_pivot_candidate",
    "pivot_score",
    "select_pivots",
    "summarize_hops",
]
