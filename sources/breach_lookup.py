"""
sources/breach_lookup.py — Breach-exposure lookup enrichment (XposedOrNot + LeakCheck).

Enriches EMAIL_ADDRESS *and handle* entities with breach-corpus exposure from
two free, key-optional sources that complement the existing (paid) HIBP
integration in ``sources/email_reputation.py``. HIBP, XposedOrNot, and
LeakCheck each draw from different breach corpora, so all three run when
available and each surfaces things the others miss.

  - XposedOrNot: free breach lookup (breach names), e-mail only. The free tier
    notably includes stealer-log exposure, which most comparable services
    charge for. An optional XPOSEDORNOT_API_KEY unlocks richer results but is
    never required.
  - LeakCheck (public tier): free, unauthenticated, and — unlike HIBP and
    XposedOrNot — it accepts a *username* as well as an e-mail address (the
    search type is detected from the value; usernames need 3+ characters).
    Returns the breach *sources* an identifier appeared in plus the categories
    of data exposed — not the full records. Treated as a lightweight
    corroboration signal, not a primary source.

Handles are checked because an actor handle is often what a breach corpus
actually indexes: a forum nick reused on a leaked site, a Telegram alias in a
combo list. LeakCheck is the only one of the three that answers for a handle,
so handle checks report under the ``leakcheck_handle`` status key and never
claim a cross-source corroboration they did not get.

Breach hits are also written as graph facts: one ``BREACH_NAME`` node per
breach (or stealer-log corpus) and an ``EXPOSED_IN`` edge from the identifier
that was found in it. Each source gets one synthetic provenance page per
investigation, because entity rows are page-attributed; re-running enrichment
reuses that page and the existing nodes/edges rather than duplicating them.
``breach_export_rows`` renders the same facts as flat rows for the report and
the CSV/JSON exports.

Both sources report independently into ``sources_used`` under the keys
``xposedornot`` and ``leakcheck``. When an email surfaces in BOTH corpora, that
cross-source agreement is a stronger signal than either alone and is tagged.

Email addresses and handles extracted from dark web content are already public
— they appeared on dark web forums/markets. Querying breach-lookup APIs about
them is legitimate security research.

Public interface
----------------
async query_xposedornot(email)                                → dict
async query_leakcheck(email)                                  → dict
async query_leakcheck_handle(handle)                          → dict
async check_breach_exposure(email)                            → dict
async check_handle_breach_exposure(handle)                    → dict
async enrich_breach_entities(extraction_results, investigation_id) → (results, stats)
breach_export_rows(entities, relationships)                   → list[dict]
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from typing import Any, Optional

import aiohttp

import pacing
from sources import http_pool
from sources.enrichment_allowlist import (
    is_enrichment_source_enabled,
    validate_enrichment_allowlist,
)
from utils.enrichment_cache import DEFAULT_TTL, get_enrichment_cache

logger = logging.getLogger(__name__)

MAX_EMAILS = 30
# Handles are extra requests on the same documented 1 RPS LeakCheck budget as
# the e-mail checks, so this cap is a latency bound as much as a scope bound.
MAX_HANDLES = 20

# Handle-bearing entity types (the value is a username, not an address).
# ICQ_NUMBER is deliberately absent: its value is numeric and maps to a phone,
# which LeakCheck's public tier does not answer for.
HANDLE_ENTITY_TYPES: tuple[str, ...] = (
    "THREAT_ACTOR_HANDLE",
    "TELEGRAM_HANDLE",
    "DISCORD_HANDLE",
    "MATRIX_HANDLE",
    "XMPP_JID",
    "TOX_ID",
    "SESSION_ID",
    "WIRE_HANDLE",
    "WICKR_ID",
    "USERNAME",
)

# Breach hits as graph facts.  BREACH_NAME is a node type of its own (see
# graph/model.py) so a breach is queryable like any other indicator, and
# EXPOSED_IN says "this identifier appeared in that corpus".
BREACH_ENTITY_TYPE = "BREACH_NAME"
BREACH_RELATIONSHIP_TYPE = "EXPOSED_IN"
MAX_BREACH_NODES_PER_IDENTIFIER = 12

# One synthetic provenance page per source and investigation: entity rows are
# page-attributed (page_id is NOT NULL), and a breach we learned from an API is
# not attributed to any scraped page.  The lookup endpoint itself is the honest
# provenance.
BREACH_PAGE_URLS: dict[str, str] = {
    "xposedornot": "https://api.xposedornot.com/v1/check-email#voidaccess-breach-exposure",
    "leakcheck": "https://leakcheck.io/api/public#voidaccess-breach-exposure",
}
DEFAULT_BREACH_PAGE_URL = BREACH_PAGE_URLS["leakcheck"]

XPOSEDORNOT_BASE_URL = "https://api.xposedornot.com/v1"
LEAKCHECK_PUBLIC_URL = "https://leakcheck.io/api/public"

# Provider-dictated pacing, verified against both providers' live docs
# 2026-07-29.  The concurrency bound and the per-request delay are ONE
# mechanism, derived together by pacing.rate_limit_delay(): N workers each
# sleeping the documented interval would produce N times the documented rate,
# so the per-worker delay is (interval x concurrency) and the slot is held for
# the duration of the sleep.  Tuning either number alone reintroduces the
# multiplication bug.
#
# XposedOrNot: 2 req/s per IP on /check-email  →  0.5 s interval.  Its 25/hr
# and 100/day caps are NOT expressible as a delay (see docs/BACKLOG.md
# pattern 1).
# LeakCheck public tier: 1 RPS documented (docs.leakcheck.io).  Was 0.4 s here,
# i.e. 2.5x over the documented limit even at `normal`.
_XON_MAX_CONCURRENCY = 2
_XON_MIN_INTERVAL = 0.5           # documented: 2 req/s per IP
_LEAKCHECK_MAX_CONCURRENCY = 2
_LEAKCHECK_MIN_INTERVAL = 1.1     # documented: 1 RPS, + margin


def _xon_delay() -> float:
    """Per-worker delay holding the aggregate XposedOrNot rate at ≤ 2 req/s."""
    return pacing.rate_limit_delay(_XON_MIN_INTERVAL, _XON_MAX_CONCURRENCY)


def _leakcheck_delay() -> float:
    """Per-worker delay holding the aggregate LeakCheck rate at < 1 req/s."""
    return pacing.rate_limit_delay(
        _LEAKCHECK_MIN_INTERVAL, _LEAKCHECK_MAX_CONCURRENCY
    )

_xon_semaphore: Optional[asyncio.Semaphore] = None
_leakcheck_semaphore: Optional[asyncio.Semaphore] = None

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# A username-shaped value: one token of 3-64 chars from the usual charset.
_HANDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
# Role accounts are not leads: a breach hit on "support" says nothing about the
# subject, and every extra lookup costs a rate-limited request.
_HANDLE_STOPWORDS: frozenset[str] = frozenset({
    "admin", "administrator", "support", "help", "info", "contact", "root",
    "user", "users", "test", "guest", "moderator", "staff", "service", "null",
    "none", "unknown", "example",
})

# Breach-name substrings that indicate infostealer / combolist / stealer-log
# origin rather than a classic site breach. XposedOrNot's free tier includes
# these, which is a higher-signal category for dark web investigations.
_STEALER_LOG_MARKERS: tuple[str, ...] = (
    "stealer", "naz.api", "nazapi", "combolist", "combo list",
    "antipubliccombo", "collection-1", "collection 1", "stealer logs",
)

# TTLs (add to the shared enrichment-cache map without editing that module).
DEFAULT_TTL.setdefault("xposedornot", 172800)  # 48 h
DEFAULT_TTL.setdefault("leakcheck", 172800)     # 48 h

_enrichment_cache_singleton: Optional[Any] = None


async def _get_enrichment_cache():
    global _enrichment_cache_singleton
    if _enrichment_cache_singleton is None:
        _enrichment_cache_singleton = await get_enrichment_cache()
    return _enrichment_cache_singleton


def _get_xon_semaphore() -> asyncio.Semaphore:
    global _xon_semaphore
    if _xon_semaphore is None:
        _xon_semaphore = asyncio.Semaphore(_XON_MAX_CONCURRENCY)
    return _xon_semaphore


def _get_leakcheck_semaphore() -> asyncio.Semaphore:
    global _leakcheck_semaphore
    if _leakcheck_semaphore is None:
        _leakcheck_semaphore = asyncio.Semaphore(_LEAKCHECK_MAX_CONCURRENCY)
    return _leakcheck_semaphore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_valid_email(value: str) -> bool:
    return bool(value and _EMAIL_RE.match(value.strip()))


def _normalise_handle(value: str) -> str:
    """The bare username for *value*: no scheme, no ``t.me/``, no ``@``, no ``#1234``.

    Telegram links, Discord legacy discriminators and Matrix IDs (``@user:server``)
    all reach the extractor in their platform form; every one of them has to be
    reduced to the username the corpus indexes.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    low = text.lower()
    for prefix in ("https://", "http://"):
        if low.startswith(prefix):
            text = text[len(prefix):]
            low = text.lower()
    for prefix in ("t.me/", "telegram.me/", "discord.gg/", "discord.com/users/"):
        if low.startswith(prefix):
            text = text[len(prefix):]
            low = text.lower()
    text = text.strip().lstrip("@")
    if ":" in text:                       # Matrix @user:server.tld
        text = text.split(":", 1)[0]
    if "#" in text:                       # Discord legacy username#0000
        text = text.split("#", 1)[0]
    return text.strip()


def _is_valid_handle(value: str) -> bool:
    handle = _normalise_handle(value)
    if not (3 <= len(handle) <= 64):
        return False
    if "@" in handle or not _HANDLE_RE.match(handle):
        return False
    if handle.isdigit():                  # a number is not a username
        return False
    return handle.lower() not in _HANDLE_STOPWORDS


def _field(item: Any, key: str, default: Any = None) -> Any:
    """Read a key from a dict *or* an ORM row (both shapes reach the exporters)."""
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def _coerce_uuid(value: Any) -> Optional[Any]:
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        return None


def _safe_log_email(email: str) -> str:
    """Return privacy-safe log representation: first 3 chars + @domain."""
    try:
        local, domain = email.split("@", 1)
        return f"{local[:3]}***@{domain}"
    except Exception:
        # A handle, not an address — same rule, no domain to keep.
        return f"{str(email or '')[:3]}***"


def _is_stealer_log_name(name: str) -> bool:
    low = (name or "").lower()
    return any(marker in low for marker in _STEALER_LOG_MARKERS)


# ---------------------------------------------------------------------------
# Source: XposedOrNot
# ---------------------------------------------------------------------------

async def query_xposedornot(email: str) -> dict[str, Any]:
    """
    Query XposedOrNot ``/check-email/{email}`` for breach exposure.

    No API key required for the free tier. An optional XPOSEDORNOT_API_KEY
    (sent as ``x-api-key``) unlocks richer results but is never required —
    the free tier returns breach names including stealer-log exposure.

    Returns a structured dict; ``source`` carries a sentinel on skip/error so
    the caller can distinguish "ran, nothing found" from "did not run".
    """
    empty: dict[str, Any] = {
        "found": False,
        "source": "xposedornot_not_found",
        "breach_count": 0,
        "breach_names": [],
        "stealer_log_exposure": False,
    }

    headers: dict[str, str] = {
        "User-Agent": "VoidAccess-OSINT/1.1 (security research)",
        "Accept": "application/json",
    }
    api_key = (os.getenv("XPOSEDORNOT_API_KEY") or "").strip()
    if api_key:
        headers["x-api-key"] = api_key

    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with _get_xon_semaphore():
            # The delay lives in a `finally` INSIDE the semaphore, deliberately:
            #  - `finally` so a 404/429/error return still pays it.  Returning
            #    early on non-200 used to skip the sleep entirely, which meant a
            #    run of 429s — exactly what a rate limiter produces — made
            #    VoidAccess speed up instead of back off.
            #  - inside the semaphore so the slot stays held for the delay,
            #    which is what makes rate_limit_delay()'s arithmetic hold.
            server_wait = 0.0
            try:
                async with http_pool.clearnet_session() as session:
                    async with session.get(
                        f"{XPOSEDORNOT_BASE_URL}/check-email/{email}",
                        headers=headers,
                        timeout=timeout,
                    ) as resp:
                        if resp.status == 404:
                            return empty
                        if resp.status == 429:
                            # XposedOrNot's 429 carries the hourly/daily cap
                            # reset; honour whatever it names, floored by our
                            # own documented interval.
                            server_wait = pacing.retry_after_seconds(
                                resp.headers, _xon_delay()
                            )
                            logger.warning(
                                "breach_lookup: XposedOrNot — rate limited, "
                                "backing off %.1fs", server_wait,
                            )
                            return {**empty, "source": "xposedornot_rate_limited"}
                        if resp.status != 200:
                            logger.debug(
                                "breach_lookup: XposedOrNot → HTTP %s for %s",
                                resp.status, _safe_log_email(email),
                            )
                            return {**empty, "source": "xposedornot_error"}
                        data = await resp.json(content_type=None)
            finally:
                await asyncio.sleep(max(_xon_delay(), server_wait))
    except asyncio.TimeoutError:
        logger.debug("breach_lookup: XposedOrNot timed out for %s", _safe_log_email(email))
        return {**empty, "source": "xposedornot_error"}
    except Exception as exc:
        logger.debug(
            "breach_lookup: XposedOrNot failed for %s: %s", _safe_log_email(email), exc
        )
        return {**empty, "source": "xposedornot_error"}

    # Not-found shape: {"Error": "Not found", "email": null}
    if not isinstance(data, dict) or data.get("Error"):
        return empty

    # Found shape: {"breaches": [["Canva", "Adobe", ...]], "email": ..., "status": "success"}
    raw_breaches = data.get("breaches") or []
    breach_names: list[str] = []
    if isinstance(raw_breaches, list):
        for item in raw_breaches:
            if isinstance(item, list):
                breach_names.extend(str(b) for b in item if b)
            elif isinstance(item, str):
                breach_names.append(item)

    if not breach_names:
        return empty

    stealer_exposure = any(_is_stealer_log_name(n) for n in breach_names)

    return {
        "found": True,
        "source": "xposedornot",
        "breach_count": len(breach_names),
        "breach_names": breach_names,
        "stealer_log_exposure": stealer_exposure,
    }


async def _cached_query_xposedornot(email: str) -> dict[str, Any]:
    """Cached wrapper. Skip/error/rate-limited results are NOT cached (retry next run)."""
    cache = await _get_enrichment_cache()
    cached = await cache.get("EMAIL_ADDRESS", email, "xposedornot")
    if cached is not None:
        logger.debug("XposedOrNot cache hit: %s", _safe_log_email(email))
        return cached
    result = await query_xposedornot(email)
    source_key = result.get("source") or ""
    if source_key in ("xposedornot", "xposedornot_not_found"):
        await cache.set(
            "EMAIL_ADDRESS", email, "xposedornot",
            result, DEFAULT_TTL["xposedornot"],
        )
    return result


# ---------------------------------------------------------------------------
# Source: LeakCheck (public tier)
# ---------------------------------------------------------------------------

async def query_leakcheck(email: str) -> dict[str, Any]:
    """
    Query LeakCheck's public API for breach-source corroboration.

    Unauthenticated, free. Returns the breach *sources* an email appeared in
    and the categories of data exposed (``fields``) — not the records. Used as
    a lightweight secondary signal, not a primary source.
    """
    empty: dict[str, Any] = {
        "found": False,
        "source": "leakcheck_not_found",
        "breach_count": 0,
        "sources": [],
        "fields": [],
    }

    headers = {
        "User-Agent": "VoidAccess-OSINT/1.1 (security research)",
        "Accept": "application/json",
    }

    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with _get_leakcheck_semaphore():
            # See _query_xposedornot for why the delay is in a `finally` inside
            # the semaphore rather than after a successful response.
            server_wait = 0.0
            try:
                async with http_pool.clearnet_session() as session:
                    async with session.get(
                        LEAKCHECK_PUBLIC_URL, params={"check": email},
                        headers=headers, timeout=timeout,
                    ) as resp:
                        if resp.status == 429:
                            server_wait = pacing.retry_after_seconds(
                                resp.headers, _leakcheck_delay()
                            )
                            logger.warning(
                                "breach_lookup: LeakCheck — rate limited, "
                                "backing off %.1fs", server_wait,
                            )
                            return {**empty, "source": "leakcheck_rate_limited"}
                        if resp.status == 400:
                            # Public API rejects some inputs (e.g. bad format) with 400.
                            return empty
                        if resp.status != 200:
                            logger.debug(
                                "breach_lookup: LeakCheck → HTTP %s for %s",
                                resp.status, _safe_log_email(email),
                            )
                            return {**empty, "source": "leakcheck_error"}
                        data = await resp.json(content_type=None)
            finally:
                await asyncio.sleep(max(_leakcheck_delay(), server_wait))
    except asyncio.TimeoutError:
        logger.debug("breach_lookup: LeakCheck timed out for %s", _safe_log_email(email))
        return {**empty, "source": "leakcheck_error"}
    except Exception as exc:
        logger.debug(
            "breach_lookup: LeakCheck failed for %s: %s", _safe_log_email(email), exc
        )
        return {**empty, "source": "leakcheck_error"}

    if not isinstance(data, dict) or not data.get("success"):
        return empty

    raw_sources = data.get("sources") or []
    source_names: list[str] = []
    source_entries: list[dict[str, Any]] = []
    for s in raw_sources:
        if isinstance(s, dict) and s.get("name"):
            source_names.append(str(s["name"]))
            source_entries.append({"name": str(s["name"]), "date": s.get("date")})
        elif isinstance(s, str):
            source_names.append(s)
            source_entries.append({"name": s, "date": None})

    found_count = int(data.get("found") or 0)
    if not source_names and found_count == 0:
        return empty

    return {
        "found": True,
        "source": "leakcheck",
        "breach_count": found_count or len(source_names),
        "sources": source_names,
        # Breach-name + date pairs, for the graph nodes and the export rows.
        "sources_detail": source_entries,
        "fields": list(data.get("fields") or []),
    }


async def _cached_query_leakcheck(email: str) -> dict[str, Any]:
    """Cached wrapper. Skip/error/rate-limited results are NOT cached (retry next run)."""
    cache = await _get_enrichment_cache()
    cached = await cache.get("EMAIL_ADDRESS", email, "leakcheck")
    if cached is not None:
        logger.debug("LeakCheck cache hit: %s", _safe_log_email(email))
        return cached
    result = await query_leakcheck(email)
    source_key = result.get("source") or ""
    if source_key in ("leakcheck", "leakcheck_not_found"):
        await cache.set(
            "EMAIL_ADDRESS", email, "leakcheck",
            result, DEFAULT_TTL["leakcheck"],
        )
    return result


# ---------------------------------------------------------------------------
# Source: LeakCheck (public tier) — handles
# ---------------------------------------------------------------------------

async def query_leakcheck_handle(handle: str) -> dict[str, Any]:
    """
    Query LeakCheck's public API for a *username* rather than an address.

    The public tier documents e-mail, e-mail-hash and username lookups on the
    same ``?check=`` endpoint with the search type detected from the value
    (username minimum 3 characters), so this is the same call as
    :func:`query_leakcheck` with a handle-shaped value and a handle-shaped
    result.  XposedOrNot has no username endpoint, so a handle hit is never
    "corroborated" — one corpus answered.
    """
    normalised = _normalise_handle(handle)
    empty: dict[str, Any] = {
        "found": False,
        "source": "leakcheck_not_found",
        "handle": normalised,
        "breach_count": 0,
        "breaches": [],
        "fields": [],
        "stealer_log_exposure": False,
    }
    if not _is_valid_handle(normalised):
        return empty

    rep = await query_leakcheck(normalised)
    if not rep.get("found"):
        return {**empty, "source": rep.get("source", "leakcheck_not_found")}

    breaches = [
        {"name": entry["name"], "date": entry.get("date")}
        for entry in (rep.get("sources_detail") or ())
        if entry.get("name")
    ]
    names = [entry["name"] for entry in breaches]
    return {
        "found": True,
        "source": "leakcheck",
        "handle": normalised,
        "breach_count": rep.get("breach_count") or len(breaches),
        "breaches": breaches,
        "fields": list(rep.get("fields") or []),
        "stealer_log_exposure": any(_is_stealer_log_name(n) for n in names),
    }


async def _cached_query_leakcheck_handle(handle: str) -> dict[str, Any]:
    """Cached wrapper. Skip/error/rate-limited results are NOT cached (retry next run)."""
    cache = await _get_enrichment_cache()
    cached = await cache.get("HANDLE", handle, "leakcheck")
    if cached is not None:
        logger.debug("LeakCheck handle cache hit: %s", _safe_log_email(handle))
        return cached
    result = await query_leakcheck_handle(handle)
    source_key = result.get("source") or ""
    if source_key in ("leakcheck", "leakcheck_not_found"):
        await cache.set(
            "HANDLE", handle, "leakcheck",
            result, DEFAULT_TTL["leakcheck"],
        )
    return result


# ---------------------------------------------------------------------------
# Core breach-exposure check
# ---------------------------------------------------------------------------

async def check_breach_exposure(email: str) -> dict[str, Any]:
    """
    Run XposedOrNot + LeakCheck concurrently for a single email address.

    Returns a structured dict with per-source findings, a corroboration flag
    (both corpora agree), tags, and a confidence delta.
    """
    result: dict[str, Any] = {
        "email": email,
        "xon_found": False,
        "xon_breach_count": 0,
        "xon_stealer_log": False,
        "leakcheck_found": False,
        "leakcheck_breach_count": 0,
        "corroborated": False,
        "tags": [],
        "confidence_delta": 0.0,
        "xon_status": "xposedornot_not_found",
        "leakcheck_status": "leakcheck_not_found",
        # Breach-name + date pairs across both corpora, for graph nodes and rows.
        "breaches": [],
    }

    if not _is_valid_email(email):
        return result

    # VOIDACCESS_ENRICHMENT_SOURCES gate: disabled sources are never called
    # and report the same neutral "not found" shape.
    async def _disabled(source: str) -> dict[str, Any]:
        return {"found": False, "source": f"{source}_not_found"}

    xon, leak = await asyncio.gather(
        _cached_query_xposedornot(email)
        if is_enrichment_source_enabled("xposedornot") else _disabled("xposedornot"),
        _cached_query_leakcheck(email)
        if is_enrichment_source_enabled("leakcheck") else _disabled("leakcheck"),
        return_exceptions=True,
    )

    if isinstance(xon, Exception):
        logger.debug("breach_lookup: XposedOrNot raised for %s: %s", _safe_log_email(email), xon)
        xon = {"found": False, "source": "xposedornot_error"}
    if isinstance(leak, Exception):
        logger.debug("breach_lookup: LeakCheck raised for %s: %s", _safe_log_email(email), leak)
        leak = {"found": False, "source": "leakcheck_error"}

    result["xon_status"] = xon.get("source", "xposedornot_error")
    result["leakcheck_status"] = leak.get("source", "leakcheck_error")

    if xon.get("found"):
        count = xon.get("breach_count", 0)
        result["xon_found"] = True
        result["xon_breach_count"] = count
        result["tags"].append("xposedornot_breached")
        result["tags"].append(f"xon_breach_count_{count}")
        result["confidence_delta"] += 0.12
        for name in xon.get("breach_names") or ():
            if name:
                result["breaches"].append(
                    {"name": str(name), "date": None, "source": "xposedornot"}
                )
        if xon.get("stealer_log_exposure"):
            result["xon_stealer_log"] = True
            result["tags"].append("stealer_log_exposure")
            result["confidence_delta"] += 0.10

    if leak.get("found"):
        result["leakcheck_found"] = True
        result["leakcheck_breach_count"] = leak.get("breach_count", 0)
        result["tags"].append("leakcheck_breached")
        result["confidence_delta"] += 0.08
        for entry in leak.get("sources_detail") or ():
            name = entry.get("name") if isinstance(entry, dict) else entry
            if name:
                result["breaches"].append(
                    {
                        "name": str(name),
                        "date": entry.get("date") if isinstance(entry, dict) else None,
                        "source": "leakcheck",
                    }
                )

    # Cross-source corroboration: strongest when both corpora agree.
    if result["xon_found"] and result["leakcheck_found"]:
        result["corroborated"] = True
        result["tags"].append("breach_corroborated")
        result["confidence_delta"] += 0.10

    return result


async def check_handle_breach_exposure(handle: str) -> dict[str, Any]:
    """
    Breach-corpus exposure for a *username* / handle.

    Only LeakCheck's public tier answers for a handle, so this check reports a
    single source and never claims corroboration.  A handle hit still matters:
    a re-used forum nick or Telegram alias in a leaked corpus links the actor
    to a real identity or an older persona.

    The handle is normalised first (``@``, ``t.me/``, ``user#1234``, Matrix
    ``@user:server``), and role accounts such as ``support`` are skipped.
    """
    normalised = _normalise_handle(handle)
    result: dict[str, Any] = {
        "handle": normalised,
        "found": False,
        "breach_count": 0,
        "breaches": [],
        "fields": [],
        "stealer_log": False,
        "tags": [],
        "confidence_delta": 0.0,
        "status": "leakcheck_not_found",
    }
    if not _is_valid_handle(normalised):
        return result

    if not is_enrichment_source_enabled("leakcheck"):
        result["status"] = "leakcheck_disabled"
        return result

    try:
        rep = await _cached_query_leakcheck_handle(normalised)
    except Exception as exc:
        logger.debug(
            "breach_lookup: LeakCheck handle lookup raised for %s: %s",
            _safe_log_email(normalised), exc,
        )
        result["status"] = "leakcheck_error"
        return result

    result["status"] = rep.get("source", "leakcheck_error")
    if not rep.get("found"):
        return result

    count = int(rep.get("breach_count") or 0)
    result.update(
        {
            "found": True,
            "breach_count": count,
            "breaches": list(rep.get("breaches") or ()),
            "fields": list(rep.get("fields") or ()),
            "stealer_log": bool(rep.get("stealer_log_exposure")),
        }
    )
    result["tags"].extend(
        ["leakcheck_breached", "handle_breached", f"breach_count_{count}", "feed:leakcheck"]
    )
    result["confidence_delta"] += 0.08
    if result["stealer_log"]:
        result["tags"].append("stealer_log_exposure")
        result["confidence_delta"] += 0.10
    return result


# ---------------------------------------------------------------------------
# DB helpers (sync — called via asyncio.to_thread)
# ---------------------------------------------------------------------------

def _update_entity_flags(
    updates: list[tuple[str, str, float, list[str]]],
) -> None:
    """Update confidence and corroborating_sources for enriched entities.

    ``updates`` carries ``(entity_type, value, confidence, tags)``: the same
    e-mail can arrive as ``EMAIL_ADDRESS`` and a handle as any of the handle
    types, so the type is part of the key rather than hard-coded.
    """
    if not os.getenv("DATABASE_URL") or not updates:
        return
    try:
        from db.session import get_session
        from db.models import Entity

        with get_session() as session:
            for entity_type, value, confidence, tags in updates:
                db_entity = session.query(Entity).filter(
                    Entity.entity_type == entity_type,
                    Entity.value == value,
                ).first()
                if db_entity is None:
                    continue
                if confidence > (db_entity.confidence or 0.0):
                    db_entity.confidence = confidence
                if tags:
                    existing: list = json.loads(db_entity.corroborating_sources or "[]")
                    for tag in tags:
                        if tag not in existing:
                            existing.append(tag)
                    db_entity.corroborating_sources = json.dumps(existing)
            session.commit()
    except Exception as exc:
        logger.warning("breach_lookup: DB update failed: %s", exc)


def _persist_breach_findings(findings: list[dict], investigation_id: Any) -> int:
    """Write breach hits as ``BREACH_NAME`` nodes with ``EXPOSED_IN`` edges.

    *findings* carries one entry per (identifier, source): the identifier's
    entity types and raw value, the source that answered, the breach names it
    answered with, and the confidence to stamp.  Returns the number of edges
    written.

    Entity rows are page-attributed (``page_id`` is NOT NULL), so each source
    gets one synthetic provenance page per investigation — the lookup endpoint
    itself.  Re-running enrichment reuses that page and the existing nodes and
    edges, so a second pass never duplicates the graph.  Failures are logged
    and swallowed: enrichment must not fail because of a write-back problem.
    """
    if not os.getenv("DATABASE_URL") or not findings:
        return 0
    inv_uuid = _coerce_uuid(investigation_id)
    if inv_uuid is None:
        return 0

    written = 0
    try:
        from db.models import Entity, EntityRelationship, Page
        from db.session import get_session
        from extractor.normalizer import canonicalize_entity_value

        with get_session() as session:
            pages: dict[str, Any] = {}
            for finding in findings or ():
                breaches = [
                    breach
                    for breach in (finding.get("breaches") or ())
                    if isinstance(breach, dict) and str(breach.get("name") or "").strip()
                ]
                entity_types = [
                    str(t).upper() for t in (finding.get("entity_types") or ()) if t
                ]
                value = str(finding.get("value") or "").strip()
                if not breaches or not entity_types or not value:
                    continue

                identifiers = (
                    session.query(Entity)
                    .filter(
                        Entity.entity_type.in_(entity_types),
                        Entity.value == value,
                        Entity.investigation_id == inv_uuid,
                    )
                    .all()
                )
                if not identifiers:
                    continue

                source = str(finding.get("source") or "leakcheck").lower()
                page = pages.get(source)
                if page is None:
                    url = BREACH_PAGE_URLS.get(source, DEFAULT_BREACH_PAGE_URL)
                    page = (
                        session.query(Page)
                        .filter(Page.url == url, Page.investigation_id == inv_uuid)
                        .first()
                    )
                    if page is None:
                        page = Page(url=url, investigation_id=inv_uuid)
                        session.add(page)
                        session.flush()
                    pages[source] = page

                confidence = max(
                    0.0, min(1.0, float(finding.get("confidence") or 0.0))
                )
                for breach in breaches[:MAX_BREACH_NODES_PER_IDENTIFIER]:
                    name = str(breach.get("name") or "").strip()
                    canonical = canonicalize_entity_value(BREACH_ENTITY_TYPE, name)
                    node = (
                        session.query(Entity)
                        .filter(
                            Entity.page_id == page.id,
                            Entity.entity_type == BREACH_ENTITY_TYPE,
                            Entity.canonical_value == canonical,
                        )
                        .first()
                    )
                    if node is None:
                        node = Entity(
                            page_id=page.id,
                            investigation_id=inv_uuid,
                            entity_type=BREACH_ENTITY_TYPE,
                            value=name,
                            canonical_value=canonical,
                            confidence=confidence,
                            context_snippet=str(breach.get("date") or "") or None,
                            corroborating_sources=json.dumps([f"feed:{source}"]),
                            extraction_method="enrich",
                        )
                        session.add(node)
                        session.flush()

                    for identifier in identifiers:
                        exists = (
                            session.query(EntityRelationship.id)
                            .filter(
                                EntityRelationship.entity_a_id == identifier.id,
                                EntityRelationship.entity_b_id == node.id,
                                EntityRelationship.relationship_type
                                == BREACH_RELATIONSHIP_TYPE,
                            )
                            .first()
                        )
                        if exists is not None:
                            continue
                        session.add(
                            EntityRelationship(
                                entity_a_id=identifier.id,
                                entity_b_id=node.id,
                                relationship_type=BREACH_RELATIONSHIP_TYPE,
                                investigation_id=inv_uuid,
                                source_page_id=page.id,
                                confidence=confidence,
                            )
                        )
                        written += 1
            session.commit()
    except Exception as exc:
        logger.warning("breach_lookup: breach graph persistence failed: %s", exc)
        return 0

    if written:
        logger.info("breach_lookup: wrote %d breach relationship(s)", written)
    return written


def breach_export_rows(
    entities: list[Any],
    relationships: list[Any],
) -> list[dict[str, Any]]:
    """One row per identifier → breach ``EXPOSED_IN`` edge, for reports and exports.

    Accepts the CLI's dicts (``get_entities`` / ``get_relationships``) and ORM
    rows alike.  Rows are deduplicated and sorted, so two runs over the same
    investigation produce the same lines.
    """
    by_id: dict[str, Any] = {}
    for entity in entities or ():
        entity_id = _field(entity, "id")
        if entity_id is not None:
            by_id[str(entity_id)] = entity

    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for relationship in relationships or ():
        rel_type = str(_field(relationship, "relationship_type") or "").upper()
        if rel_type != BREACH_RELATIONSHIP_TYPE:
            continue
        identifier = by_id.get(str(_field(relationship, "entity_a_id") or ""))
        breach = by_id.get(str(_field(relationship, "entity_b_id") or ""))
        if identifier is None or breach is None:
            continue
        if str(_field(breach, "entity_type") or "").upper() != BREACH_ENTITY_TYPE:
            continue
        identifier_value = str(_field(identifier, "value") or "")
        breach_value = str(_field(breach, "value") or "")
        key = (identifier_value.lower(), breach_value.lower())
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "identifier": identifier_value,
                "identifier_type": str(_field(identifier, "entity_type") or ""),
                "breach": breach_value,
                "confidence": _field(relationship, "confidence"),
                "sources": _field(breach, "corroborating_sources"),
            }
        )
    rows.sort(key=lambda row: (row["identifier"].lower(), row["breach"].lower()))
    return rows


# ---------------------------------------------------------------------------
# Pipeline integration
# ---------------------------------------------------------------------------

def _status_string(prefix: str, checked: int, hits: int, error_state: bool) -> str:
    """Build a sources_used status string honestly reflecting what ran."""
    if error_state and checked == 0:
        return "error"
    return f"ok_{hits}_results" if checked else "ok_0_results"


def _collect_handles(extraction_results: list) -> dict[str, dict[str, Any]]:
    """Unique handle-shaped entities, keyed by normalised handle.

    One handle can arrive under several entity types (a Telegram alias and a
    forum handle with the same username), so each entry keeps every type it was
    seen as plus the strongest confidence — one lookup, all the identifiers it
    belongs to.
    """
    handles: dict[str, dict[str, Any]] = {}
    for exr in extraction_results:
        for entity in getattr(exr, "entities", []):
            etype = str(getattr(entity, "entity_type", "") or "").upper()
            if etype not in HANDLE_ENTITY_TYPES:
                continue
            raw = (getattr(entity, "value", "") or "").strip()
            if not _is_valid_handle(raw):
                continue
            key = _normalise_handle(raw).lower()
            entry = handles.setdefault(
                key, {"entity_types": [], "value": raw, "confidence": 0.0}
            )
            if etype not in entry["entity_types"]:
                entry["entity_types"].append(etype)
            entry["confidence"] = max(
                entry["confidence"], float(getattr(entity, "confidence", 1.0) or 0.0)
            )
    return handles


async def enrich_breach_entities(
    extraction_results: list,
    investigation_id: Any,
) -> tuple[list, dict]:
    """
    Post-extraction breach-exposure enrichment (STEP 6.5).

    Complements HIBP (STEP 6.4) with XposedOrNot + LeakCheck for e-mail
    addresses, and LeakCheck for handles. Each source reports its own
    ``sources_used`` status (keys ``xposedornot``, ``leakcheck`` and
    ``leakcheck_handle``). Caps at MAX_EMAILS unique addresses and MAX_HANDLES
    unique handles per investigation.

    Breach hits are also written as ``BREACH_NAME`` nodes with ``EXPOSED_IN``
    edges so the graph, the report and the exports carry them.

    Returns (extraction_results, stats_dict). ``stats_dict`` always carries the
    status keys so the orchestrator can surface them.
    """
    validate_enrichment_allowlist()  # unknown ids fail loudly, never silently

    seen: dict[str, float] = {}
    for exr in extraction_results:
        for entity in getattr(exr, "entities", []):
            if getattr(entity, "entity_type", "") != "EMAIL_ADDRESS":
                continue
            email = getattr(entity, "value", "").strip()
            if not email or not _is_valid_email(email):
                continue
            if email not in seen:
                seen[email] = getattr(entity, "confidence", 1.0)

    handles = _collect_handles(extraction_results)

    unique_emails = list(seen.keys())
    if len(unique_emails) > MAX_EMAILS:
        logger.info(
            "breach_lookup: capping to %d of %d unique emails",
            MAX_EMAILS, len(unique_emails),
        )
        unique_emails = unique_emails[:MAX_EMAILS]

    handle_list = sorted(handles.keys())
    if len(handle_list) > MAX_HANDLES:
        logger.info(
            "breach_lookup: capping to %d of %d unique handles",
            MAX_HANDLES, len(handle_list),
        )
        handle_list = handle_list[:MAX_HANDLES]

    stats: dict[str, Any] = {
        "emails_checked": len(unique_emails),
        "xon_breached": 0,
        "leakcheck_breached": 0,
        "stealer_log_exposed": 0,
        "corroborated": 0,
        "handles_checked": len(handle_list),
        "handles_breached": 0,
        "breach_edges": 0,
    }

    if not unique_emails and not handle_list:
        stats["xposedornot"] = "ok_0_results"
        stats["leakcheck"] = "ok_0_results"
        stats["leakcheck_handle"] = "ok_0_results"
        return extraction_results, stats

    logger.info(
        "breach_lookup: checking %d unique email(s), %d unique handle(s)",
        len(unique_emails), len(handle_list),
    )

    email_reps, handle_reps = await asyncio.gather(
        asyncio.gather(
            *[check_breach_exposure(e) for e in unique_emails],
            return_exceptions=True,
        ),
        asyncio.gather(
            *[check_handle_breach_exposure(h) for h in handle_list],
            return_exceptions=True,
        ),
    )

    db_updates: list[tuple[str, str, float, list[str]]] = []
    findings: list[dict[str, Any]] = []
    xon_error = False
    leakcheck_error = False
    leakcheck_handle_error = False

    for email, rep in zip(unique_emails, email_reps):
        if isinstance(rep, Exception):
            logger.debug(
                "breach_lookup: check raised for %s: %s", _safe_log_email(email), rep
            )
            xon_error = True
            leakcheck_error = True
            continue

        if rep.get("xon_status") == "xposedornot_error":
            xon_error = True
        if rep.get("leakcheck_status") == "leakcheck_error":
            leakcheck_error = True

        if rep.get("xon_found"):
            stats["xon_breached"] += 1
        if rep.get("leakcheck_found"):
            stats["leakcheck_breached"] += 1
        if rep.get("xon_stealer_log"):
            stats["stealer_log_exposed"] += 1
        if rep.get("corroborated"):
            stats["corroborated"] += 1

        tags = rep.get("tags", [])
        delta = rep.get("confidence_delta", 0.0)
        if tags or delta:
            base_conf = seen.get(email, 1.0)
            new_conf = max(0.50, min(base_conf + delta, 1.0))
            db_updates.append(("EMAIL_ADDRESS", email, new_conf, tags))
            by_source: dict[str, list[dict[str, Any]]] = {}
            for breach in rep.get("breaches") or ():
                source_name = str(breach.get("source") or "leakcheck")
                by_source.setdefault(source_name, []).append(breach)
            for source_name, items in by_source.items():
                findings.append(
                    {
                        "entity_types": ["EMAIL_ADDRESS"],
                        "value": email,
                        "source": source_name,
                        "breaches": items,
                        "confidence": new_conf,
                    }
                )

    for handle, rep in zip(handle_list, handle_reps):
        if isinstance(rep, Exception):
            logger.debug(
                "breach_lookup: handle check raised for %s: %s",
                _safe_log_email(handle), rep,
            )
            leakcheck_handle_error = True
            continue
        if rep.get("status") == "leakcheck_error":
            leakcheck_handle_error = True
        if not rep.get("found"):
            continue

        stats["handles_breached"] += 1
        entry = handles[handle]
        new_conf = max(
            0.50,
            min(entry["confidence"] + rep.get("confidence_delta", 0.0), 1.0),
        )
        for etype in entry["entity_types"]:
            db_updates.append((etype, entry["value"], new_conf, rep.get("tags", [])))
        if rep.get("breaches"):
            findings.append(
                {
                    "entity_types": list(entry["entity_types"]),
                    "value": entry["value"],
                    "source": "leakcheck",
                    "breaches": rep["breaches"],
                    "confidence": new_conf,
                }
            )
        logger.info(
            "[%s] Handle breach exposure: %s in %d corpus/corpora",
            investigation_id, _safe_log_email(handle), rep.get("breach_count", 0),
        )

    if db_updates:
        await asyncio.to_thread(_update_entity_flags, db_updates)
    if findings:
        stats["breach_edges"] = await asyncio.to_thread(
            _persist_breach_findings, findings, investigation_id
        )

    checked = stats["emails_checked"]
    stats["xposedornot"] = _status_string(
        "xposedornot", checked, stats["xon_breached"], xon_error
    )
    stats["leakcheck"] = _status_string(
        "leakcheck", checked, stats["leakcheck_breached"], leakcheck_error
    )
    stats["leakcheck_handle"] = _status_string(
        "leakcheck",
        stats["handles_checked"],
        stats["handles_breached"],
        leakcheck_handle_error,
    )

    # Report honestly when the allowlist switched a source off.
    if not is_enrichment_source_enabled("xposedornot"):
        stats["xposedornot"] = "disabled"
    if not is_enrichment_source_enabled("leakcheck"):
        stats["leakcheck"] = "disabled"
        stats["leakcheck_handle"] = "disabled"

    logger.info(
        "breach_lookup: done — %d email(s) checked, XposedOrNot %d breached "
        "(%d stealer-log), LeakCheck %d breached, %d corroborated by both; "
        "%d handle(s) checked, %d breached; %d breach edge(s) written",
        checked, stats["xon_breached"], stats["stealer_log_exposed"],
        stats["leakcheck_breached"], stats["corroborated"],
        stats["handles_checked"], stats["handles_breached"], stats["breach_edges"],
    )

    return extraction_results, stats
