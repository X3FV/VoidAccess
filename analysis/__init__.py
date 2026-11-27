"""
analysis — Temporal, behavioral pattern, OPSEC failure and deep-pivot analysis.

Public interface
---------------
from analysis.temporal  import build_activity_timeline, compute_activity_stats
from analysis.temporal  import detect_anomalies, detect_silence_breaks
from analysis.patterns  import check_exit_scam_pattern, check_law_enforcement_pattern
from analysis.patterns  import check_new_actor_pattern, run_all_patterns
from analysis.opsec     import detect_timezone_leak, detect_language_switch
from analysis.opsec     import detect_clearnet_slip, detect_pgp_reuse
from analysis.opsec     import run_full_opsec_analysis
from analysis.deep_investigation import deep_limits, select_pivots, summarize_hops
"""

from analysis.opsec import (
    detect_clearnet_slip,
    detect_language_switch,
    detect_pgp_reuse,
    detect_timezone_leak,
    run_full_opsec_analysis,
)
from analysis.patterns import (
    check_exit_scam_pattern,
    check_law_enforcement_pattern,
    check_new_actor_pattern,
    run_all_patterns,
)
from analysis.temporal import (
    build_activity_timeline,
    compute_activity_stats,
    detect_anomalies,
    detect_silence_breaks,
)
from analysis.deep_investigation import (
    DeepBudget,
    Pivot,
    build_pivot_query,
    deep_limits,
    is_pivot_candidate,
    pivot_score,
    select_pivots,
    summarize_hops,
)

__all__ = [
    "build_activity_timeline",
    "compute_activity_stats",
    "detect_anomalies",
    "detect_silence_breaks",
    "check_exit_scam_pattern",
    "check_law_enforcement_pattern",
    "check_new_actor_pattern",
    "run_all_patterns",
    "detect_timezone_leak",
    "detect_language_switch",
    "detect_clearnet_slip",
    "detect_pgp_reuse",
    "run_full_opsec_analysis",
    # deep investigation (multi-hop pivot passes)
    "DeepBudget",
    "Pivot",
    "build_pivot_query",
    "deep_limits",
    "is_pivot_candidate",
    "pivot_score",
    "select_pivots",
    "summarize_hops",
]
