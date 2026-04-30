from __future__ import annotations
from typing import Dict, Any, List, Tuple, Set, Optional
from collections import Counter, defaultdict
from pathlib import Path
import time
import json

from ..utils.logger import get_logger

logger = get_logger(__name__)


CacheItem = Tuple[str, str, str, bool]


def _extract_cache_added(entry: Dict[str, Any]) -> Set[CacheItem]:
    """Extract normalized cache 'added' items from a DNS-Monitor cache entry."""
    items: Set[CacheItem] = set()
    try:
        diff = entry.get("diff") or {}
        added = diff.get("added") or []
        for it in added:
            name = str(it.get("name", ""))
            rtype = str(it.get("rtype", ""))
            rdata = str(it.get("rdata", ""))
            is_neg = bool(it.get("is_neg", False))
            items.add((name, rtype, rdata, is_neg))
    except Exception as e:
        logger.debug(f"Failed to extract cache added items: {e}")
    return items


def _extract_resolver_tx(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Extract a compact resolver transaction snapshot."""
    tx = entry.get("transaction") or {}
    return {
        "query_name": tx.get("query_name"),
        "query_type": tx.get("query_type"),
        "rcode": tx.get("rcode"),
        "answer_count": tx.get("answer_count"),
        "duration": tx.get("duration"),
        "status": tx.get("status"),
    }


def _extract_resolver_path(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Extract resolution path information from analyzed_path."""
    try:
        tx = entry.get("transaction") or {}
        analyzed_path = tx.get("analyzed_path") or {}
        steps = analyzed_path.get("steps") or []
        
        # Collect step information
        step_info = []
        dst_ips = []
        queries = []
        
        for step in steps:
            query = step.get("query") or {}
            response = step.get("response") or {}
            
            dst_ip = query.get("dst_ip")
            qname = query.get("qname")
            qtype = query.get("qtype")
            rcode = response.get("rcode")
            duration = step.get("duration")
            
            if dst_ip:
                dst_ips.append(dst_ip)
            
            step_data = {
                "dst_ip": dst_ip,
                "qname": qname,
                "qtype": qtype,
                "rcode": rcode,
                "duration": duration,
            }
            step_info.append(step_data)
            
            # Track unique queries as (dst_ip, qname, qtype)
            if dst_ip and qname and qtype:
                queries.append((dst_ip, qname, qtype))
        
        return {
            "steps": step_info,
            "step_count": len(steps),
            "dst_ips": dst_ips,
            "unique_dst_ips": list(set(dst_ips)),
            "queries": queries,
        }
    except Exception as e:
        logger.debug(f"Failed to extract resolver path: {e}")
        return {
            "steps": [],
            "step_count": 0,
            "dst_ips": [],
            "unique_dst_ips": [],
            "queries": [],
        }


class CompareEngine:
    """Maintain a rolling window of monitor results and compute comparisons."""

    def __init__(
        self,
        window_size: int = 10,
        enable_cache_compare: bool = True,
        enable_resolver_compare: bool = True,
    ) -> None:
        self.window: List[Dict[str, Any]] = []
        self.window_size = max(1, int(window_size))
        self.enable_cache_compare = enable_cache_compare
        self.enable_resolver_compare = enable_resolver_compare

    def add_result(self, result: Dict[str, Any]) -> None:
        """Add a monitor result into the rolling window."""
        self.window.append(result)
        if len(self.window) > self.window_size:
            self.window.pop(0)

    def compute_summary(self) -> Dict[str, Any]:
        """Compute a comparison summary across current window."""
        summary: Dict[str, Any] = {
            "timestamp": time.time(),
            "window_size": len(self.window),
            "cache": {},
            "resolver": {},
        }

        if not self.window:
            summary["message"] = "No data in window"
            return summary

        # Cache comparison across sources and window
        if self.enable_cache_compare:
            # Track per-source item frequencies
            source_counters: Dict[str, Counter] = defaultdict(Counter)
            # Latest snapshot cross-source diffs (from most recent result)
            latest = self.window[-1]
            latest_cache_sources = {k: v for k, v in latest.items() if k.startswith("cache:")}
            latest_sets: Dict[str, Set[CacheItem]] = {}
            for src, entry in latest_cache_sources.items():
                latest_sets[src] = _extract_cache_added(entry)

            # Build window counters
            for res in self.window:
                for src, entry in res.items():
                    if not src.startswith("cache:"):
                        continue
                    items = _extract_cache_added(entry)
                    for it in items:
                        source_counters[src][it] += 1

            # Compute cross-source differences for latest
            cross_diffs: Dict[str, Any] = {}
            sources = list(latest_sets.keys())
            if len(sources) >= 2:
                for i in range(len(sources)):
                    for j in range(i + 1, len(sources)):
                        s1, s2 = sources[i], sources[j]
                        only_s1 = sorted(list(latest_sets[s1] - latest_sets[s2]))
                        only_s2 = sorted(list(latest_sets[s2] - latest_sets[s1]))
                        both = sorted(list(latest_sets[s1] & latest_sets[s2]))
                        cross_diffs[f"{s1} vs {s2}"] = {
                            "only_left": only_s1[:25],
                            "only_right": only_s2[:25],
                            "intersection": both[:25],
                        }

            # Top frequent items per source
            top_per_source: Dict[str, List[Tuple[CacheItem, int]]] = {}
            for src, counter in source_counters.items():
                top_per_source[src] = counter.most_common(25)

            summary["cache"] = {
                "latest_cross_diffs": cross_diffs,
                "top_items_per_source": {
                    src: [
                        {
                            "item": {
                                "name": it[0],
                                "rtype": it[1],
                                "rdata": it[2],
                                "is_neg": it[3],
                            },
                            "count": cnt,
                        }
                        for it, cnt in top_per_source[src]
                    ]
                    for src in top_per_source
                },
            }

        # Resolver comparison across window
        if self.enable_resolver_compare:
            # Aggregate basic stats per resolver source
            durations: Dict[str, List[float]] = defaultdict(list)
            rcode_counts: Dict[str, Counter] = defaultdict(Counter)
            answer_counts: Dict[str, List[int]] = defaultdict(list)
            
            # Aggregate resolution path stats across window
            path_dst_ips: Dict[str, Set[str]] = defaultdict(set)
            path_queries: Dict[str, List[Tuple[str, str, str]]] = defaultdict(list)
            path_dst_ip_frequencies: Dict[str, Counter] = defaultdict(Counter)
            path_qname_frequencies: Dict[str, Counter] = defaultdict(Counter)
            path_details: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

            for res in self.window:
                for src, entry in res.items():
                    if not src.startswith("resolver:"):
                        continue
                    tx = _extract_resolver_tx(entry)
                    dur = tx.get("duration")
                    ans = tx.get("answer_count")
                    rcode = tx.get("rcode")
                    if isinstance(dur, (int, float)):
                        durations[src].append(float(dur))
                    if isinstance(ans, int):
                        answer_counts[src].append(ans)
                    if rcode:
                        rcode_counts[src][rcode] += 1
                    
                    # Extract and aggregate path information
                    path_info = _extract_resolver_path(entry)
                    if path_info["step_count"] > 0:
                        path_dst_ips[src].update(path_info["unique_dst_ips"])
                        path_queries[src].extend(path_info["queries"])
                        
                        # Count dst_ip frequencies across all queries in window
                        for dst_ip in path_info["dst_ips"]:
                            path_dst_ip_frequencies[src][dst_ip] += 1
                        
                        # Count qname frequencies across all queries in window
                        for step in path_info["steps"]:
                            qname = step.get("qname")
                            if qname:
                                path_qname_frequencies[src][qname] += 1
                        
                        # Store path details for latest result (for cross-comparison)
                        if res == self.window[-1]:
                            path_details[src].append({
                                "steps": path_info["steps"],
                                "step_count": path_info["step_count"],
                                "unique_dst_ips": path_info["unique_dst_ips"],
                            })

            resolver_summary: Dict[str, Any] = {}
            all_sources = set(list(durations.keys()) + list(rcode_counts.keys()) + 
                            list(answer_counts.keys()) + list(path_dst_ips.keys()))
            
            for src in all_sources:
                dur_list = durations.get(src, [])
                avg_duration = sum(dur_list) / len(dur_list) if dur_list else None
                rcode_top = rcode_counts.get(src, Counter()).most_common(3)
                ans_list = answer_counts.get(src, [])
                avg_answers = sum(ans_list) / len(ans_list) if ans_list else None
                
                # Path statistics (aggregated across window)
                unique_dst_ips = list(path_dst_ips.get(src, set()))
                dst_ip_top = path_dst_ip_frequencies.get(src, Counter()).most_common(10)
                qname_top = path_qname_frequencies.get(src, Counter()).most_common(10)
                
                resolver_summary[src] = {
                    "avg_duration": avg_duration,
                    "rcode_top": rcode_top,
                    "avg_answers": avg_answers,
                    "samples": len(dur_list) if dur_list else 0,  # Number of queries in window (e.g., 2 if window_size=2)
                    "path_stats": {
                        "unique_dst_ips": unique_dst_ips,
                        "dst_ip_frequencies": dst_ip_top,
                        "qname_frequencies": qname_top,
                        "total_steps": len(path_queries.get(src, [])),  # Total resolution steps across all queries in window
                    }
                }
            
            # Cross-resolver path comparison for latest result only
            # Note: step_count here refers to the number of resolution steps in the LATEST query,
            # not the total across the window (that's total_steps in path_stats above)
            path_comparison: Dict[str, Any] = {}
            resolver_sources = list(path_details.keys())
            if len(resolver_sources) >= 2:
                for i in range(len(resolver_sources)):
                    for j in range(i + 1, len(resolver_sources)):
                        src1, src2 = resolver_sources[i], resolver_sources[j]
                        
                        # Get latest path details
                        path1 = path_details[src1][0] if path_details[src1] else None
                        path2 = path_details[src2][0] if path_details[src2] else None
                        
                        if path1 and path2:
                            dst_ips1 = set(path1["unique_dst_ips"])
                            dst_ips2 = set(path2["unique_dst_ips"])
                            
                            # Compare dst_ips
                            only_src1_ips = sorted(list(dst_ips1 - dst_ips2))
                            only_src2_ips = sorted(list(dst_ips2 - dst_ips1))
                            common_ips = sorted(list(dst_ips1 & dst_ips2))
                            
                            # Compare step sequences
                            steps1 = path1["steps"]
                            steps2 = path2["steps"]
                            step_count_diff = path1["step_count"] - path2["step_count"]
                            
                            comparison_data = {
                                "_note": "This comparison is for the LATEST query only",
                                "step_count_left": path1["step_count"],  # Number of steps in latest query
                                "step_count_right": path2["step_count"],  # Number of steps in latest query
                                "step_count_diff": step_count_diff,
                                "dst_ips_only_left": only_src1_ips,
                                "dst_ips_only_right": only_src2_ips,
                                "dst_ips_common": common_ips,
                                "steps_left": steps1[:10],  # Limit to first 10 steps
                                "steps_right": steps2[:10],
                            }
                            
                            # Add interpretation of the differences
                            interpretations = []
                            if step_count_diff != 0:
                                if step_count_diff < 0:
                                    interpretations.append(f"{src1} used {abs(step_count_diff)} fewer steps")
                                else:
                                    interpretations.append(f"{src1} used {step_count_diff} more steps")
                            
                            if only_src1_ips:
                                interpretations.append(f"{src1} queried {len(only_src1_ips)} unique server(s) not used by {src2}")
                            if only_src2_ips:
                                interpretations.append(f"{src2} queried {len(only_src2_ips)} unique server(s) not used by {src1}")
                            
                            if interpretations:
                                comparison_data["interpretation"] = "; ".join(interpretations)
                            
                            path_comparison[f"{src1} vs {src2}"] = comparison_data
            
            resolver_summary["cross_comparison"] = path_comparison
            summary["resolver"] = resolver_summary

        return summary

    def save_summary(self, output_dir: Path, summary: Optional[Dict[str, Any]] = None) -> Path:
        """Save comparison summary to a JSON file and return the path."""
        if summary is None:
            summary = self.compute_summary()
        ts = int(time.time())
        out = output_dir / f"compare_{ts}.json"
        try:
            with open(out, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2)
            logger.debug(f"Saved compare summary to {out}")
        except Exception as e:
            logger.error(f"Failed to save compare summary: {e}")
        return out