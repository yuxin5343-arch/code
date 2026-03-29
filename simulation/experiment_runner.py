from __future__ import annotations

"""Playbook-driven experiment runner.

Runs four deterministic playbooks under two modes:
- one-shot collaboration (enforce actions)
- no-collaboration baseline (observe only)

Each playbook is repeated N times with tiny jitter to collect statistical samples.
"""

import asyncio
import ast
import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Dict, List, Tuple

# Allow direct script execution: `python simulation/experiment_runner.py`
if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent.parent))

from communication.async_client import AsyncAPIClient
from simulation.attack_scripts.cross_domain_attack import evaluate_attack_progression
from simulation.playbooks import Playbook, load_playbooks, materialize_playbook_events
from simulation.report_generator import generate_report

MANAGER = os.getenv("MANAGER_SERVICE", "http://127.0.0.1:8000")
OFFICE_EXECUTOR = os.getenv("EXECUTOR_OFFICE_SERVICE", "http://127.0.0.1:8101")
CORE_EXECUTOR = os.getenv("EXECUTOR_CORE_SERVICE", "http://127.0.0.1:8102")
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"

EXPERIMENT_SEED = int(os.getenv("EXPERIMENT_SEED", "20260327"))
RUNS_PER_PLAYBOOK = int(os.getenv("PLAYBOOK_RUNS", "50"))
PLAYBOOK_JITTER_MS = int(os.getenv("PLAYBOOK_JITTER_MS", "120"))
INTER_EVENT_SLEEP_JITTER_MS = int(os.getenv("INTER_EVENT_SLEEP_JITTER_MS", "60"))

MODES: List[Tuple[str, bool]] = [
    ("oneshot_collab", True),
    ("no_collab", False),
]


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _print(msg: str) -> None:
    print(f"[{_now_str()}] {msg}")


def _seed_for(mode: str, playbook_id: str, run_index: int) -> int:
    return EXPERIMENT_SEED + (17 if mode == "oneshot_collab" else 53) + (abs(hash(playbook_id)) % 10000) + run_index


def parse_dispatch_results(raw_items: List) -> List[Dict]:
    parsed: List[Dict] = []
    for item in raw_items:
        if isinstance(item, dict):
            parsed.append(item)
            continue
        if isinstance(item, str):
            try:
                converted = ast.literal_eval(item)
                if isinstance(converted, dict):
                    parsed.append(converted)
            except Exception:
                continue
    return parsed


def flatten_results(dispatch_results: List[Dict], task_lookup: Dict[str, Dict]) -> List[Dict]:
    flat: List[Dict] = []
    for dispatch in dispatch_results:
        executor = dispatch.get("executor", "unknown-executor")
        for result in dispatch.get("results", []):
            task_id = result.get("task_id", "")
            task_meta = task_lookup.get(task_id, {})
            flat.append(
                {
                    "task_id": task_id,
                    "incident_id": task_meta.get("incident_id", result.get("incident_id", "")),
                    "executor": executor,
                    "domain": task_meta.get("target_domain", executor.replace("executor-", "")),
                    "objective": task_meta.get("objective", "unknown"),
                    "status": result.get("status", "unknown"),
                    "success": result.get("success", False),
                    "latency_ms": result.get("latency_ms", 0),
                    "error": result.get("error"),
                }
            )
    return flat


def summarize_task_execution(flat_results: List[Dict]) -> Dict:
    latencies: List[int] = []
    success_count = 0
    total = 0
    by_domain: Dict[str, Dict] = {}

    for result in flat_results:
        total += 1
        ok = bool(result.get("success", False))
        domain = str(result.get("domain", "unknown"))
        latency = int(result.get("latency_ms", 0))

        if ok:
            success_count += 1
        latencies.append(latency)

        if domain not in by_domain:
            by_domain[domain] = {"tasks": 0, "success": 0, "_latencies": []}
        by_domain[domain]["tasks"] += 1
        by_domain[domain]["success"] += 1 if ok else 0
        by_domain[domain]["_latencies"].append(latency)

    for stats in by_domain.values():
        local_latencies = stats.pop("_latencies", [])
        stats["avg_latency_ms"] = int(mean(local_latencies)) if local_latencies else 0
        stats["success_rate"] = round(stats["success"] / stats["tasks"], 3) if stats["tasks"] else 0

    return {
        "tasks": total,
        "success": success_count,
        "task_success_rate": round(success_count / total, 3) if total else 0,
        "avg_latency_ms": int(mean(latencies)) if latencies else 0,
        "domain_stats": by_domain,
    }


def _extract_statuses(dispatch_block: List[Dict]) -> List[str]:
    statuses: List[str] = []
    for item in dispatch_block:
        for result in item.get("results", []):
            statuses.append(str(result.get("status", "unknown")))
    return statuses


def _status_counter(statuses: List[str]) -> Dict[str, int]:
    counts = {
        "accept": 0,
        "counter_proposal": 0,
        "reject": 0,
        "other": 0,
    }
    for item in statuses:
        if item in counts:
            counts[item] += 1
        else:
            counts["other"] += 1
    return counts


def _detection_summary(log_injection: Dict) -> Dict:
    suspicious = int(log_injection.get("suspicious", 0))
    benign = int(log_injection.get("benign", 0))
    reported_suspicious = int(log_injection.get("reported_suspicious", 0))
    reported_benign = int(log_injection.get("reported_benign", 0))

    tp = max(0, min(reported_suspicious, suspicious))
    fn = max(0, suspicious - tp)
    fp = max(0, min(reported_benign, benign))
    tn = max(0, benign - fp)

    fpr = round(fp / (fp + tn), 3) if (fp + tn) else 0.0
    fnr = round(fn / (tp + fn), 3) if (tp + fn) else 0.0
    return {
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
    }


async def wait_services_ready(client: AsyncAPIClient, retries: int = 30, interval_sec: float = 0.5) -> bool:
    endpoints = [
        f"{MANAGER}/health",
        f"{OFFICE_EXECUTOR}/health",
        f"{CORE_EXECUTOR}/health",
    ]
    for _ in range(retries):
        ok = True
        for endpoint in endpoints:
            try:
                await client.get_json(endpoint)
            except Exception:
                ok = False
                break
        if ok:
            return True
        await asyncio.sleep(interval_sec)
    return False


async def reset_runtime_state(client: AsyncAPIClient) -> None:
    await client.post_json(f"{MANAGER}/debug/reset-state", {})
    await client.post_json(f"{OFFICE_EXECUTOR}/debug/reset-state", {})
    await client.post_json(f"{CORE_EXECUTOR}/debug/reset-state", {})


async def apply_preconditions(client: AsyncAPIClient, playbook: Playbook) -> None:
    for domain, cfg in playbook.preconditions.items():
        resource_cfg = cfg.get("resource_status", {}) if isinstance(cfg, dict) else {}
        report_manager = bool(cfg.get("report_manager", True)) if isinstance(cfg, dict) else True
        endpoint = OFFICE_EXECUTOR if domain == "office" else CORE_EXECUTOR
        await client.post_json(
            f"{endpoint}/debug/resource-status",
            {"resource_status": resource_cfg, "report_manager": report_manager},
        )


async def inject_logs_for_playbook(
    client: AsyncAPIClient,
    playbook: Playbook,
    run_id: str,
    jitter_rng: random.Random,
) -> Dict:
    jitter_ms_by_event = [jitter_rng.randint(-PLAYBOOK_JITTER_MS, PLAYBOOK_JITTER_MS) for _ in playbook.events]
    logs = materialize_playbook_events(playbook=playbook, run_id=run_id, jitter_ms_by_event=jitter_ms_by_event)

    stats = {
        "sent": 0,
        "failed": 0,
        "reported_alerts": 0,
        "suspicious": 0,
        "benign": 0,
        "reported_suspicious": 0,
        "reported_benign": 0,
    }

    for log in logs:
        endpoint = OFFICE_EXECUTOR if log.get("domain") == "office" else CORE_EXECUTOR
        sleep_jitter = max(0.0, jitter_rng.uniform(0, INTER_EVENT_SLEEP_JITTER_MS) / 1000.0)
        await asyncio.sleep(sleep_jitter)

        try:
            response = await client.post_json(f"{endpoint}/local-logs", log)
            stats["sent"] += 1
            if bool(log.get("suspicious", False)):
                stats["suspicious"] += 1
            else:
                stats["benign"] += 1
            if isinstance(response, dict):
                reported = int(response.get("reported_alerts", 0))
                stats["reported_alerts"] += reported
                if bool(log.get("suspicious", False)):
                    stats["reported_suspicious"] += reported
                else:
                    stats["reported_benign"] += reported
        except Exception:
            stats["failed"] += 1

    return stats


async def run_playbook_once(playbook: Playbook, mode: str, collab_enabled: bool, run_index: int) -> Dict:
    client = AsyncAPIClient(timeout=20.0)
    seed = _seed_for(mode=mode, playbook_id=playbook.playbook_id, run_index=run_index)
    rng = random.Random(seed)

    await reset_runtime_state(client)
    await apply_preconditions(client, playbook)

    run_id = f"{playbook.playbook_id}-{mode}-{run_index}"
    injection = await inject_logs_for_playbook(client, playbook, run_id=run_id, jitter_rng=rng)

    t0 = time.perf_counter()
    decision = await client.post_json(
        f"{MANAGER}/decision/trigger",
        {"enforce_actions": collab_enabled, "clear_alerts": True},
    )
    decision_elapsed_ms = int((time.perf_counter() - t0) * 1000)

    dispatch_results = decision.get("dispatch", {}).get("dispatch_results", [])
    parsed_dispatch = parse_dispatch_results(dispatch_results)

    task_lookup: Dict[str, Dict] = {}
    for task in decision.get("task_payload", {}).get("tasks", []):
        task_id = task.get("task_id")
        if task_id:
            task_lookup[task_id] = task

    flat_results = flatten_results(parsed_dispatch, task_lookup)
    task_metrics = summarize_task_execution(flat_results)
    attack_metrics = evaluate_attack_progression(flat_results)
    detect_metrics = _detection_summary(injection)

    negotiation = decision.get("negotiation", {}) if isinstance(decision, dict) else {}
    intent_dispatch = negotiation.get("intent_dispatch", []) if isinstance(negotiation, dict) else []
    consensus_dispatch = negotiation.get("consensus_dispatch", []) if isinstance(negotiation, dict) else []
    intent_statuses = _extract_statuses(intent_dispatch)
    consensus_statuses = _extract_statuses(consensus_dispatch)

    intent_tasks = negotiation.get("intent_plan", {}).get("tasks", []) if isinstance(negotiation, dict) else []
    consensus_tasks = negotiation.get("consensus_plan", {}).get("tasks", []) if isinstance(negotiation, dict) else []
    intent_objectives = [str(t.get("objective", "")) for t in intent_tasks]
    consensus_objectives = [str(t.get("objective", "")) for t in consensus_tasks]
    max_rounds = int(negotiation.get("max_rounds", 1)) if isinstance(negotiation, dict) else 1
    timeout_ms = int(negotiation.get("timeout_ms", 0)) if isinstance(negotiation, dict) else 0

    intent_status_counts = _status_counter(intent_statuses)
    fallback_task_count = 0
    downgrade_counter_task_count = 0
    downgrade_adopt_task_count = 0
    low_confidence_reject_task_count = 0
    for task in consensus_tasks:
        constraints = task.get("constraints", {}) if isinstance(task.get("constraints"), dict) else {}
        if str(constraints.get("consensus_reason", "")) in {"fallback_safe_policy", "fallback_min_gain_policy"}:
            fallback_task_count += 1
        is_downgrade = bool(constraints.get("counter_is_downgrade", False))
        if is_downgrade:
            downgrade_counter_task_count += 1
            if str(constraints.get("consensus_reason", "")) == "adopt_counter_proposal":
                downgrade_adopt_task_count += 1
            if bool(constraints.get("low_confidence_penalty_applied", False)) and str(
                constraints.get("consensus_reason", "")
            ) == "fallback_min_gain_policy":
                low_confidence_reject_task_count += 1

    counter_triggered = any(s in {"counter_proposal", "reject"} for s in intent_statuses)
    adopted_counter = intent_objectives != consensus_objectives
    intent_accept_rate = round(sum(1 for s in intent_statuses if s == "accept") / len(intent_statuses), 3) if intent_statuses else 0.0

    analysis = decision.get("analysis", {}) if isinstance(decision, dict) else {}
    risk_level = str(analysis.get("risk_level", "low"))
    base_risk_level = str(analysis.get("base_risk_level", risk_level))
    domain_weight_factor = float(analysis.get("domain_weight_factor", 0.0))
    domain_weight_calibrated = bool(analysis.get("domain_weight_calibrated", False))

    result = {
        "run_id": run_id,
        "seed": seed,
        "mode": mode,
        "collaboration_enabled": collab_enabled,
        "playbook_id": playbook.playbook_id,
        "playbook_title": playbook.title,
        "playbook_objective": playbook.objective,
        "playbook_notes": playbook.notes,
        "decision_elapsed_ms": decision_elapsed_ms,
        "analysis_risk_level": risk_level,
        "analysis_base_risk_level": base_risk_level,
        "analysis_domain_weight_factor": domain_weight_factor,
        "analysis_domain_weight_calibrated": domain_weight_calibrated,
        "intent_statuses": intent_statuses,
        "intent_status_counts": intent_status_counts,
        "consensus_statuses": consensus_statuses,
        "max_rounds": max_rounds,
        "timeout_ms": timeout_ms,
        "intent_accept_rate": intent_accept_rate,
        "counter_triggered": counter_triggered,
        "adopted_counter": adopted_counter,
        "fallback_task_count": fallback_task_count,
        "fallback_triggered": fallback_task_count > 0,
        "downgrade_counter_task_count": downgrade_counter_task_count,
        "downgrade_adopt_task_count": downgrade_adopt_task_count,
        "low_confidence_reject_task_count": low_confidence_reject_task_count,
        "downgrade_adoption_rate": round(downgrade_adopt_task_count / downgrade_counter_task_count, 3)
        if downgrade_counter_task_count
        else 0.0,
        "intent_objectives": intent_objectives,
        "consensus_objectives": consensus_objectives,
        "false_negative": 1 if attack_metrics.get("attack_success", True) else 0,
        **task_metrics,
        **attack_metrics,
        **detect_metrics,
        "flat_results": flat_results,
    }
    result["block_rate"] = round(1 - float(result.get("attack_success_rate", 1.0)), 3)
    return result


def aggregate_runs(samples: List[Dict]) -> Dict:
    if not samples:
        return {
            "samples": 0,
            "tasks": 0,
            "success": 0,
            "task_success_rate": 0.0,
            "attack_success_rate": 1.0,
            "block_rate": 0.0,
            "false_positive_rate": 0.0,
            "false_negative_rate": 1.0,
            "avg_latency_ms": 0,
            "containment_time_ms": 0,
            "decision_elapsed_ms": 0,
            "counter_rate": 0.0,
            "adopt_counter_rate": 0.0,
            "counter_total": 0,
            "adopt_counter_total": 0,
            "fallback_total": 0,
            "fallback_rate": 0.0,
            "intent_accept_rate": 0.0,
            "intent_statuses": {
                "counts": {"accept": 0, "counter_proposal": 0, "reject": 0, "other": 0},
                "ratios": {"accept": 0.0, "counter_proposal": 0.0, "reject": 0.0, "other": 0.0},
            },
            "max_rounds": 1,
            "timeout_ms": 0,
            "lateral_spread_block_count": 0,
            "lateral_spread_count": 0,
            "domain_weight_factor_avg": 0.0,
            "risk_calibrated_rate": 0.0,
            "base_risk_distribution": {"low": 0, "medium": 0, "high": 0, "critical": 0},
            "final_risk_distribution": {"low": 0, "medium": 0, "high": 0, "critical": 0},
            "downgrade_counter_total": 0,
            "downgrade_adopt_total": 0,
            "downgrade_reject_total": 0,
            "downgrade_adoption_rate": 0.0,
            "low_confidence_reject_total": 0,
            "low_confidence_reject_rate": 0.0,
            "domain_stats": {},
        }

    total_tasks = sum(int(s.get("tasks", 0)) for s in samples)
    total_success = sum(int(s.get("success", 0)) for s in samples)

    domain_acc: Dict[str, Dict[str, List[float] | int]] = {}
    for sample in samples:
        domain_stats = sample.get("domain_stats", {})
        for domain, stats in domain_stats.items():
            entry = domain_acc.setdefault(domain, {"tasks": 0, "success": 0, "latencies": []})
            entry["tasks"] = int(entry["tasks"]) + int(stats.get("tasks", 0))
            entry["success"] = int(entry["success"]) + int(stats.get("success", 0))
            entry["latencies"].append(float(stats.get("avg_latency_ms", 0)))

    merged_domain: Dict[str, Dict] = {}
    for domain, item in domain_acc.items():
        tasks = int(item.get("tasks", 0))
        success = int(item.get("success", 0))
        latencies = [float(x) for x in item.get("latencies", [])]
        merged_domain[domain] = {
            "tasks": tasks,
            "success": success,
            "success_rate": round(success / tasks, 3) if tasks else 0.0,
            "avg_latency_ms": int(mean(latencies)) if latencies else 0,
        }

    intent_counts = {"accept": 0, "counter_proposal": 0, "reject": 0, "other": 0}
    for sample in samples:
        local_counts = sample.get("intent_status_counts", {})
        for key in intent_counts:
            intent_counts[key] += int(local_counts.get(key, 0))

    total_intent_status = sum(intent_counts.values())
    intent_ratios = {
        key: round(intent_counts[key] / total_intent_status, 3) if total_intent_status else 0.0
        for key in intent_counts
    }

    counter_total = sum(1 for s in samples if bool(s.get("counter_triggered", False)))
    adopt_counter_total = sum(1 for s in samples if bool(s.get("adopted_counter", False)))
    fallback_total = sum(1 for s in samples if bool(s.get("fallback_triggered", False)))
    calibrated_total = sum(1 for s in samples if bool(s.get("analysis_domain_weight_calibrated", False)))
    downgrade_counter_total = sum(int(s.get("downgrade_counter_task_count", 0)) for s in samples)
    downgrade_adopt_total = sum(int(s.get("downgrade_adopt_task_count", 0)) for s in samples)
    low_confidence_reject_total = sum(int(s.get("low_confidence_reject_task_count", 0)) for s in samples)
    max_rounds_values = [int(s.get("max_rounds", 1)) for s in samples]
    timeout_values = [int(s.get("timeout_ms", 0)) for s in samples]
    lateral_spread_block_count = sum(1 for s in samples if float(s.get("lateral_spread_count", 3.0)) < 3.0)

    risk_levels = ["low", "medium", "high", "critical"]
    base_risk_distribution = {k: 0 for k in risk_levels}
    final_risk_distribution = {k: 0 for k in risk_levels}
    for s in samples:
        base_key = str(s.get("analysis_base_risk_level", "low"))
        final_key = str(s.get("analysis_risk_level", "low"))
        if base_key in base_risk_distribution:
            base_risk_distribution[base_key] += 1
        if final_key in final_risk_distribution:
            final_risk_distribution[final_key] += 1

    return {
        "samples": len(samples),
        "tasks": total_tasks,
        "success": total_success,
        "task_success_rate": round(total_success / total_tasks, 3) if total_tasks else 0.0,
        "attack_success_rate": round(mean(float(s.get("attack_success_rate", 1.0)) for s in samples), 3),
        "block_rate": round(mean(float(s.get("block_rate", 0.0)) for s in samples), 3),
        "false_positive_rate": round(mean(float(s.get("false_positive_rate", 0.0)) for s in samples), 3),
        "false_negative_rate": round(mean(float(s.get("false_negative_rate", 0.0)) for s in samples), 3),
        "avg_latency_ms": int(mean(int(s.get("avg_latency_ms", 0)) for s in samples)),
        "containment_time_ms": int(mean(int(s.get("containment_time_ms", 0)) for s in samples)),
        "decision_elapsed_ms": int(mean(int(s.get("decision_elapsed_ms", 0)) for s in samples)),
        "counter_rate": round(counter_total / len(samples), 3),
        "adopt_counter_rate": round(adopt_counter_total / len(samples), 3),
        "counter_total": counter_total,
        "adopt_counter_total": adopt_counter_total,
        "fallback_total": fallback_total,
        "fallback_rate": round(fallback_total / len(samples), 3),
        "intent_accept_rate": round(mean(float(s.get("intent_accept_rate", 0.0)) for s in samples), 3),
        "intent_statuses": {
            "counts": intent_counts,
            "ratios": intent_ratios,
        },
        "max_rounds": int(max(max_rounds_values)) if max_rounds_values else 1,
        "timeout_ms": int(mean(timeout_values)) if timeout_values else 0,
        "lateral_spread_block_count": lateral_spread_block_count,
        "lateral_spread_count": round(mean(float(s.get("lateral_spread_count", 0)) for s in samples), 3),
        "domain_weight_factor_avg": round(mean(float(s.get("analysis_domain_weight_factor", 0.0)) for s in samples), 3),
        "risk_calibrated_rate": round(calibrated_total / len(samples), 3),
        "base_risk_distribution": base_risk_distribution,
        "final_risk_distribution": final_risk_distribution,
        "downgrade_counter_total": int(downgrade_counter_total),
        "downgrade_adopt_total": int(downgrade_adopt_total),
        "downgrade_reject_total": int(max(0, downgrade_counter_total - downgrade_adopt_total)),
        "downgrade_adoption_rate": round(downgrade_adopt_total / downgrade_counter_total, 3)
        if downgrade_counter_total
        else 0.0,
        "low_confidence_reject_total": int(low_confidence_reject_total),
        "low_confidence_reject_rate": round(low_confidence_reject_total / downgrade_counter_total, 3)
        if downgrade_counter_total
        else 0.0,
        "domain_stats": merged_domain,
    }


def build_group_summary(samples: List[Dict]) -> Dict:
    by_mode: Dict[str, List[Dict]] = {m: [] for m, _ in MODES}
    by_mode_playbook: Dict[str, Dict[str, List[Dict]]] = {m: {} for m, _ in MODES}

    for sample in samples:
        mode = str(sample.get("mode", "unknown"))
        playbook_id = str(sample.get("playbook_id", "unknown"))
        by_mode.setdefault(mode, []).append(sample)
        by_mode_playbook.setdefault(mode, {}).setdefault(playbook_id, []).append(sample)

    mode_summary = {mode: aggregate_runs(items) for mode, items in by_mode.items()}

    mode_playbook_summary: Dict[str, Dict[str, Dict]] = {}
    for mode, pb in by_mode_playbook.items():
        mode_playbook_summary[mode] = {playbook_id: aggregate_runs(items) for playbook_id, items in pb.items()}

    return {
        "by_mode": mode_summary,
        "by_mode_playbook": mode_playbook_summary,
    }


def persist_experiment(result: Dict, metadata: Dict) -> Tuple[Path, Path]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    json_path = RESULTS_DIR / f"experiment_{timestamp}.json"
    html_path = RESULTS_DIR / f"report_{timestamp}.html"

    artifact = {
        **result,
        "reproducibility": metadata,
    }
    json_path.write_text(json.dumps(artifact, ensure_ascii=False, indent=2), encoding="utf-8")

    generate_report(result, html_path)
    return json_path, html_path


async def main() -> None:
    _print("Playbook experiment started")
    _print(f"manager={MANAGER}")
    _print(f"office_executor={OFFICE_EXECUTOR}")
    _print(f"core_executor={CORE_EXECUTOR}")
    _print(f"seed={EXPERIMENT_SEED}, runs_per_playbook={RUNS_PER_PLAYBOOK}")

    client = AsyncAPIClient(timeout=20.0)
    ready = await wait_services_ready(client)
    if not ready:
        raise RuntimeError("services not ready")

    playbooks = load_playbooks()
    all_samples: List[Dict] = []

    total_runs = len(playbooks) * RUNS_PER_PLAYBOOK * len(MODES)
    finished = 0

    for mode, collab_enabled in MODES:
        for playbook in playbooks:
            _print(f"running mode={mode} playbook={playbook.playbook_id} repeats={RUNS_PER_PLAYBOOK}")
            for run_idx in range(1, RUNS_PER_PLAYBOOK + 1):
                sample = await run_playbook_once(
                    playbook=playbook,
                    mode=mode,
                    collab_enabled=collab_enabled,
                    run_index=run_idx,
                )
                all_samples.append(sample)
                finished += 1
                if run_idx % 10 == 0 or run_idx == RUNS_PER_PLAYBOOK:
                    _print(
                        "progress {}/{} mode={} playbook={} attack_success_rate={:.3f} intent_accept_rate={:.3f}".format(
                            finished,
                            total_runs,
                            mode,
                            playbook.playbook_id,
                            float(sample.get("attack_success_rate", 1.0)),
                            float(sample.get("intent_accept_rate", 0.0)),
                        )
                    )

    summary = build_group_summary(all_samples)
    expected_samples = len(playbooks) * RUNS_PER_PLAYBOOK
    mode_samples = {
        mode: int(summary["by_mode"].get(mode, {}).get("samples", 0))
        for mode, _ in MODES
    }

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "experiment_type": "playbook_driven",
        "total_samples": len(all_samples),
        "expected_samples": expected_samples * len(MODES),
        "samples_per_mode": mode_samples,
        "playbooks": [
            {
                "playbook_id": pb.playbook_id,
                "title": pb.title,
                "objective": pb.objective,
                "notes": pb.notes,
            }
            for pb in playbooks
        ],
        "summary": summary,
        "samples": all_samples,
    }

    metadata = {
        "seed": EXPERIMENT_SEED,
        "runs_per_playbook": RUNS_PER_PLAYBOOK,
        "playbook_jitter_ms": PLAYBOOK_JITTER_MS,
        "inter_event_sleep_jitter_ms": INTER_EVENT_SLEEP_JITTER_MS,
        "manager_service": MANAGER,
        "office_executor_service": OFFICE_EXECUTOR,
        "core_executor_service": CORE_EXECUTOR,
        "modes": [mode for mode, _ in MODES],
    }

    json_path, html_path = persist_experiment(report, metadata)

    _print(f"done total_samples={len(all_samples)} expected={report['expected_samples']}")
    _print(f"oneshot_collab_samples={mode_samples.get('oneshot_collab', 0)}")
    _print(f"no_collab_samples={mode_samples.get('no_collab', 0)}")
    _print(f"json={json_path}")
    _print(f"html={html_path}")


if __name__ == "__main__":
    asyncio.run(main())
