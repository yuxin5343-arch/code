from __future__ import annotations

import ast
import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Dict, List

# Allow direct script execution: `python simulation/experiment_runner.py`
if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent.parent))

from communication.async_client import AsyncAPIClient
from simulation.attack_scripts.cross_domain_attack import evaluate_attack_progression
from simulation.report_generator import generate_report
from simulation.traffic_generator import TrafficGenerator

# 关键修改：从环境变量读取服务地址，本地调试用127.0.0.1，容器内用服务名
MANAGER = os.getenv("MANAGER_SERVICE", "http://127.0.0.1:8000")
OFFICE_EXECUTOR = os.getenv("EXECUTOR_OFFICE_SERVICE", "http://127.0.0.1:8101")
CORE_EXECUTOR = os.getenv("EXECUTOR_CORE_SERVICE", "http://127.0.0.1:8102")
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"


async def feed_local_logs(client: AsyncAPIClient, endpoint: str, logs: List[Dict]) -> None:
    for log in logs:
        try:
            await client.post_json(f"{endpoint}/local-logs", log)
        except Exception as exc:
            print(f"[ERROR] feed_local_logs failed: {exc}")


async def wait_services_ready(client: AsyncAPIClient, retries: int = 20, interval_sec: float = 0.5) -> bool:
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


async def wait_alerts_ready(client: AsyncAPIClient, expected_min: int = 2, retries: int = 30, interval_sec: float = 0.3) -> bool:
    for _ in range(retries):
        try:
            health = await client.get_json(f"{MANAGER}/health")
            if int(health.get("alert_buffer_size", 0)) >= expected_min:
                return True
        except Exception:
            pass
        await asyncio.sleep(interval_sec)
    return False


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
            except Exception as exc:
                print(f"[ERROR] Failed to parse dispatch result string: {exc}")
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
                    "executor": executor,
                    "domain": task_meta.get("target_domain", executor.replace("executor-", "")),
                    "objective": task_meta.get("objective", "unknown"),
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
    by_objective: Dict[str, Dict] = {}

    for result in flat_results:
        total += 1
        ok = bool(result.get("success", False))
        domain = result.get("domain", "unknown")
        objective = result.get("objective", "unknown")
        latency = int(result.get("latency_ms", 0))

        if ok:
            success_count += 1
        latencies.append(latency)

        if domain not in by_domain:
            by_domain[domain] = {"tasks": 0, "success": 0, "_latencies": []}
        by_domain[domain]["tasks"] += 1
        by_domain[domain]["success"] += 1 if ok else 0
        by_domain[domain]["_latencies"].append(latency)

        if objective not in by_objective:
            by_objective[objective] = {"tasks": 0, "success": 0}
        by_objective[objective]["tasks"] += 1
        by_objective[objective]["success"] += 1 if ok else 0

    for stats in by_domain.values():
        local_latencies = stats.pop("_latencies", [])
        stats["avg_latency_ms"] = int(mean(local_latencies)) if local_latencies else 0
        stats["success_rate"] = round(stats["success"] / stats["tasks"], 3) if stats["tasks"] else 0

    for stats in by_objective.values():
        stats["success_rate"] = round(stats["success"] / stats["tasks"], 3) if stats["tasks"] else 0

    return {
        "tasks": total,
        "success": success_count,
        "task_success_rate": round(success_count / total, 3) if total else 0,
        "avg_latency_ms": int(mean(latencies)) if latencies else 0,
        "domain_stats": by_domain,
        "objective_stats": by_objective,
    }


def persist_experiment(result: Dict) -> tuple[Path, Path]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    json_path = RESULTS_DIR / f"experiment_{timestamp}.json"
    html_path = RESULTS_DIR / f"report_{timestamp}.html"

    json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    generate_report(result, html_path)
    return json_path, html_path


async def run_once(defense_enabled: bool) -> Dict:
    client = AsyncAPIClient(timeout=20.0)
    generator = TrafficGenerator()

    ready = await wait_services_ready(client)
    if not ready:
        return {
            "tasks": 0,
            "success": 0,
            "task_success_rate": 0,
            "attack_success_rate": 0,
            "lateral_spread_count": 0,
            "containment_time_ms": 0,
            "avg_latency_ms": 0,
            "decision_elapsed_ms": 0,
            "error": "services not ready",
            "domain_stats": {},
            "objective_stats": {},
            "flat_results": [],
        }

    office_logs = generator.generate_local_logs("office", attack=True, count=25)
    core_logs = generator.generate_local_logs("core", attack=True, count=25)

    try:
        await asyncio.gather(
            feed_local_logs(client, OFFICE_EXECUTOR, office_logs),
            feed_local_logs(client, CORE_EXECUTOR, core_logs),
        )
    except Exception as exc:
        print(f"[ERROR] gather feed_local_logs failed: {exc}")

    alerts_ready = await wait_alerts_ready(client, expected_min=2)
    t0 = time.perf_counter()

    if not alerts_ready:
        return {
            "tasks": 0,
            "success": 0,
            "task_success_rate": 0,
            "attack_success_rate": 1.0,
            "lateral_spread_count": 3,
            "containment_time_ms": 0,
            "avg_latency_ms": 0,
            "decision_elapsed_ms": 0,
            "error": "executor alerts not ready",
            "domain_stats": {},
            "objective_stats": {},
            "flat_results": [],
        }

    try:
        decision = await client.post_json(
            f"{MANAGER}/decision/trigger",
            {"enforce_actions": defense_enabled, "clear_alerts": True},
        )
    except Exception as exc:
        print(f"[ERROR] decision/trigger failed: {exc}")
        return {
            "tasks": 0,
            "success": 0,
            "task_success_rate": 0,
            "attack_success_rate": 1.0,
            "lateral_spread_count": 3,
            "containment_time_ms": 0,
            "avg_latency_ms": 0,
            "decision_elapsed_ms": 0,
            "error": str(exc),
            "domain_stats": {},
            "objective_stats": {},
            "flat_results": [],
        }

    elapsed = int((time.perf_counter() - t0) * 1000)
    dispatch_results = decision.get("dispatch", {}).get("dispatch_results", [])
    parsed_dispatch = parse_dispatch_results(dispatch_results)

    task_lookup: Dict[str, Dict] = {}
    for task in decision.get("task_payload", {}).get("tasks", []):
        task_id = task.get("task_id")
        if task_id:
            task_lookup[task_id] = task

    flat_results = flatten_results(parsed_dispatch, task_lookup)
    metrics = summarize_task_execution(flat_results)
    attack_effect = evaluate_attack_progression(flat_results)
    metrics.update(attack_effect)
    metrics["block_rate"] = round(1 - metrics.get("attack_success_rate", 1), 3)
    metrics["decision_elapsed_ms"] = elapsed
    metrics["flat_results"] = flat_results
    metrics["decision"] = decision.get("decision", {})
    metrics["manager_alert_sources"] = decision.get("alert_sources", [])
    return metrics


async def main() -> None:
    print("[INFO] Running with defense...")
    with_defense = await run_once(defense_enabled=True)
    print("[INFO] Running without defense...")
    without_defense = await run_once(defense_enabled=False)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "with_defense": with_defense,
        "without_defense": without_defense,
        "delta": {
            "attack_success_rate_delta": round(
                without_defense.get("attack_success_rate", 0) - with_defense.get("attack_success_rate", 0), 3
            ),
            "lateral_spread_delta": without_defense.get("lateral_spread_count", 0)
            - with_defense.get("lateral_spread_count", 0),
            "latency_delta_ms": with_defense.get("avg_latency_ms", 0)
            - without_defense.get("avg_latency_ms", 0),
        },
    }

    json_path, html_path = persist_experiment(report)
    print("=== Experiment Result ===")
    print("With Defense:", with_defense)
    print("Without Defense:", without_defense)
    print(f"[INFO] JSON saved to: {json_path}")
    print(f"[INFO] HTML report saved to: {html_path}")


if __name__ == "__main__":
    asyncio.run(main())