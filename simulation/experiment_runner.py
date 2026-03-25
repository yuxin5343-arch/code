from __future__ import annotations

"""实验总控脚本。

负责联动 manager/executor 服务，注入日志，触发决策并汇总实验指标。
"""

import ast
import asyncio
import json
import os
import random
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
ATTACK_PROFILE = os.getenv("ATTACK_PROFILE", "mixed")
ATTACK_MODE = os.getenv("ATTACK_MODE", "real")
SCENARIO_ID = os.getenv("SCENARIO_ID", "B_privilege_data_theft")
EXPERIMENT_SEED = int(os.getenv("EXPERIMENT_SEED", "20260325"))
ATTACK_MIX_THRESHOLD = float(os.getenv("ATTACK_MIX_THRESHOLD", "0.45"))
SCRIPTED_ATTACK_THRESHOLD = float(os.getenv("SCRIPTED_ATTACK_THRESHOLD", "0.25"))
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
ENABLE_ANSI_COLOR = os.getenv("ANSI_COLOR", "1") != "0" and sys.stdout.isatty()

ANSI_RESET = "\033[0m"
ANSI_RED = "\033[31m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"

SCENARIO_PRESETS = {
    "A_lateral_penetration": {
        "description": "Web域受控后横向扫描并尝试进入核心域",
        "office_profile": "command_execution",
        "core_profile": "privilege_escalation",
        "real_count": 12,
        "data_count": 25,
    },
    "B_privilege_data_theft": {
        "description": "办公域权限扩散并尝试访问核心敏感数据",
        "office_profile": "privilege_escalation",
        "core_profile": "sensitive_file_access",
        "real_count": 10,
        "data_count": 22,
    },
}


def _scenario_config() -> Dict:
    selected = SCENARIO_PRESETS.get(SCENARIO_ID)
    if selected:
        return selected
    return {
        "description": "fallback mixed attack profile",
        "office_profile": ATTACK_PROFILE,
        "core_profile": ATTACK_PROFILE,
        "real_count": 12,
        "data_count": 25,
    }


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _sep(char: str = "-") -> str:
    return char * 86


def _rate_to_pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def _color(text: str, ansi_code: str) -> str:
    if not ENABLE_ANSI_COLOR:
        return text
    return f"{ansi_code}{text}{ANSI_RESET}"


def _green(text: str) -> str:
    return _color(text, ANSI_GREEN)


def _yellow(text: str) -> str:
    return _color(text, ANSI_YELLOW)


def _red(text: str) -> str:
    return _color(text, ANSI_RED)


def _color_rate(value: float, lower_is_better: bool = True) -> str:
    text = _rate_to_pct(value)
    if lower_is_better:
        if value <= 0.2:
            return _green(text)
        if value <= 0.6:
            return _yellow(text)
        return _red(text)
    if value >= 0.8:
        return _green(text)
    if value >= 0.5:
        return _yellow(text)
    return _red(text)


def _print_banner() -> None:
    print(_sep("="))
    print(_green("Cross-Domain Defense Experiment"))
    print(_sep("="))
    print(f"[{_now_str()}] mode={ATTACK_MODE} profile={ATTACK_PROFILE}")
    print(f"[{_now_str()}] manager={MANAGER}")
    print(f"[{_now_str()}] office_executor={OFFICE_EXECUTOR}")
    print(f"[{_now_str()}] core_executor={CORE_EXECUTOR}")
    print(f"[{_now_str()}] scenario={SCENARIO_ID}")
    print(f"[{_now_str()}] seed={EXPERIMENT_SEED}")
    print(_sep("-"))


def _seed_for_run(mode_label: str, channel: str) -> int:
    base = EXPERIMENT_SEED
    mode_offset = 101 if mode_label == "with_defense" else 202
    channel_offset = {
        "traffic": 1,
        "office_real": 2,
        "core_real": 3,
    }.get(channel, 0)
    return base + mode_offset + channel_offset


def _print_step(stage: str, detail: str) -> None:
    message = f"[{_now_str()}] {stage:<18} | {detail}"
    lower = detail.lower()
    if "error" in lower or "failed" in lower:
        print(_red(message))
    elif "等待" in detail or "retry" in lower or "warn" in lower:
        print(_yellow(message))
    elif "完成" in detail or "就绪" in detail or "saved" in lower:
        print(_green(message))
    else:
        print(message)


def _progress_bar(current: int, total: int, width: int = 20) -> str:
    safe_total = total if total > 0 else 1
    safe_current = max(0, min(current, safe_total))
    filled = int(width * safe_current / safe_total)
    return "[" + ("#" * filled) + ("-" * (width - filled)) + "]"


def _print_stat_table(title: str, rows: List[Dict], key_col: str) -> None:
    print(_sep("-"))
    print(title)
    print(_sep("-"))
    if not rows:
        print("(empty)")
        return

    print(f"{key_col:<22}{'tasks':<10}{'success':<10}{'success_rate':<14}{'avg_latency_ms':<16}")
    print(_sep("-"))
    for row in rows:
        print(
            f"{row.get(key_col, 'unknown'):<22}{int(row.get('tasks', 0)):<10}{int(row.get('success', 0)):<10}"
            f"{_color_rate(float(row.get('success_rate', 0)), lower_is_better=False):<14}{int(row.get('avg_latency_ms', 0)):<16}"
        )


def _print_run_summary(title: str, metrics: Dict) -> None:
    print(_sep("-"))
    print(_green(f"{title}"))
    print(_sep("-"))
    if metrics.get("error"):
        print(f"error               : {_red(str(metrics.get('error')))}")
        return

    print(f"tasks               : {metrics.get('tasks', 0)}")
    print(f"task_success_rate   : {_color_rate(float(metrics.get('task_success_rate', 0)), lower_is_better=False)}")
    print(f"attack_success_rate : {_color_rate(float(metrics.get('attack_success_rate', 0)), lower_is_better=True)}")
    print(f"block_rate          : {_color_rate(float(metrics.get('block_rate', 0)), lower_is_better=False)}")
    print(f"false_positive_rate : {_color_rate(float(metrics.get('false_positive_rate', 0)), lower_is_better=True)}")
    print(f"false_negative_rate : {_color_rate(float(metrics.get('false_negative_rate', 0)), lower_is_better=True)}")
    print(f"closure_rate        : {_color_rate(float(metrics.get('incident_closure_rate', 0)), lower_is_better=False)}")
    print(f"closure_time_ms     : {metrics.get('mean_closure_time_ms', 0)}")
    print(f"lateral_spread      : {metrics.get('lateral_spread_count', 0)}")
    print(f"avg_latency_ms      : {metrics.get('avg_latency_ms', 0)}")
    print(f"decision_elapsed_ms : {metrics.get('decision_elapsed_ms', 0)}")

    domain_rows = []
    for domain, stats in metrics.get("domain_stats", {}).items():
        domain_rows.append(
            {
                "domain": domain,
                "tasks": stats.get("tasks", 0),
                "success": stats.get("success", 0),
                "success_rate": stats.get("success_rate", 0),
                "avg_latency_ms": stats.get("avg_latency_ms", 0),
            }
        )
    _print_stat_table("Domain Stats", domain_rows, "domain")

    objective_rows = []
    for objective, stats in metrics.get("objective_stats", {}).items():
        objective_rows.append(
            {
                "objective": objective,
                "tasks": stats.get("tasks", 0),
                "success": stats.get("success", 0),
                "success_rate": stats.get("success_rate", 0),
                "avg_latency_ms": stats.get("avg_latency_ms", 0),
            }
        )
    _print_stat_table("Objective Stats", objective_rows, "objective")


def _print_compare(with_defense: Dict, without_defense: Dict) -> None:
    print(_sep("="))
    print(_green("Final Comparison"))
    print(_sep("="))
    print(f"{'metric':<24}{'with_defense':<18}{'without_defense':<18}{'delta':<18}")
    print(_sep("-"))

    with_attack = float(with_defense.get("attack_success_rate", 0))
    without_attack = float(without_defense.get("attack_success_rate", 0))
    with_latency = int(with_defense.get("avg_latency_ms", 0))
    without_latency = int(without_defense.get("avg_latency_ms", 0))
    with_spread = int(with_defense.get("lateral_spread_count", 0))
    without_spread = int(without_defense.get("lateral_spread_count", 0))
    with_fpr = float(with_defense.get("false_positive_rate", 0))
    without_fpr = float(without_defense.get("false_positive_rate", 0))
    with_fnr = float(with_defense.get("false_negative_rate", 0))
    without_fnr = float(without_defense.get("false_negative_rate", 0))
    with_closure_rate = float(with_defense.get("incident_closure_rate", 0))
    without_closure_rate = float(without_defense.get("incident_closure_rate", 0))

    attack_delta = without_attack - with_attack
    attack_delta_text = _green(_rate_to_pct(attack_delta)) if attack_delta >= 0 else _red(_rate_to_pct(attack_delta))
    print(
        f"{'attack_success_rate':<24}{_color_rate(with_attack, lower_is_better=True):<18}{_color_rate(without_attack, lower_is_better=True):<18}{attack_delta_text:<18}"
    )
    fpr_delta = without_fpr - with_fpr
    fpr_delta_text = _green(_rate_to_pct(fpr_delta)) if fpr_delta >= 0 else _red(_rate_to_pct(fpr_delta))
    print(
        f"{'false_positive_rate':<24}{_color_rate(with_fpr, lower_is_better=True):<18}{_color_rate(without_fpr, lower_is_better=True):<18}{fpr_delta_text:<18}"
    )
    fnr_delta = without_fnr - with_fnr
    fnr_delta_text = _green(_rate_to_pct(fnr_delta)) if fnr_delta >= 0 else _red(_rate_to_pct(fnr_delta))
    print(
        f"{'false_negative_rate':<24}{_color_rate(with_fnr, lower_is_better=True):<18}{_color_rate(without_fnr, lower_is_better=True):<18}{fnr_delta_text:<18}"
    )
    closure_delta = with_closure_rate - without_closure_rate
    closure_delta_text = _green(_rate_to_pct(closure_delta)) if closure_delta >= 0 else _red(_rate_to_pct(closure_delta))
    print(
        f"{'incident_closure_rate':<24}{_color_rate(with_closure_rate, lower_is_better=False):<18}{_color_rate(without_closure_rate, lower_is_better=False):<18}{closure_delta_text:<18}"
    )
    print(f"{'avg_latency_ms':<24}{with_latency:<18}{without_latency:<18}{(with_latency - without_latency):<18}")
    print(f"{'lateral_spread_count':<24}{with_spread:<18}{without_spread:<18}{(without_spread - with_spread):<18}")
    print(_sep("="))


async def feed_local_logs(client: AsyncAPIClient, endpoint: str, logs: List[Dict]) -> Dict:
    """向指定执行器批量发送本地日志。"""
    sent = 0
    failed = 0
    reported_alerts = 0
    suspicious_reported_alerts = 0
    benign_reported_alerts = 0
    suspicious_sent = 0
    benign_sent = 0
    for log in logs:
        try:
            response = await client.post_json(f"{endpoint}/local-logs", log)
            sent += 1
            if bool(log.get("suspicious", False)):
                suspicious_sent += 1
            else:
                benign_sent += 1
            if isinstance(response, dict):
                new_alerts = int(response.get("reported_alerts", 0))
                reported_alerts += new_alerts
                if bool(log.get("suspicious", False)):
                    suspicious_reported_alerts += new_alerts
                else:
                    benign_reported_alerts += new_alerts
        except Exception as exc:
            failed += 1
            print(f"[ERROR] feed_local_logs failed: {exc}")
    return {
        "sent": sent,
        "failed": failed,
        "reported_alerts": reported_alerts,
        "suspicious_reported_alerts": suspicious_reported_alerts,
        "benign_reported_alerts": benign_reported_alerts,
        "suspicious_sent": suspicious_sent,
        "benign_sent": benign_sent,
    }


async def trigger_real_behaviors(
    client: AsyncAPIClient,
    endpoint: str,
    domain: str,
    count: int = 10,
    profile: str = "mixed",
    run_id: str = "run",
) -> Dict:
    """调用执行器接口，在容器内真实执行行为尝试。"""
    attempts = 0
    failed = 0
    suspicious = 0
    reported_alerts = 0
    for idx in range(count):
        payload = {
            "profile": profile,
            "event_id": f"{domain}-{run_id}-real-{idx}",
            "src_ip": "10.10.1.23",
            "dst_ip": "10.20.5.8" if domain == "office" else "10.20.9.3",
            "device_type": "ids" if domain == "office" else "firewall",
        }
        try:
            resp = await client.post_json(f"{endpoint}/behavior/attempt", payload)
            attempts += 1
            event = resp.get("event", {}) if isinstance(resp, dict) else {}
            if bool(event.get("suspicious", False)):
                suspicious += 1
            if isinstance(resp, dict):
                reported_alerts += int(resp.get("reported_alerts", 0))
        except Exception as exc:
            failed += 1
            print(f"[ERROR] trigger_real_behaviors failed: {exc}")
    return {
        "attempts": attempts,
        "failed": failed,
        "suspicious": suspicious,
        "reported_alerts": reported_alerts,
    }


def _compute_detection_metrics(malicious_events: int, benign_events: int, tp_like_alerts: int, fp_like_alerts: int) -> Dict:
    """根据实验注入与告警上报估算FPR/FNR。"""
    true_positive = max(0, min(tp_like_alerts, malicious_events))
    false_negative = max(0, malicious_events - true_positive)
    false_positive = max(0, min(fp_like_alerts, benign_events))
    true_negative = max(0, benign_events - false_positive)

    fnr = round(false_negative / (true_positive + false_negative), 3) if (true_positive + false_negative) else 0.0
    fpr = round(false_positive / (false_positive + true_negative), 3) if (false_positive + true_negative) else 0.0

    return {
        "malicious_events": malicious_events,
        "benign_events": benign_events,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "true_negative": true_negative,
        "false_negative": false_negative,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
    }


async def wait_services_ready(client: AsyncAPIClient, retries: int = 20, interval_sec: float = 0.5) -> bool:
    """轮询健康检查接口，等待核心服务就绪。"""
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


async def wait_alerts_ready(
    client: AsyncAPIClient,
    expected_min: int = 2,
    retries: int = 30,
    interval_sec: float = 0.3,
    stage_label: str = "wait_alerts",
    log_every: int = 5,
) -> Dict:
    """等待 manager 侧告警缓冲达到最小阈值，并返回等待过程信息。"""
    last_size = 0
    prev_size = -1
    for idx in range(retries):
        attempt = idx + 1
        try:
            health = await client.get_json(f"{MANAGER}/health")
            last_size = int(health.get("alert_buffer_size", 0))
            should_log = (
                attempt == 1
                or attempt == retries
                or last_size != prev_size
                or (log_every > 0 and attempt % log_every == 0)
            )
            if should_log:
                _print_step(
                    stage_label,
                    "alerts {} {}/{} (retry {}/{})".format(
                        _progress_bar(min(last_size, expected_min), expected_min),
                        last_size,
                        expected_min,
                        attempt,
                        retries,
                    ),
                )
            prev_size = last_size
            if last_size >= expected_min:
                return {"ready": True, "last_size": last_size, "attempts": attempt}
        except Exception:
            if attempt == 1 or attempt == retries or (log_every > 0 and attempt % log_every == 0):
                _print_step(stage_label, f"alerts {_progress_bar(0, expected_min)} n/a/{expected_min} (retry {attempt}/{retries})")
        await asyncio.sleep(interval_sec)
    return {"ready": False, "last_size": last_size, "attempts": retries}


async def get_alert_buffer_size(client: AsyncAPIClient) -> int:
    """读取 manager 当前告警缓冲大小，失败返回 -1。"""
    try:
        health = await client.get_json(f"{MANAGER}/health")
        return int(health.get("alert_buffer_size", 0))
    except Exception:
        return -1


def parse_dispatch_results(raw_items: List) -> List[Dict]:
    """解析 dispatch 返回值，兼容 dict 与字符串字典两种格式。"""
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
    """将按执行器分组的结果摊平为逐任务结果。"""
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
    """汇总任务成功率、时延及按域/目标统计信息。"""
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
            by_objective[objective] = {"tasks": 0, "success": 0, "_latencies": []}
        by_objective[objective]["tasks"] += 1
        by_objective[objective]["success"] += 1 if ok else 0
        by_objective[objective]["_latencies"].append(latency)

    for stats in by_domain.values():
        local_latencies = stats.pop("_latencies", [])
        stats["avg_latency_ms"] = int(mean(local_latencies)) if local_latencies else 0
        stats["success_rate"] = round(stats["success"] / stats["tasks"], 3) if stats["tasks"] else 0

    for stats in by_objective.values():
        local_latencies = stats.pop("_latencies", [])
        stats["avg_latency_ms"] = int(mean(local_latencies)) if local_latencies else 0
        stats["success_rate"] = round(stats["success"] / stats["tasks"], 3) if stats["tasks"] else 0

    return {
        "tasks": total,
        "success": success_count,
        "task_success_rate": round(success_count / total, 3) if total else 0,
        "avg_latency_ms": int(mean(latencies)) if latencies else 0,
        "domain_stats": by_domain,
        "objective_stats": by_objective,
    }


def persist_experiment(result: Dict, metadata: Dict) -> tuple[Path, Path]:
    """将实验结果持久化为 JSON 与 HTML 报告。"""
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


async def run_once(defense_enabled: bool) -> Dict:
    """执行单轮实验，可选择启用或关闭防御动作。"""
    client = AsyncAPIClient(timeout=20.0)

    mode_label = "with_defense" if defense_enabled else "without_defense"
    scenario = _scenario_config()
    traffic_rng = random.Random(_seed_for_run(mode_label, "traffic"))
    generator = TrafficGenerator(
        rng=traffic_rng,
        attack_mix_threshold=ATTACK_MIX_THRESHOLD,
        scripted_attack_threshold=SCRIPTED_ATTACK_THRESHOLD,
    )
    _print_step(mode_label, "等待服务健康检查")
    malicious_events = 0
    benign_events = 0
    alerts_from_malicious = 0
    alerts_from_benign = 0

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

    if ATTACK_MODE == "real":
        _print_step(mode_label, "在 executor 容器执行真实行为尝试")
        run_id = f"{mode_label}-{int(time.time() * 1000)}"
        try:
            office_real, core_real = await asyncio.gather(
                trigger_real_behaviors(
                    client,
                    OFFICE_EXECUTOR,
                    "office",
                    count=int(scenario.get("real_count", 12)),
                    profile=str(scenario.get("office_profile", ATTACK_PROFILE)),
                    run_id=run_id,
                ),
                trigger_real_behaviors(
                    client,
                    CORE_EXECUTOR,
                    "core",
                    count=int(scenario.get("real_count", 12)),
                    profile=str(scenario.get("core_profile", ATTACK_PROFILE)),
                    run_id=run_id,
                ),
            )
            _print_step(
                mode_label,
                "real_attempts office={}/{} core={}/{}".format(
                    office_real.get("attempts", 0),
                    office_real.get("failed", 0),
                    core_real.get("attempts", 0),
                    core_real.get("failed", 0),
                ),
            )
            malicious_events += int(office_real.get("attempts", 0)) + int(core_real.get("attempts", 0))
            alerts_from_malicious += int(office_real.get("reported_alerts", 0)) + int(core_real.get("reported_alerts", 0))
        except Exception as exc:
            print(f"[ERROR] gather trigger_real_behaviors failed: {exc}")

        # 同时补充一部分正常流量，模拟真实背景噪声。
        _print_step(mode_label, "注入背景正常流量")
        office_benign_logs = generator.generate_local_logs("office", attack=False, count=10)
        core_benign_logs = generator.generate_local_logs("core", attack=False, count=10)
        office_feed, core_feed = await asyncio.gather(
            feed_local_logs(client, OFFICE_EXECUTOR, office_benign_logs),
            feed_local_logs(client, CORE_EXECUTOR, core_benign_logs),
        )
        _print_step(
            mode_label,
            "benign_logs office={}/{} core={}/{}".format(
                office_feed.get("sent", 0),
                office_feed.get("failed", 0),
                core_feed.get("sent", 0),
                core_feed.get("failed", 0),
            ),
        )
        benign_events += int(office_feed.get("benign_sent", 0)) + int(core_feed.get("benign_sent", 0))
        alerts_from_benign += int(office_feed.get("benign_reported_alerts", 0)) + int(core_feed.get("benign_reported_alerts", 0))
    else:
        _print_step(mode_label, "使用数据驱动模式注入攻击日志")
        data_count = int(scenario.get("data_count", 25))
        office_logs = generator.generate_local_logs(
            "office",
            attack=True,
            count=data_count,
            attack_profile=str(scenario.get("office_profile", ATTACK_PROFILE)),
        )
        core_logs = generator.generate_local_logs(
            "core",
            attack=True,
            count=data_count,
            attack_profile=str(scenario.get("core_profile", ATTACK_PROFILE)),
        )

        try:
            office_feed, core_feed = await asyncio.gather(
                feed_local_logs(client, OFFICE_EXECUTOR, office_logs),
                feed_local_logs(client, CORE_EXECUTOR, core_logs),
            )
            _print_step(
                mode_label,
                "attack_logs office={}/{} core={}/{}".format(
                    office_feed.get("sent", 0),
                    office_feed.get("failed", 0),
                    core_feed.get("sent", 0),
                    core_feed.get("failed", 0),
                ),
            )
            malicious_events += int(office_feed.get("suspicious_sent", 0)) + int(core_feed.get("suspicious_sent", 0))
            benign_events += int(office_feed.get("benign_sent", 0)) + int(core_feed.get("benign_sent", 0))
            alerts_from_malicious += int(office_feed.get("suspicious_reported_alerts", 0)) + int(core_feed.get("suspicious_reported_alerts", 0))
            alerts_from_benign += int(office_feed.get("benign_reported_alerts", 0)) + int(core_feed.get("benign_reported_alerts", 0))
        except Exception as exc:
            print(f"[ERROR] gather feed_local_logs failed: {exc}")

    current_buffer = await get_alert_buffer_size(client)
    _print_step(mode_label, f"当前 manager 告警缓冲={current_buffer}")

    _print_step(mode_label, "等待 manager 告警缓冲达到阈值")
    alerts_state = await wait_alerts_ready(client, expected_min=2, stage_label=mode_label)
    t0 = time.perf_counter()

    if not bool(alerts_state.get("ready", False)):
        _print_step(
            mode_label,
            "告警等待超时: last_buffer={} expected_min={} retries={}".format(
                alerts_state.get("last_size", 0),
                2,
                alerts_state.get("attempts", 0),
            ),
        )
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

    _print_step(
        mode_label,
        "告警就绪: buffer_size={} attempts={}".format(
            alerts_state.get("last_size", 0), alerts_state.get("attempts", 0)
        ),
    )

    _print_step(mode_label, "触发 manager 决策与任务下发")
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
    detection_metrics = _compute_detection_metrics(
        malicious_events=malicious_events,
        benign_events=benign_events,
        tp_like_alerts=alerts_from_malicious,
        fp_like_alerts=alerts_from_benign,
    )
    metrics.update(detection_metrics)
    metrics["block_rate"] = round(1 - metrics.get("attack_success_rate", 1), 3)
    metrics["decision_elapsed_ms"] = elapsed
    metrics["flat_results"] = flat_results
    metrics["decision"] = decision.get("decision", {})
    metrics["manager_alert_sources"] = decision.get("alert_sources", [])
    metrics["incident_id"] = decision.get("incident_id", "")
    ooda = decision.get("ooda", {}) if isinstance(decision, dict) else {}
    metrics["incident_closure_rate"] = float(ooda.get("incident_closure_rate", 0.0))
    metrics["mean_closure_time_ms"] = int(ooda.get("mean_closure_time_ms", 0))
    metrics["incidents_total"] = int(ooda.get("incidents_total", 0))
    metrics["incidents_closed"] = int(ooda.get("incidents_closed", 0))
    metrics["scenario_id"] = SCENARIO_ID
    metrics["scenario_description"] = scenario.get("description", "")

    _print_step(
        mode_label,
        "完成: tasks={} attack_success_rate={} avg_latency_ms={}".format(
            metrics.get("tasks", 0),
            _rate_to_pct(float(metrics.get("attack_success_rate", 0))),
            metrics.get("avg_latency_ms", 0),
        ),
    )
    return metrics


async def main() -> None:
    """分别运行有防御/无防御实验并输出对比结果。"""
    random.seed(EXPERIMENT_SEED)
    _print_banner()
    _print_step("experiment", "开始执行 with_defense 场景")
    with_defense = await run_once(defense_enabled=True)
    _print_run_summary("WITH_DEFENSE SUMMARY", with_defense)

    _print_step("experiment", "开始执行 without_defense 场景")
    without_defense = await run_once(defense_enabled=False)
    _print_run_summary("WITHOUT_DEFENSE SUMMARY", without_defense)

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

    metadata = {
        "seed": EXPERIMENT_SEED,
        "scenario_id": SCENARIO_ID,
        "attack_mix_threshold": ATTACK_MIX_THRESHOLD,
        "scripted_attack_threshold": SCRIPTED_ATTACK_THRESHOLD,
        "attack_mode": ATTACK_MODE,
        "attack_profile": ATTACK_PROFILE,
        "manager_service": MANAGER,
        "office_executor_service": OFFICE_EXECUTOR,
        "core_executor_service": CORE_EXECUTOR,
    }
    json_path, html_path = persist_experiment(report, metadata)
    _print_compare(with_defense, without_defense)
    _print_step("artifact", f"json={json_path}")
    _print_step("artifact", f"html={html_path}")


if __name__ == "__main__":
    asyncio.run(main())