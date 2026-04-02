from __future__ import annotations

import os
import asyncio
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from uuid import uuid4

from fastapi import FastAPI
from pydantic import BaseModel

from manager.model_loader import ModelLoader
from communication.async_client import AsyncAPIClient
from communication.message_protocol import BaseMessage, MessageType, TaskItem, TaskPayload
from utils.config_loader import load_yaml

app = FastAPI(title="Manager Agent API", version="1.0.0")

# 进程内全局状态：仅在当前 manager 实例生命周期内有效。
_models = ModelLoader().load_all()
_rule_engine = _models["rule_engine"]
_decision_tree = _models["decision_tree"]
_api_client = AsyncAPIClient(timeout=20.0)
_received_alerts: List[Dict[str, Any]] = []
_incidents: Dict[str, Dict[str, Any]] = {}
_executor_situations: Dict[str, Dict[str, Any]] = {}

_executor_endpoints = {
    "office": os.getenv("EXECUTOR_OFFICE_SERVICE", "http://127.0.0.1:8101"),
    "core": os.getenv("EXECUTOR_CORE_SERVICE", "http://127.0.0.1:8102"),
    "portal": os.getenv("EXECUTOR_PORTAL_SERVICE", "http://127.0.0.1:8103"),
}

DEFAULT_ACTION_POLICY: Dict[str, Any] = {
    "actions": {
        "isolate_host": {"security_gain": 10, "business_cost": 9},
        "tighten_acl": {"security_gain": 9, "business_cost": 7},
        "block_ip": {"security_gain": 8, "business_cost": 6},
        "block_traffic": {"security_gain": 8, "business_cost": 7},
        "degrade_traffic": {"security_gain": 5, "business_cost": 4},
        "raise_monitoring": {"security_gain": 4, "business_cost": 2},
        "observe_alert": {"security_gain": 2, "business_cost": 1},
    },
    "risk_min_gain": {
        "critical": 8,
        "high": 6,
        "medium": 4,
        "low": 2,
    },
    "fallback_by_risk": {
        "critical": ["block_ip", "block_traffic", "raise_monitoring", "observe_alert"],
        "high": ["block_ip", "raise_monitoring", "observe_alert"],
        "medium": ["raise_monitoring", "observe_alert"],
        "low": ["observe_alert"],
    },
    "reason_disallow_actions": {
        "RESOURCE_BLOCK_LIMIT": ["block_ip", "block_traffic", "tighten_acl", "isolate_host"],
        "FAILURE_STREAK_DEGRADE": ["block_ip", "block_traffic", "tighten_acl", "isolate_host"],
        "CRITICAL_ASSET_PROTECTED": ["tighten_acl", "isolate_host"],
    },
}


def _deep_merge(base: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
    """递归合并策略配置，确保本地配置可按层覆盖默认值。"""
    merged = dict(base)
    for key, value in incoming.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_action_policy() -> Dict[str, Any]:
    """从 YAML 读取动作策略，并与内置默认策略做兜底合并。"""
    policy_path = os.getenv(
        "ACTION_POLICY_FILE",
        str(Path(__file__).resolve().parent / "configs" / "action_policy.yaml"),
    )
    loaded = load_yaml(policy_path)
    if not isinstance(loaded, dict):
        loaded = {}
    return _deep_merge(DEFAULT_ACTION_POLICY, loaded)


_action_policy = _load_action_policy()


def _risk_min_gain(risk_level: str) -> int:
    risk_key = str(risk_level or "low").lower()
    table = _action_policy.get("risk_min_gain", {}) if isinstance(_action_policy, dict) else {}
    return int(table.get(risk_key, table.get("low", 2)))


def _domain_min_gain_offset(domain: str) -> int:
    table = _action_policy.get("domain_min_gain_offset", {}) if isinstance(_action_policy, dict) else {}
    domain_key = str(domain or "").lower()
    return int(table.get(domain_key, 0))


def _min_confidence_for_downgrade() -> float:
    policy = _action_policy.get("confidence_policy", {}) if isinstance(_action_policy, dict) else {}
    return float(policy.get("min_confidence_for_downgrade", 0.6))


def _low_confidence_extra_gain() -> int:
    policy = _action_policy.get("confidence_policy", {}) if isinstance(_action_policy, dict) else {}
    return int(policy.get("low_confidence_extra_gain", 1))


def _action_gain(action: str) -> int:
    actions = _action_policy.get("actions", {}) if isinstance(_action_policy, dict) else {}
    item = actions.get(str(action), {}) if isinstance(actions, dict) else {}
    return int(item.get("security_gain", 0))


def _pick_fallback_action(risk_level: str, reason_code: str) -> str:
    """当反提案不可用时，按风险等级与限制条件选择兜底动作。"""
    risk_key = str(risk_level or "low").lower()
    reason = str(reason_code or "")
    fallback_table = _action_policy.get("fallback_by_risk", {}) if isinstance(_action_policy, dict) else {}
    reason_disallow = _action_policy.get("reason_disallow_actions", {}) if isinstance(_action_policy, dict) else {}

    candidates = fallback_table.get(risk_key, fallback_table.get("low", ["observe_alert"]))
    blocked = set(reason_disallow.get(reason, [])) if isinstance(reason_disallow, dict) else set()
    min_gain = _risk_min_gain(risk_key)

    # 第一轮：优先满足最小安全增益基线。
    for action in candidates:
        if action in blocked:
            continue
        if _action_gain(action) >= min_gain:
            return str(action)

    # 第二轮：若受约束无法达标，则选择未被禁用的可执行动作平稳降级。
    for action in candidates:
        if action in blocked:
            continue
        return str(action)

    return "observe_alert"


class DecisionTriggerRequest(BaseModel):
    enforce_actions: bool = True
    clear_alerts: bool = True


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_incident(incident_id: str) -> Dict[str, Any]:
    """确保事件存在；不存在时初始化事件聚合结构。"""
    if incident_id not in _incidents:
        _incidents[incident_id] = {
            "incident_id": incident_id,
            "created_at": _now_iso(),
            "updated_at": _now_iso(),
            "closed_at": "",
            "status": "open",
            "ooda_stage": "observe",
            "alert_count": 0,
            "tasks_total": 0,
            "tasks_success": 0,
            "tasks_failed": 0,
            "executors": [],
            "analysis": {},
            "decision": {},
            "feedback_events": 0,
        }
    return _incidents[incident_id]


def _create_incident_context(alerts: List[Dict[str, Any]], analysis: Dict[str, Any], decision: Dict[str, Any]) -> str:
    incident_id = str(uuid4())
    item = _ensure_incident(incident_id)
    item["alert_count"] = len(alerts)
    item["analysis"] = analysis
    item["decision"] = decision
    item["status"] = "open"
    item["ooda_stage"] = "decide"
    item["updated_at"] = _now_iso()
    return incident_id


def _apply_result_to_incident(result: Dict[str, Any]) -> None:
    """将执行结果回填到事件状态，并推进 OODA 阶段。"""
    incident_id = str(result.get("incident_id", ""))
    if not incident_id:
        return

    item = _ensure_incident(incident_id)
    task_id = str(result.get("task_id", ""))
    if task_id:
        task_states = item.setdefault("task_states", {})
        if task_id in task_states:
            return
        task_states[task_id] = bool(result.get("success", False))

    if bool(result.get("success", False)):
        item["tasks_success"] = int(item.get("tasks_success", 0)) + 1
    else:
        item["tasks_failed"] = int(item.get("tasks_failed", 0)) + 1

    executor = str(result.get("executor_id", result.get("executor", "")))
    if executor and executor not in item["executors"]:
        item["executors"].append(executor)

    total = int(item.get("tasks_total", 0))
    completed = int(item.get("tasks_success", 0)) + int(item.get("tasks_failed", 0))
    if total > 0 and completed >= total:
        if int(item.get("tasks_failed", 0)) == 0:
            item["status"] = "closed"
            item["ooda_stage"] = "feedback"
            item["closed_at"] = _now_iso()
        else:
            item["status"] = "degraded"
            item["ooda_stage"] = "feedback"
    else:
        item["status"] = "acting"
        item["ooda_stage"] = "act"

    item["feedback_events"] = int(item.get("feedback_events", 0)) + 1
    item["updated_at"] = _now_iso()


def _ooda_metrics() -> Dict[str, Any]:
    total = len(_incidents)
    closed = sum(1 for v in _incidents.values() if v.get("status") == "closed")
    closure_rate = round(closed / total, 3) if total else 0.0

    closure_times: List[int] = []
    for v in _incidents.values():
        created_at = v.get("created_at")
        closed_at = v.get("closed_at")
        if not created_at or not closed_at:
            continue
        try:
            t0 = datetime.fromisoformat(str(created_at))
            t1 = datetime.fromisoformat(str(closed_at))
            closure_times.append(int((t1 - t0).total_seconds() * 1000))
        except Exception:
            continue

    mean_closure_time_ms = int(sum(closure_times) / len(closure_times)) if closure_times else 0
    return {
        "incidents_total": total,
        "incidents_closed": closed,
        "incident_closure_rate": closure_rate,
        "mean_closure_time_ms": mean_closure_time_ms,
    }


def _normalize_alert(payload: Dict[str, Any]) -> Dict[str, Any]:
    """兼容原始告警与消息封装两种格式，统一为告警体。"""
    if payload.get("message_type") == MessageType.ALERT.value and isinstance(payload.get("payload"), dict):
        normalized = dict(payload["payload"])
        normalized["alert_source"] = payload.get("source", "unknown")
        return normalized
    return payload


def _pick_objective(playbook: List[str], enforce_actions: bool, has_ip: bool) -> str:
    if not enforce_actions:
        return "observe_alert"
    if "block_ip" in playbook and has_ip:
        return "block_ip"
    if "tighten_acl" in playbook:
        return "tighten_acl"
    if "enable_ids_strict" in playbook:
        return "enable_ids_strict"
    if "raise_monitoring" in playbook:
        return "raise_monitoring"
    return "observe_alert"


def _collect_domain_context(alerts: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """按域聚合告警，并提取任务构建所需的关键上下文。"""
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for alert in alerts:
        grouped[alert.get("domain", "unknown")].append(alert)

    context: Dict[str, Dict[str, Any]] = {}
    for domain, domain_alerts in grouped.items():
        first = domain_alerts[0] if domain_alerts else {}
        details = first.get("details", {}) if isinstance(first.get("details"), dict) else {}
        context[domain] = {
            "src_ip": first.get("src_ip"),
            "dst_ip": first.get("dst_ip"),
            "attack_type": first.get("attack_type", "unknown"),
            "asset_level": first.get("asset_level") or details.get("asset_level", "normal"),
            "asset_id": first.get("asset_id") or details.get("asset_id", ""),
        }
    return context


def _local_constraints_by_domain() -> Dict[str, Dict[str, Any]]:
    """将 executor 上报的本地态势映射为按域约束。"""
    result: Dict[str, Dict[str, Any]] = {}
    for item in _executor_situations.values():
        domain = str(item.get("domain", "unknown"))
        if not domain:
            continue
        result[domain] = {
            "executor_id": item.get("executor_id", "unknown"),
            "resource_status": item.get("resource_status", {}),
            "proposed_action": item.get("proposed_action", "observe_alert"),
            "confidence": item.get("confidence", 0.0),
        }
    return result


def _build_task_payload(
    alerts: List[Dict[str, Any]],
    strategy: Dict[str, Any],
    enforce_actions: bool,
    incident_id: str,
    plan_type: str = "task_plan",
    negotiation_round: int = 1,
    max_negotiation_rounds: int = 1,
    negotiation_timeout_ms: int = 3000,
) -> TaskPayload:
    """根据策略与域上下文生成任务载荷（意图计划或联合计划）。"""
    domain_context = _collect_domain_context(alerts)

    tasks: List[TaskItem] = []
    playbook = strategy.get("playbook", [])
    priority = int(strategy.get("priority", 5))
    strategy_name = strategy.get("strategy", "unknown")
    incident_type = strategy.get("incident_type", "none")
    joint_plan = strategy.get("joint_plan", [])

    if enforce_actions and joint_plan:
        for step in joint_plan:
            domain = step.get("domain", "unknown")
            objective = step.get("objective", "observe_alert")
            context = domain_context.get(domain, {})
            tasks.append(
                TaskItem(
                    incident_id=incident_id,
                    negotiation_round=negotiation_round,
                    objective=objective,
                    target_domain=domain,
                    priority=priority,
                    ooda_stage="act",
                    status="pending",
                    action_hints=["joint_plan", f"strategy:{strategy_name}", f"incident:{incident_type}"],
                    constraints={
                        "incident_id": incident_id,
                        "ip": context.get("src_ip"),
                        "src_ip": context.get("src_ip"),
                        "dst_ip": context.get("dst_ip"),
                        "asset_level": context.get("asset_level", "normal"),
                        "asset_id": context.get("asset_id", ""),
                        "target_domain": domain,
                        "incident_type": incident_type,
                        "attack_pattern": strategy.get("pattern", "unknown"),
                        "enforce_actions": enforce_actions,
                    },
                )
            )
        return TaskPayload(
            reasoning=f"strategy={strategy_name}, incident={incident_type}, mode=joint_plan",
            plan_type=plan_type,
            negotiation_timeout_ms=negotiation_timeout_ms,
            max_negotiation_rounds=max_negotiation_rounds,
            tasks=tasks,
        )

    for domain, context in domain_context.items():
        src_ip = context.get("src_ip")
        objective = _pick_objective(playbook, enforce_actions=enforce_actions, has_ip=bool(src_ip))
        hints = [
            "enforce" if enforce_actions else "observe_only",
            f"strategy:{strategy_name}",
            f"incident:{incident_type}",
        ]

        tasks.append(
            TaskItem(
                incident_id=incident_id,
                negotiation_round=negotiation_round,
                objective=objective,
                target_domain=domain,
                priority=priority,
                ooda_stage="act",
                status="pending",
                action_hints=hints,
                constraints={
                    "incident_id": incident_id,
                    "ip": src_ip,
                    "src_ip": src_ip,
                    "dst_ip": context.get("dst_ip"),
                    "asset_level": context.get("asset_level", "normal"),
                    "asset_id": context.get("asset_id", ""),
                    "target_domain": domain,
                    "enforce_actions": enforce_actions,
                    "incident_type": incident_type,
                    "attack_pattern": strategy.get("pattern", "unknown"),
                },
            )
        )

    return TaskPayload(
        reasoning=f"strategy={strategy_name}, enforce_actions={enforce_actions}",
        plan_type=plan_type,
        negotiation_timeout_ms=negotiation_timeout_ms,
        max_negotiation_rounds=max_negotiation_rounds,
        tasks=tasks,
    )


async def _dispatch_tasks(task_payload: TaskPayload, message_type: MessageType = MessageType.TASK) -> List[Dict[str, Any]]:
    """按域拆分任务并下发到 executor，内置轻量重试。"""
    dispatch_results: List[Dict[str, Any]] = []
    grouped: Dict[str, List[TaskItem]] = defaultdict(list)
    for task in task_payload.tasks:
        grouped[task.target_domain].append(task)

    for domain, tasks in grouped.items():
        endpoint = _executor_endpoints.get(domain)
        if not endpoint:
            dispatch_results.append(
                {
                    "executor": f"executor-{domain}",
                    "results": [
                        {
                            "task_id": t.task_id,
                            "success": False,
                            "latency_ms": 0,
                            "error": f"missing endpoint for domain={domain}",
                        }
                        for t in tasks
                    ],
                }
            )
            continue

        msg = BaseMessage(
            message_type=message_type,
            source="manager",
            target=f"executor-{domain}",
            payload=TaskPayload(
                strategy_id=task_payload.strategy_id,
                reasoning=task_payload.reasoning,
                plan_type=task_payload.plan_type,
                negotiation_timeout_ms=task_payload.negotiation_timeout_ms,
                max_negotiation_rounds=task_payload.max_negotiation_rounds,
                tasks=tasks,
            ).model_dump(),
        )

        last_exc: Exception | None = None
        response: Dict[str, Any] | None = None
        for _ in range(3):
            try:
                response = await _api_client.post_json(f"{endpoint}/tasks", msg.model_dump())
                break
            except Exception as exc:
                last_exc = exc
                await asyncio.sleep(0.3)

        if response is not None:
            dispatch_results.append(response)
            continue

        if last_exc is None:
            last_exc = RuntimeError("unknown dispatch error")

        dispatch_results.append(
            {
                "executor": f"executor-{domain}",
                "results": [
                    {
                        "task_id": t.task_id,
                        "success": False,
                        "latency_ms": 0,
                        "error": str(last_exc),
                    }
                    for t in tasks
                ],
            }
        )

    return dispatch_results


def _collect_negotiation_feedback(dispatch_results: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """把 executor 返回整理为按 task_id 索引的协商反馈。"""
    feedback: Dict[str, Dict[str, Any]] = {}
    for dispatch in dispatch_results:
        for result in dispatch.get("results", []):
            task_id = str(result.get("task_id", ""))
            if not task_id:
                continue
            details = result.get("details", {}) if isinstance(result.get("details"), dict) else {}
            local_situation = details.get("local_situation", {}) if isinstance(details.get("local_situation"), dict) else {}
            confidence = float(local_situation.get("confidence", details.get("confidence", 0.0)) or 0.0)
            feedback[task_id] = {
                "status": str(result.get("status", "unknown")),
                "reason_code": str(details.get("reason_code", "")),
                "counter_proposal": str(details.get("counter_proposal") or details.get("proposed_action") or ""),
                "cost_estimate": str(details.get("cost_estimate", "")),
                "confidence": confidence,
                "local_evidence": details.get("local_evidence", {}),
                "proposal_id": str(details.get("proposal_id") or result.get("proposal_id") or ""),
            }
    return feedback


def _refine_consensus_payload(
    intent_payload: TaskPayload,
    feedback: Dict[str, Dict[str, Any]],
    analysis: Dict[str, Any],
) -> TaskPayload:
    """一轮协商终裁：采纳有效反提案，否则回退到策略兜底动作。"""
    refined_tasks: List[TaskItem] = []
    global_risk_level = str(analysis.get("risk_level", "low"))
    confidence_global = str(analysis.get("confidence_global", analysis.get("confidence", "low"))).lower()
    dominant_attack = str(analysis.get("attack_pattern", "")).lower()
    incident_graph = analysis.get("incident_graph", {}) if isinstance(analysis.get("incident_graph"), dict) else {}
    edge_count = int(incident_graph.get("summary", {}).get("edge_count", 0)) if isinstance(incident_graph, dict) else 0
    weak_cross_domain_evidence = (
        bool(analysis.get("is_cross_domain_attack", False))
        and edge_count == 0
        and confidence_global in {"low", "medium"}
        and dominant_attack == "port_scan"
    )
    involved_domains = {str(d) for d in analysis.get("involved_domains", []) if str(d)}
    allow_portal_fallback = "portal" in involved_domains and "office" in involved_domains
    has_portal_blocking_intent = any(
        str(t.target_domain) == "portal" and str(t.objective) in {"block_ip", "block_traffic", "tighten_acl"}
        for t in intent_payload.tasks
    )
    blocking_objectives = {"block_ip", "block_traffic", "tighten_acl", "isolate_host", "enable_ids_strict"}

    base_min_gain = _risk_min_gain(global_risk_level)
    min_confidence = _min_confidence_for_downgrade()
    low_confidence_gain_bonus = _low_confidence_extra_gain()
    for task in intent_payload.tasks:
        fb = feedback.get(task.task_id, {})
        status = str(fb.get("status", "accept"))
        suggested = str(fb.get("counter_proposal", ""))
        reason_code = str(fb.get("reason_code", ""))
        confidence = float(fb.get("confidence", 0.0))
        domain = str(task.target_domain)

        domain_adjusted_min_gain = base_min_gain + _domain_min_gain_offset(domain)
        intent_gain = _action_gain(str(task.objective))
        suggested_gain = _action_gain(suggested) if suggested else 0
        is_downgrade = bool(suggested) and suggested_gain < intent_gain

        effective_min_gain = domain_adjusted_min_gain
        if is_downgrade and confidence < min_confidence:
            # executor 低置信度且要求降级时，提高门槛避免过度降防。
            effective_min_gain += low_confidence_gain_bonus

        final_objective = task.objective
        final_reason = "accepted_intent"
        add_portal_fallback = False
        # 一轮协商后强制终裁：要么采纳反提案，要么执行兜底策略。
        if weak_cross_domain_evidence and str(task.objective) in blocking_objectives:
            final_objective = "observe_alert"
            final_reason = "reject_block_low_confidence"
        elif status in {"counter_proposal", "reject"}:
            if domain == "office" and reason_code == "CRITICAL_ASSET_PROTECTED" and suggested:
                final_objective = suggested
                final_reason = "adopt_counter_proposal"
                add_portal_fallback = allow_portal_fallback and final_objective == "observe_alert"
            elif suggested and suggested_gain >= effective_min_gain:
                final_objective = suggested
                final_reason = "adopt_counter_proposal"
            else:
                final_objective = _pick_fallback_action(global_risk_level, reason_code=reason_code)
                final_reason = "fallback_min_gain_policy"
                add_portal_fallback = (
                    allow_portal_fallback
                    and not has_portal_blocking_intent
                    and domain == "office"
                    and reason_code == "CRITICAL_ASSET_PROTECTED"
                    and final_objective == "observe_alert"
                )

        constraints = dict(task.constraints)
        constraints["consensus_reason"] = final_reason
        constraints["counter_reason_code"] = reason_code
        constraints["cost_estimate"] = fb.get("cost_estimate", "")
        constraints["local_evidence"] = fb.get("local_evidence", {})
        constraints["executor_confidence"] = round(confidence, 3)
        constraints["global_risk_level"] = str(global_risk_level)
        constraints["base_min_gain"] = int(base_min_gain)
        constraints["domain_min_gain_offset"] = int(_domain_min_gain_offset(domain))
        constraints["effective_min_gain"] = int(effective_min_gain)
        constraints["counter_gain"] = int(suggested_gain)
        constraints["counter_valid"] = bool(suggested and suggested_gain >= effective_min_gain)
        constraints["counter_is_downgrade"] = bool(is_downgrade)
        constraints["low_confidence_penalty_applied"] = bool(is_downgrade and confidence < min_confidence)
        constraints["fallback_action"] = final_objective if final_reason == "fallback_min_gain_policy" else ""
        constraints["low_confidence_block_reject"] = bool(final_reason == "reject_block_low_confidence")
        constraints["global_confidence"] = confidence_global
        constraints["cross_domain_edge_count"] = edge_count

        refined_tasks.append(
            TaskItem(
                task_id=task.task_id,
                proposal_id=task.proposal_id,
                incident_id=task.incident_id,
                negotiation_round=2,
                objective=final_objective,
                target_domain=task.target_domain,
                priority=task.priority,
                ooda_stage=task.ooda_stage,
                status="pending",
                action_hints=list(task.action_hints) + ["consensus_final"],
                constraints=constraints,
            )
        )

        if add_portal_fallback:
            portal_objective = "tighten_acl"
            if _action_gain(portal_objective) < base_min_gain:
                portal_objective = "block_ip"

            portal_constraints = dict(task.constraints)
            portal_constraints["consensus_reason"] = "fallback_source_containment"
            portal_constraints["source_fallback_from_domain"] = "office"
            portal_constraints["source_fallback_trigger"] = "office_critical_asset_blocked"
            portal_constraints["fallback_generated"] = True

            refined_tasks.append(
                TaskItem(
                    incident_id=task.incident_id,
                    negotiation_round=2,
                    objective=portal_objective,
                    target_domain="portal",
                    priority=task.priority,
                    ooda_stage=task.ooda_stage,
                    status="pending",
                    action_hints=list(task.action_hints) + ["source_fallback", "target:portal"],
                    constraints=portal_constraints,
                )
            )

    return TaskPayload(
        strategy_id=intent_payload.strategy_id,
        reasoning=f"{intent_payload.reasoning}, one_shot_negotiation=finalized",
        plan_type="consensus_plan",
        negotiation_timeout_ms=intent_payload.negotiation_timeout_ms,
        max_negotiation_rounds=1,
        tasks=refined_tasks,
    )


@app.get("/health")
async def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "role": "manager",
        "alert_buffer_size": len(_received_alerts),
        "executor_situation_count": len(_executor_situations),
        "ooda": _ooda_metrics(),
    }


@app.post("/alerts")
async def alerts(message: Dict[str, Any]) -> Dict[str, Any]:
    normalized = _normalize_alert(message)
    _received_alerts.append(normalized)
    return {"status": "success", "accepted": True, "buffered": len(_received_alerts)}


@app.post("/decision/trigger")
async def decision_trigger(request: DecisionTriggerRequest) -> Dict[str, Any]:
    # 主流程：观察告警 -> 规则分析 -> 决策选策 -> 意图下发 -> 协商收敛 -> 结果回填。
    alerts_snapshot = list(_received_alerts)
    alert_sources = sorted({a.get("alert_source", "unknown") for a in alerts_snapshot})
    analysis = _rule_engine.evaluate(alerts_snapshot)
    local_constraints = _local_constraints_by_domain()
    decision = _decision_tree.choose_strategy(analysis, local_constraints=local_constraints)
    incident_id = _create_incident_context(alerts_snapshot, analysis, decision)
    intent_payload = _build_task_payload(
        alerts_snapshot,
        decision,
        enforce_actions=request.enforce_actions,
        incident_id=incident_id,
        plan_type="intent_plan",
        negotiation_round=1,
        max_negotiation_rounds=1,
        negotiation_timeout_ms=3000,
    )

    incident = _ensure_incident(incident_id)
    incident["tasks_total"] = len(intent_payload.tasks)
    incident["status"] = "open" if not request.enforce_actions else "acting"
    incident["ooda_stage"] = "decide" if not request.enforce_actions else "act"
    incident["updated_at"] = _now_iso()

    intent_dispatch = await _dispatch_tasks(intent_payload, message_type=MessageType.PROPOSAL)
    feedback = _collect_negotiation_feedback(intent_dispatch)
    consensus_payload = _refine_consensus_payload(
        intent_payload,
        feedback,
        analysis=analysis,
    )
    consensus_dispatch = await _dispatch_tasks(consensus_payload, message_type=MessageType.CONSENSUS)

    for dispatch in consensus_dispatch:
        for result in dispatch.get("results", []):
            normalized_result = dict(result)
            normalized_result["incident_id"] = normalized_result.get("incident_id") or incident_id
            _apply_result_to_incident(normalized_result)

    if request.clear_alerts:
        _received_alerts.clear()

    return {
        "incident_id": incident_id,
        "alerts_snapshot": alerts_snapshot,
        "alert_sources": alert_sources,
        "analysis": analysis,
        "decision": decision,
        "local_constraints": local_constraints,
        "task_payload": consensus_payload.model_dump(),
        "negotiation": {
            "mode": "one_shot",
            "intent_plan": intent_payload.model_dump(),
            "intent_feedback": feedback,
            "consensus_plan": consensus_payload.model_dump(),
            "timeout_ms": intent_payload.negotiation_timeout_ms,
            "max_rounds": intent_payload.max_negotiation_rounds,
            "intent_dispatch": intent_dispatch,
            "consensus_dispatch": consensus_dispatch,
        },
        "dispatch": {"dispatch_results": consensus_dispatch},
        "incident": _incidents.get(incident_id, {}),
        "ooda": _ooda_metrics(),
    }


@app.post("/incidents/feedback")
async def incidents_feedback(message: Dict[str, Any]) -> Dict[str, Any]:
    payload = message
    if payload.get("message_type") == MessageType.RESULT.value and isinstance(payload.get("payload"), dict):
        payload = payload.get("payload", {})

    incident_id = str(payload.get("incident_id", ""))
    if not incident_id:
        return {"accepted": False, "reason": "incident_id is required"}

    _ensure_incident(incident_id)
    for result in payload.get("results", []):
        normalized_result = dict(result)
        normalized_result["incident_id"] = incident_id
        normalized_result["executor_id"] = normalized_result.get("executor_id") or payload.get("executor_id", "unknown")
        _apply_result_to_incident(normalized_result)

    return {
        "accepted": True,
        "incident_id": incident_id,
        "incident": _incidents.get(incident_id, {}),
        "ooda": _ooda_metrics(),
    }


@app.post("/executors/local-situation")
async def executor_local_situation(message: Dict[str, Any]) -> Dict[str, Any]:
    payload = message
    if payload.get("message_type") == MessageType.LOCAL_SITUATION.value and isinstance(payload.get("payload"), dict):
        payload = payload.get("payload", {})

    executor_id = str(payload.get("executor_id", ""))
    domain = str(payload.get("domain", "unknown"))
    if not executor_id:
        return {"accepted": False, "reason": "executor_id is required"}

    item = dict(payload)
    item["updated_at"] = _now_iso()
    _executor_situations[executor_id] = item
    return {
        "accepted": True,
        "executor_id": executor_id,
        "domain": domain,
        "stored": len(_executor_situations),
    }


@app.get("/executors/local-situation")
async def list_executor_local_situation() -> Dict[str, Any]:
    return {"count": len(_executor_situations), "items": list(_executor_situations.values())}


@app.post("/debug/reset-state")
async def debug_reset_state() -> Dict[str, Any]:
    """重置内存态，便于做可重复的 playbook 实验。"""
    _received_alerts.clear()
    _incidents.clear()
    _executor_situations.clear()
    return {"accepted": True, "reset": True}