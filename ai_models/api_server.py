from __future__ import annotations

import os
import asyncio
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4

from fastapi import FastAPI
from pydantic import BaseModel

from ai_models.model_loader import ModelLoader
from communication.async_client import AsyncAPIClient
from communication.message_protocol import BaseMessage, MessageType, TaskItem, TaskPayload

app = FastAPI(title="Manager Agent API", version="1.0.0")

_models = ModelLoader().load_all()
_rule_engine = _models["rule_engine"]
_decision_tree = _models["decision_tree"]
_api_client = AsyncAPIClient(timeout=20.0)
_received_alerts: List[Dict[str, Any]] = []
_incidents: Dict[str, Dict[str, Any]] = {}

_executor_endpoints = {
    "office": os.getenv("EXECUTOR_OFFICE_SERVICE", "http://127.0.0.1:8101"),
    "core": os.getenv("EXECUTOR_CORE_SERVICE", "http://127.0.0.1:8102"),
}


class DecisionTriggerRequest(BaseModel):
    enforce_actions: bool = True
    clear_alerts: bool = True


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_incident(incident_id: str) -> Dict[str, Any]:
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
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for alert in alerts:
        grouped[alert.get("domain", "unknown")].append(alert)

    context: Dict[str, Dict[str, Any]] = {}
    for domain, domain_alerts in grouped.items():
        first = domain_alerts[0] if domain_alerts else {}
        context[domain] = {
            "src_ip": first.get("src_ip"),
            "dst_ip": first.get("dst_ip"),
            "attack_type": first.get("attack_type", "unknown"),
        }
    return context


def _build_task_payload(
    alerts: List[Dict[str, Any]],
    strategy: Dict[str, Any],
    enforce_actions: bool,
    incident_id: str,
) -> TaskPayload:
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
                        "target_domain": domain,
                        "incident_type": incident_type,
                        "attack_pattern": strategy.get("pattern", "unknown"),
                        "enforce_actions": enforce_actions,
                    },
                )
            )
        return TaskPayload(
            reasoning=f"strategy={strategy_name}, incident={incident_type}, mode=joint_plan",
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
                    "target_domain": domain,
                    "enforce_actions": enforce_actions,
                    "incident_type": incident_type,
                    "attack_pattern": strategy.get("pattern", "unknown"),
                },
            )
        )

    return TaskPayload(
        reasoning=f"strategy={strategy_name}, enforce_actions={enforce_actions}",
        tasks=tasks,
    )


async def _dispatch_tasks(task_payload: TaskPayload) -> List[Dict[str, Any]]:
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
            message_type=MessageType.TASK,
            source="manager",
            target=f"executor-{domain}",
            payload=TaskPayload(reasoning=task_payload.reasoning, tasks=tasks).model_dump(),
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


@app.get("/health")
async def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "role": "manager",
        "alert_buffer_size": len(_received_alerts),
        "ooda": _ooda_metrics(),
    }


@app.post("/alerts")
async def alerts(message: Dict[str, Any]) -> Dict[str, Any]:
    normalized = _normalize_alert(message)
    _received_alerts.append(normalized)
    return {"status": "success", "accepted": True, "buffered": len(_received_alerts)}


@app.post("/decision/trigger")
async def decision_trigger(request: DecisionTriggerRequest) -> Dict[str, Any]:
    alerts_snapshot = list(_received_alerts)
    alert_sources = sorted({a.get("alert_source", "unknown") for a in alerts_snapshot})
    analysis = _rule_engine.evaluate(alerts_snapshot)
    decision = _decision_tree.choose_strategy(analysis)
    incident_id = _create_incident_context(alerts_snapshot, analysis, decision)
    task_payload = _build_task_payload(
        alerts_snapshot,
        decision,
        enforce_actions=request.enforce_actions,
        incident_id=incident_id,
    )

    incident = _ensure_incident(incident_id)
    incident["tasks_total"] = len(task_payload.tasks)
    incident["status"] = "open" if not request.enforce_actions else "acting"
    incident["ooda_stage"] = "decide" if not request.enforce_actions else "act"
    incident["updated_at"] = _now_iso()

    dispatch_results = await _dispatch_tasks(task_payload)
    for dispatch in dispatch_results:
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
        "task_payload": task_payload.model_dump(),
        "dispatch": {"dispatch_results": dispatch_results},
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