from __future__ import annotations

import os
import asyncio
from collections import defaultdict
from typing import Any, Dict, List

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

_executor_endpoints = {
    "office": os.getenv("EXECUTOR_OFFICE_SERVICE", "http://127.0.0.1:8101"),
    "core": os.getenv("EXECUTOR_CORE_SERVICE", "http://127.0.0.1:8102"),
}


class DecisionTriggerRequest(BaseModel):
    enforce_actions: bool = True
    clear_alerts: bool = True


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


def _build_task_payload(alerts: List[Dict[str, Any]], strategy: Dict[str, Any], enforce_actions: bool) -> TaskPayload:
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for alert in alerts:
        grouped[alert.get("domain", "unknown")].append(alert)

    tasks: List[TaskItem] = []
    playbook = strategy.get("playbook", [])
    priority = int(strategy.get("priority", 5))
    strategy_name = strategy.get("strategy", "unknown")

    for domain, domain_alerts in grouped.items():
        src_ip = domain_alerts[0].get("src_ip") if domain_alerts else None
        objective = _pick_objective(playbook, enforce_actions=enforce_actions, has_ip=bool(src_ip))
        hints = ["enforce" if enforce_actions else "observe_only", f"strategy:{strategy_name}"]

        tasks.append(
            TaskItem(
                objective=objective,
                target_domain=domain,
                priority=priority,
                action_hints=hints,
                constraints={
                    "ip": src_ip,
                    "enforce_actions": enforce_actions,
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
    return {"status": "ok", "role": "manager", "alert_buffer_size": len(_received_alerts)}


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
    task_payload = _build_task_payload(alerts_snapshot, decision, enforce_actions=request.enforce_actions)
    dispatch_results = await _dispatch_tasks(task_payload)

    if request.clear_alerts:
        _received_alerts.clear()

    return {
        "alerts_snapshot": alerts_snapshot,
        "alert_sources": alert_sources,
        "analysis": analysis,
        "decision": decision,
        "task_payload": task_payload.model_dump(),
        "dispatch": {"dispatch_results": dispatch_results},
    }