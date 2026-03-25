from __future__ import annotations

import os
import asyncio
import random
from typing import Dict, List

from fastapi import BackgroundTasks, FastAPI

from ai_models.decision_tree import DecisionTreeModel
from communication.async_client import AsyncAPIClient
from communication.message_protocol import BaseMessage, MessageType, ResultPayload, TaskItem, TaskPayload
from executor.base_executor import BaseExecutor
from executor.device_controller import DeviceController
from executor.local_analyzer import LocalAnalyzer
from executor.task_parser import TaskParser
from simulation.attack_scripts.malicious_behaviors import execute_malicious_behavior_attempt
from utils.logger import get_logger

logger = get_logger("executor")
app = FastAPI(title="Executor Agent API", version="1.0.0")
MANAGER = os.getenv("MANAGER_SERVICE", "http://127.0.0.1:8000")
_api_client = AsyncAPIClient(timeout=10.0)


def build_executor_from_env() -> "ExecutorAgent":
    executor_id = os.getenv("EXECUTOR_ID", "executor-unknown")
    domain = os.getenv("EXECUTOR_DOMAIN", "unknown")
    seed = int(os.getenv("EXECUTOR_SEED", "20260325"))
    success_rate = float(os.getenv("EXECUTOR_SUCCESS_RATE", "0.92"))
    latency_min_ms = int(os.getenv("EXECUTOR_LATENCY_MIN_MS", "20"))
    latency_max_ms = int(os.getenv("EXECUTOR_LATENCY_MAX_MS", "120"))
    return ExecutorAgent(
        executor_id=executor_id,
        domain=domain,
        seed=seed,
        success_rate=success_rate,
        latency_min_ms=latency_min_ms,
        latency_max_ms=latency_max_ms,
    )


class ExecutorAgent(BaseExecutor):
    def __init__(
        self,
        executor_id: str,
        domain: str,
        seed: int,
        success_rate: float,
        latency_min_ms: int,
        latency_max_ms: int,
    ) -> None:
        super().__init__(executor_id, domain)
        self.seed = int(seed)
        self.controller_rng = random.Random(self.seed)
        self.behavior_rng = random.Random(self.seed + 1)
        self.controller = DeviceController(
            rng=self.controller_rng,
            success_rate=success_rate,
            latency_min_ms=latency_min_ms,
            latency_max_ms=latency_max_ms,
        )
        self.analyzer = LocalAnalyzer()
        self.task_parser = TaskParser()
        self.pending_tasks: Dict[str, Dict] = {}
        self.reported_alert_ids: set[str] = set()

    async def execute_tasks(self, task_payload: TaskPayload) -> List[ResultPayload]:
        results: List[ResultPayload] = []
        for task in task_payload.tasks:
            parsed = self.task_parser.parse(task)
            device = parsed.get("receiver", "unknown")
            params = parsed.get("parameters", {})
            capability = parsed.get("capability")
            capability_args = parsed.get("capability_args", {})
            controller_fn = getattr(self.controller, str(capability), None)

            if callable(controller_fn):
                outcome = controller_fn(**capability_args)
                outcome["capability"] = capability
            else:
                outcome = self.controller.execute(
                    device_type=device,
                    command=params.get("command", "noop"),
                    params=params,
                )
                outcome["capability"] = "legacy_execute"
            results.append(
                ResultPayload(
                    task_id=task.task_id,
                    incident_id=task.incident_id,
                    executor_id=self.executor_id,
                    objective=task.objective,
                    ooda_stage="act",
                    status="completed" if bool(outcome.get("success", False)) else "failed",
                    success=bool(outcome.get("success", False)),
                    latency_ms=int(outcome.get("latency_ms", 0)),
                    details=outcome,
                )
            )
        return results

    async def dispatch_task(self, task: TaskItem) -> None:
        self.pending_tasks[task.task_id] = {"status": "pending", "task": task.model_dump()}

    async def track_task_status(self, task_id: str) -> Dict:
        return self.pending_tasks.get(task_id, {"status": "unknown"})


executor_agent = build_executor_from_env()


async def _report_alert_to_manager(alert: Dict) -> None:
    msg = BaseMessage(
        message_type=MessageType.ALERT,
        source=executor_agent.executor_id,
        target="manager",
        payload=alert,
    )
    last_exc: Exception | None = None
    for _ in range(3):
        try:
            await _api_client.post_json(f"{MANAGER}/alerts", msg.model_dump())
            return
        except Exception as exc:
            last_exc = exc
            await asyncio.sleep(0.2)
    logger.error("report alert failed executor=%s error=%s", executor_agent.executor_id, last_exc)


async def _report_execution_feedback(incident_id: str, results: List[ResultPayload]) -> None:
    if not incident_id:
        return

    feedback_payload = {
        "incident_id": incident_id,
        "executor_id": executor_agent.executor_id,
        "ooda_stage": "feedback",
        "status": "reported",
        "results": [r.model_dump() for r in results],
    }
    msg = BaseMessage(
        message_type=MessageType.RESULT,
        source=executor_agent.executor_id,
        target="manager",
        payload=feedback_payload,
    )

    last_exc: Exception | None = None
    for _ in range(3):
        try:
            await _api_client.post_json(f"{MANAGER}/incidents/feedback", msg.model_dump())
            return
        except Exception as exc:
            last_exc = exc
            await asyncio.sleep(0.2)
    logger.error(
        "report feedback failed executor=%s incident_id=%s error=%s",
        executor_agent.executor_id,
        incident_id,
        last_exc,
    )


async def _analyze_and_report_latest() -> Dict:
    analysis = executor_agent.analyzer.analyze(executor_agent.read_local_logs(), task_objective="detect_intrusion")
    reported = 0
    for alert in analysis.get("alerts", []):
        alert_id = alert.get("alert_id")
        if not alert_id or alert_id in executor_agent.reported_alert_ids:
            continue
        await _report_alert_to_manager(alert)
        executor_agent.reported_alert_ids.add(alert_id)
        reported += 1
    return {"alerts": len(analysis.get("alerts", [])), "reported": reported}


def _filter_tasks(payload: TaskPayload, domain: str) -> TaskPayload:
    filtered_tasks: List[TaskItem] = [t for t in payload.tasks if t.target_domain in {domain, "all"}]
    payload.tasks = filtered_tasks
    return payload


@app.get("/health")
async def health() -> Dict:
    return {
        "status": "ok",
        "role": "executor",
        "executor_id": executor_agent.executor_id,
        "domain": executor_agent.domain,
        "seed": executor_agent.seed,
    }


@app.post("/local-logs")
async def push_local_log(event: Dict) -> Dict:
    executor_agent.ingest_local_log(event)
    report_stats = await _analyze_and_report_latest()
    return {
        "accepted": True,
        "count": len(executor_agent.local_logs),
        "analysis_alerts": report_stats["alerts"],
        "reported_alerts": report_stats["reported"],
    }


@app.post("/behavior/attempt")
async def behavior_attempt(payload: Dict) -> Dict:
    """在当前执行器容器内执行一次恶意行为尝试并上报。"""
    profile = payload.get("profile", "mixed")
    event_id = payload.get("event_id") or f"{executor_agent.domain}-behavior-{len(executor_agent.local_logs)}"
    src_ip = payload.get("src_ip", "10.10.1.23")
    dst_ip = payload.get("dst_ip", "10.20.5.8" if executor_agent.domain == "office" else "10.20.9.3")
    device_type = payload.get("device_type", "ids" if executor_agent.domain == "office" else "firewall")

    event = execute_malicious_behavior_attempt(
        domain=executor_agent.domain,
        event_id=event_id,
        src_ip=src_ip,
        dst_ip=dst_ip,
        device_type=device_type,
        profile=profile,
        rng=executor_agent.behavior_rng,
    )

    executor_agent.ingest_local_log(event)
    report_stats = await _analyze_and_report_latest()
    return {
        "accepted": True,
        "event": event,
        "analysis_alerts": report_stats["alerts"],
        "reported_alerts": report_stats["reported"],
    }


@app.post("/tasks")
async def receive_tasks(message: BaseMessage) -> Dict:
    if message.message_type != MessageType.TASK:
        return {"accepted": False, "reason": "message_type must be task"}

    payload = TaskPayload(**message.payload)
    payload = _filter_tasks(payload, executor_agent.domain)

    results = await executor_agent.execute_tasks(payload)
    incident_id = payload.tasks[0].incident_id if payload.tasks else ""
    if incident_id:
        await _report_execution_feedback(incident_id=incident_id, results=results)
    logger.info("executor=%s results=%s", executor_agent.executor_id, [r.model_dump() for r in results])

    return {
        "accepted": True,
        "executor": executor_agent.executor_id,
        "results": [r.model_dump() for r in results],
    }


@app.post("/dispatch-task")
async def dispatch_task_endpoint(task: TaskItem, background_tasks: BackgroundTasks) -> Dict:
    """
    接收任务并异步调度。
    """
    background_tasks.add_task(executor_agent.dispatch_task, task)
    return {"status": "dispatched", "task_id": task.task_id}


@app.get("/task-status/{task_id}")
async def get_task_status(task_id: str) -> Dict:
    """
    查询任务状态。
    """
    return await executor_agent.track_task_status(task_id)


@app.post("/generate-task-list")
async def generate_task_list_endpoint(analysis: Dict) -> Dict:
    """
    根据分析结果生成协同任务清单。
    """
    decision_tree = DecisionTreeModel()
    task_list = decision_tree.generate_task_list(analysis)
    return {"task_list": task_list}
