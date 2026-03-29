from __future__ import annotations

import os
import asyncio
import random
from typing import Dict, List

from fastapi import BackgroundTasks, FastAPI

from manager.decision_tree import DecisionTreeModel
from communication.async_client import AsyncAPIClient
from communication.message_protocol import BaseMessage, LocalSituationPayload, MessageType, ResultPayload, TaskItem, TaskPayload
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
    max_block_actions = int(os.getenv("EXECUTOR_MAX_BLOCK_ACTIONS", "5"))
    failure_threshold = int(os.getenv("EXECUTOR_FAILURE_THRESHOLD", "3"))
    whitelist_assets_raw = os.getenv("EXECUTOR_WHITELIST_ASSETS", "")
    whitelist_assets = [s.strip() for s in whitelist_assets_raw.split(",") if s.strip()]
    return ExecutorAgent(
        executor_id=executor_id,
        domain=domain,
        seed=seed,
        success_rate=success_rate,
        latency_min_ms=latency_min_ms,
        latency_max_ms=latency_max_ms,
        max_block_actions=max_block_actions,
        failure_threshold=failure_threshold,
        whitelist_assets=whitelist_assets,
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
        max_block_actions: int,
        failure_threshold: int,
        whitelist_assets: List[str],
    ) -> None:
        super().__init__(executor_id, domain)
        self.initial_seed = int(seed)
        self.initial_success_rate = float(success_rate)
        self.initial_latency_min_ms = int(latency_min_ms)
        self.initial_latency_max_ms = int(latency_max_ms)
        self.initial_max_block_actions = int(max_block_actions)
        self.initial_failure_threshold = int(failure_threshold)
        self.initial_whitelist_assets = list(whitelist_assets)
        self.seed = int(seed)
        self.controller_rng = random.Random(self.seed)
        self.behavior_rng = random.Random(self.seed + 1)
        self.controller = DeviceController(
            rng=self.controller_rng,
            success_rate=success_rate,
            latency_min_ms=latency_min_ms,
            latency_max_ms=latency_max_ms,
        )
        self.analyzer = LocalAnalyzer(
            max_block_actions=max_block_actions,
            failure_threshold=failure_threshold,
            business_whitelist_assets=whitelist_assets,
        )
        self.task_parser = TaskParser()
        self.pending_tasks: Dict[str, Dict] = {}
        self.reported_alert_ids: set[str] = set()

    def reset_state(self) -> None:
        """Reset volatile runtime state so each experiment run is independent."""
        self.local_logs.clear()
        self.pending_tasks.clear()
        self.reported_alert_ids.clear()
        self.controller_rng = random.Random(self.initial_seed)
        self.behavior_rng = random.Random(self.initial_seed + 1)
        self.controller = DeviceController(
            rng=self.controller_rng,
            success_rate=self.initial_success_rate,
            latency_min_ms=self.initial_latency_min_ms,
            latency_max_ms=self.initial_latency_max_ms,
        )
        self.analyzer = LocalAnalyzer(
            max_block_actions=self.initial_max_block_actions,
            failure_threshold=self.initial_failure_threshold,
            business_whitelist_assets=self.initial_whitelist_assets,
        )

    def patch_resource_status(self, patch: Dict) -> Dict:
        status = self.analyzer.resource_status
        max_block_actions = int(status.get("max_block_actions", 0))

        if "max_block_actions" in patch:
            max_block_actions = max(1, int(patch.get("max_block_actions", max_block_actions)))
            status["max_block_actions"] = max_block_actions

        if "used_block_actions" in patch:
            used_value = patch.get("used_block_actions")
            if used_value == "max":
                status["used_block_actions"] = max_block_actions
            else:
                status["used_block_actions"] = max(0, int(used_value))

        if "consecutive_failures" in patch:
            status["consecutive_failures"] = max(0, int(patch.get("consecutive_failures", 0)))

        return dict(status)

    @staticmethod
    def _estimate_local_cost(action: str, local_situation: Dict) -> str:
        resource = local_situation.get("resource_status", {}) if isinstance(local_situation, dict) else {}
        used = int(resource.get("used_block_actions", 0))
        quota = int(resource.get("max_block_actions", 0))
        if action in {"isolate_host", "tighten_acl"}:
            return "high"
        if action in {"block_ip", "block_traffic"}:
            if quota > 0 and used >= max(1, quota - 1):
                return "high"
            return "medium"
        return "low"

    async def execute_tasks(self, task_payload: TaskPayload, phase: str = "task", enforce_consensus: bool = False) -> List[ResultPayload]:
        results: List[ResultPayload] = []
        for task in task_payload.tasks:
            local_situation = self.analyzer.get_local_situation()
            objective = str(task.objective)

            if not enforce_consensus:
                parser_precheck = self.task_parser.precheck_task(task, local_situation)
                if parser_precheck["decision"] != "accept":
                    results.append(
                        ResultPayload(
                            task_id=task.task_id,
                            incident_id=task.incident_id,
                            executor_id=self.executor_id,
                            objective=task.objective,
                            ooda_stage="act",
                            status=parser_precheck["decision"],
                            success=False,
                            latency_ms=0,
                            details={
                                "decision_source": "task_parser",
                                "reason_code": parser_precheck["reason_code"],
                                "message": parser_precheck["message"],
                                "proposal_id": task.proposal_id,
                                "negotiation_round": task.negotiation_round,
                                "counter_proposal": parser_precheck.get("proposed_action", ""),
                                "cost_estimate": self._estimate_local_cost(objective, local_situation),
                                "local_evidence": {
                                    "resource_status": local_situation.get("resource_status", {}),
                                    "top_alert_types": local_situation.get("top_alert_types", []),
                                },
                                "local_situation": local_situation,
                            },
                        )
                    )
                    continue

            parsed = self.task_parser.parse(task)
            if not enforce_consensus:
                controller_precheck = self.controller.precheck_task(parsed, local_situation)
                if controller_precheck["decision"] != "accept":
                    results.append(
                        ResultPayload(
                            task_id=task.task_id,
                            incident_id=task.incident_id,
                            executor_id=self.executor_id,
                            objective=task.objective,
                            ooda_stage="act",
                            status=controller_precheck["decision"],
                            success=False,
                            latency_ms=0,
                            details={
                                "decision_source": "device_controller",
                                "reason_code": controller_precheck["reason_code"],
                                "message": controller_precheck["message"],
                                "proposal_id": task.proposal_id,
                                "negotiation_round": task.negotiation_round,
                                "counter_proposal": controller_precheck.get("proposed_action", ""),
                                "cost_estimate": self._estimate_local_cost(objective, local_situation),
                                "local_evidence": {
                                    "resource_status": local_situation.get("resource_status", {}),
                                    "top_alert_types": local_situation.get("top_alert_types", []),
                                },
                                "local_situation": local_situation,
                            },
                        )
                    )
                    continue

            if phase == "intent":
                results.append(
                    ResultPayload(
                        task_id=task.task_id,
                        incident_id=task.incident_id,
                        executor_id=self.executor_id,
                        objective=task.objective,
                        ooda_stage="act",
                        status="accept",
                        success=True,
                        latency_ms=0,
                        details={
                            "decision_source": "intent_phase",
                            "reason_code": "ACCEPT_INTENT",
                            "proposal_id": task.proposal_id,
                            "negotiation_round": task.negotiation_round,
                            "local_situation": local_situation,
                        },
                    )
                )
                continue

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
            self.analyzer.record_task_outcome(action=str(capability), success=bool(outcome.get("success", False)))
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
                    details={
                        **outcome,
                        "proposal_id": task.proposal_id,
                        "negotiation_round": task.negotiation_round,
                        "finalized_by": "manager_consensus" if enforce_consensus else "executor_local",
                    },
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


async def _report_local_situation_to_manager(event: str) -> None:
    local_situation = executor_agent.analyzer.get_local_situation()
    payload = LocalSituationPayload(
        executor_id=executor_agent.executor_id,
        domain=executor_agent.domain,
        risk_score=float(local_situation.get("risk_score", 0.0)),
        confidence=float(local_situation.get("confidence", 0.0)),
        top_alert_types=list(local_situation.get("top_alert_types", [])),
        resource_status=dict(local_situation.get("resource_status", {})),
        proposed_action=str(local_situation.get("proposed_action", "observe_alert")),
        event=event,
    )
    msg = BaseMessage(
        message_type=MessageType.LOCAL_SITUATION,
        source=executor_agent.executor_id,
        target="manager",
        payload=payload.model_dump(),
    )

    last_exc: Exception | None = None
    for _ in range(3):
        try:
            await _api_client.post_json(f"{MANAGER}/executors/local-situation", msg.model_dump())
            return
        except Exception as exc:
            last_exc = exc
            await asyncio.sleep(0.2)
    logger.warning("report local_situation failed executor=%s error=%s", executor_agent.executor_id, last_exc)


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
    if reported > 0 or float(analysis.get("risk_score", 0.0)) >= 70.0:
        await _report_local_situation_to_manager(event="alert_update")
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
        "local_situation": executor_agent.analyzer.get_local_situation(),
    }


@app.get("/local-situation")
async def local_situation() -> Dict:
    return {
        "executor": executor_agent.executor_id,
        "domain": executor_agent.domain,
        "local_situation": executor_agent.analyzer.get_local_situation(),
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


@app.post("/debug/reset-state")
async def debug_reset_state() -> Dict:
    executor_agent.reset_state()
    await _report_local_situation_to_manager(event="debug_reset")
    return {"accepted": True, "reset": True, "executor": executor_agent.executor_id}


@app.post("/debug/resource-status")
async def debug_patch_resource_status(payload: Dict) -> Dict:
    patch = payload.get("resource_status", payload)
    report_manager = bool(payload.get("report_manager", True)) if isinstance(payload, dict) else True
    patched = executor_agent.patch_resource_status(patch if isinstance(patch, dict) else {})
    if report_manager:
        await _report_local_situation_to_manager(event="debug_resource_patch")
    return {"accepted": True, "executor": executor_agent.executor_id, "resource_status": patched}


@app.post("/tasks")
async def receive_tasks(message: BaseMessage) -> Dict:
    if message.message_type not in {MessageType.TASK, MessageType.PROPOSAL, MessageType.CONSENSUS}:
        return {"accepted": False, "reason": "message_type must be task/proposal/consensus"}

    payload = TaskPayload(**message.payload)
    payload = _filter_tasks(payload, executor_agent.domain)
    if payload.max_negotiation_rounds > 1:
        return {"accepted": False, "reason": "one-shot negotiation only: max_negotiation_rounds must be 1"}

    phase = "task"
    enforce_consensus = False
    if message.message_type == MessageType.PROPOSAL:
        phase = "intent"
    elif message.message_type == MessageType.CONSENSUS:
        phase = "consensus"
        enforce_consensus = True

    results = await executor_agent.execute_tasks(payload, phase=phase, enforce_consensus=enforce_consensus)
    incident_id = payload.tasks[0].incident_id if payload.tasks else ""
    if incident_id and phase != "intent":
        await _report_execution_feedback(incident_id=incident_id, results=results)
    await _report_local_situation_to_manager(event="task_feedback")
    logger.info("executor=%s results=%s", executor_agent.executor_id, [r.model_dump() for r in results])

    negotiation_message_type = MessageType.PROPOSAL.value
    if any(r.status in {"counter_proposal", "reject"} for r in results):
        negotiation_message_type = MessageType.COUNTER_PROPOSAL.value
    elif phase == "consensus":
        negotiation_message_type = MessageType.CONSENSUS.value

    return {
        "accepted": True,
        "phase": phase,
        "negotiation_message_type": negotiation_message_type,
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
