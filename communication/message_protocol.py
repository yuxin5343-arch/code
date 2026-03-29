from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class MessageType(str, Enum):
    ALERT = "alert"
    TASK = "task"
    PROPOSAL = "proposal"
    COUNTER_PROPOSAL = "counter_proposal"
    CONSENSUS = "consensus"
    COMMAND = "command"
    RESULT = "result"
    LOCAL_SITUATION = "local_situation"
    HEARTBEAT = "heartbeat"
    REGISTER = "register"


class BaseMessage(BaseModel):
    message_id: str = Field(default_factory=lambda: str(uuid4()))
    message_type: MessageType
    source: str
    target: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    payload: Dict[str, Any] = Field(default_factory=dict)


class AlertPayload(BaseModel):
    domain: str
    device_type: str
    severity: str
    attack_type: str
    src_ip: str
    dst_ip: str
    evidence: Dict[str, Any] = Field(default_factory=dict)


class TaskItem(BaseModel):
    task_id: str = Field(default_factory=lambda: str(uuid4()))
    proposal_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str = ""
    negotiation_round: int = 1
    objective: str
    target_domain: str
    priority: int = 5
    ooda_stage: str = "decide"
    status: str = "pending"
    action_hints: List[str] = Field(default_factory=list)
    constraints: Dict[str, Any] = Field(default_factory=dict)


class TaskPayload(BaseModel):
    strategy_id: str = Field(default_factory=lambda: str(uuid4()))
    reasoning: str
    plan_type: str = "task_plan"
    negotiation_timeout_ms: int = 3000
    max_negotiation_rounds: int = 1
    tasks: List[TaskItem]


class CommandPayload(BaseModel):
    task_id: str
    device_type: str
    command: str
    params: Dict[str, Any] = Field(default_factory=dict)


class ResultPayload(BaseModel):
    task_id: str
    incident_id: str = ""
    executor_id: str
    objective: str = "unknown"
    ooda_stage: str = "act"
    status: str = "running"
    success: bool
    latency_ms: int
    details: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None


class FeedbackPayload(BaseModel):
    incident_id: str
    executor_id: str
    ooda_stage: str = "feedback"
    status: str = "reported"
    results: List[ResultPayload] = Field(default_factory=list)


class LocalSituationPayload(BaseModel):
    executor_id: str
    domain: str
    risk_score: float
    confidence: float
    top_alert_types: List[str] = Field(default_factory=list)
    resource_status: Dict[str, Any] = Field(default_factory=dict)
    proposed_action: str = "observe_alert"
    event: str = "periodic"


class ManagerAgent:
    """
    ManagerAgent 基类，负责管理生命周期和消息处理。
    """
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.running = False

    def start(self):
        """启动智能体。"""
        self.running = True
        print(f"ManagerAgent {self.agent_id} started.")

    def stop(self):
        """停止智能体。"""
        self.running = False
        print(f"ManagerAgent {self.agent_id} stopped.")

    def handle_message(self, message: BaseMessage):
        """处理收到的消息。"""
        raise NotImplementedError("handle_message 方法需要子类实现。")


class ExecutorAgent:
    """
    ExecutorAgent 基类，负责执行任务和报告状态。
    """
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.running = False

    def start(self):
        """启动智能体。"""
        self.running = True
        print(f"ExecutorAgent {self.agent_id} started.")

    def stop(self):
        """停止智能体。"""
        self.running = False
        print(f"ExecutorAgent {self.agent_id} stopped.")

    def execute_task(self, task: TaskPayload):
        """执行任务。"""
        raise NotImplementedError("execute_task 方法需要子类实现。")
