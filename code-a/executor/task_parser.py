from __future__ import annotations

from typing import Dict

from communication.message_protocol import TaskItem


class TaskParser:
    """将通用协同任务映射到设备能力层。"""

    def parse(self, task: TaskItem) -> Dict:
        """
        将通用任务解析为结构化定义，包括任务ID、接收方和执行参数。
        """
        objective = task.objective
        task_id = f"task-{task.task_id}"
        receiver = "unknown"
        parameters = {}
        constraints = task.constraints if isinstance(task.constraints, dict) else {}

        if objective == "block_ip":
            receiver = "firewall"
            ip = constraints.get("ip")
            if ip:
                parameters = {"command": "iptables", "args": ["-A", "INPUT", "-s", ip, "-j", "DROP"]}
            else:
                parameters = {"command": "noop", "args": ["missing_ip"]}
        elif objective == "tighten_acl":
            receiver = "firewall"
            parameters = {"command": "set_acl", "args": ["strict"]}
        elif objective == "enable_ids_strict":
            receiver = "ids"
            parameters = {"command": "enable_strict_mode"}
        elif objective == "raise_monitoring":
            receiver = "ids"
            parameters = {"command": "set_monitoring", "args": ["high"]}
        elif objective == "observe_alert":
            receiver = "ids"
            parameters = {"command": "collect_context", "args": ["--no-block"]}

        return {
            "task_id": task_id,
            "receiver": receiver,
            "parameters": parameters,
        }
