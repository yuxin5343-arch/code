from __future__ import annotations

from typing import Dict, List, Union

from communication.message_protocol import ResultPayload, TaskPayload


class BaseExecutor:
    def __init__(self, executor_id: str, domain: str) -> None:
        self.executor_id = executor_id
        self.domain = domain
        self.local_logs: List[Dict] = []

    def ingest_local_log(self, event: Dict) -> None:
        """
        接收并处理来自不同安全设备的日志。
        """
        device_type = event.get("device_type", "unknown")
        if device_type == "snort":
            self._process_snort_log(event)
        elif device_type == "firewall":
            self._process_firewall_log(event)
        else:
            self.local_logs.append(event)

    def _process_snort_log(self, log: Dict) -> None:
        """
        处理Snort IDS日志。
        """
        log["processed"] = True
        pre_marked = bool(log.get("suspicious", False))
        log["suspicious"] = pre_marked or ("alert" in log.get("message", "").lower())
        self.local_logs.append(log)

    def _process_firewall_log(self, log: Dict) -> None:
        """
        处理防火墙日志。
        """
        log["processed"] = True
        pre_marked = bool(log.get("suspicious", False))
        log["suspicious"] = pre_marked or ("block" in log.get("action", "").lower())
        self.local_logs.append(log)

    def read_local_logs(self) -> List[Dict]:
        return list(self.local_logs)

    async def execute_tasks(self, task_payload: TaskPayload) -> List[ResultPayload]:
        raise NotImplementedError
