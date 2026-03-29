from __future__ import annotations

import random
import time
from typing import Dict


class DeviceController:
    """异构设备控制适配层（当前为模拟实现）。"""

    def __init__(
        self,
        rng: random.Random | None = None,
        success_rate: float = 0.92,
        latency_min_ms: int = 20,
        latency_max_ms: int = 120,
    ) -> None:
        self.rng = rng or random.Random()
        self.success_rate = max(0.0, min(float(success_rate), 1.0))
        self.latency_min_ms = int(latency_min_ms)
        self.latency_max_ms = int(latency_max_ms)

    def _simulate_outcome(self, device_type: str, action: str, payload: Dict) -> Dict:
        start = time.perf_counter()
        latency = self.rng.randint(self.latency_min_ms, self.latency_max_ms)
        success = self.rng.random() <= self.success_rate
        elapsed_ms = int((time.perf_counter() - start) * 1000) + latency
        return {
            "success": success,
            "latency_ms": elapsed_ms,
            "device_type": device_type,
            "action": action,
            "params": payload,
        }

    def precheck_task(self, parsed_task: Dict, local_situation: Dict) -> Dict:
        capability = str(parsed_task.get("capability", ""))
        capability_args = parsed_task.get("capability_args", {}) if isinstance(parsed_task, dict) else {}
        resource_status = local_situation.get("resource_status", {}) if isinstance(local_situation, dict) else {}

        if capability == "block_traffic" and not (capability_args.get("src_ip") or capability_args.get("dst_ip")):
            return {
                "decision": "reject",
                "reason_code": "MISSING_TARGET_IP",
                "message": "block_traffic requires src_ip or dst_ip",
                "proposed_action": "raise_monitoring",
            }

        if capability == "isolate_host" and not capability_args.get("ip"):
            return {
                "decision": "counter_proposal",
                "reason_code": "MISSING_HOST_IP",
                "message": "isolate_host requires host ip",
                "proposed_action": "degrade_traffic",
            }

        max_block_actions = int(resource_status.get("max_block_actions", 0))
        used_block_actions = int(resource_status.get("used_block_actions", 0))
        if capability in {"block_traffic", "isolate_host"} and max_block_actions > 0 and used_block_actions >= max_block_actions:
            return {
                "decision": "reject",
                "reason_code": "DEVICE_RESOURCE_EXHAUSTED",
                "message": "controller local quota reached",
                "proposed_action": "observe_alert",
            }

        return {
            "decision": "accept",
            "reason_code": "OK",
            "message": "controller precheck passed",
            "proposed_action": "",
        }

    def isolate_host(self, ip: str | None, domain: str | None) -> Dict:
        payload = {"ip": ip, "domain": domain}
        return self._simulate_outcome("firewall", "isolate_host", payload)

    def block_traffic(self, src_ip: str | None, dst_ip: str | None, port: int | None) -> Dict:
        payload = {"src_ip": src_ip, "dst_ip": dst_ip, "port": int(port or 0)}
        return self._simulate_outcome("firewall", "block_traffic", payload)

    def increase_alert_level(self, domain: str | None) -> Dict:
        payload = {"domain": domain, "level": "high"}
        return self._simulate_outcome("ids", "increase_alert_level", payload)

    def execute(self, device_type: str, command: str, params: Dict) -> Dict:
        command_map = {
            "iptables": lambda p: self.block_traffic(
                src_ip=p.get("src_ip") or p.get("ip"),
                dst_ip=p.get("dst_ip"),
                port=p.get("port"),
            ),
            "set_acl": lambda p: self.isolate_host(ip=p.get("ip"), domain=p.get("domain")),
            "enable_strict_mode": lambda p: self.increase_alert_level(domain=p.get("domain")),
            "set_monitoring": lambda p: self.increase_alert_level(domain=p.get("domain")),
            "collect_context": lambda p: self._simulate_outcome(device_type, "collect_context", p),
        }
        if command in command_map:
            result = command_map[command](params)
            result["command"] = command
            return result
        return self._simulate_outcome(device_type, command or "noop", params)
