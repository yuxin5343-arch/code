from __future__ import annotations

from typing import Dict

from communication.message_protocol import TaskItem


class TaskParser:
    """将通用协同任务映射到设备能力层。"""

    def precheck_task(self, task: TaskItem, local_situation: Dict) -> Dict:
        constraints = task.constraints if isinstance(task.constraints, dict) else {}
        resource_status = local_situation.get("resource_status", {}) if isinstance(local_situation, dict) else {}

        objective = str(task.objective)
        asset_level = str(constraints.get("asset_level", "")).lower()
        asset_id = str(constraints.get("asset_id", ""))
        whitelist_assets = set(resource_status.get("business_whitelist_assets", []))
        max_block_actions = int(resource_status.get("max_block_actions", 0))
        used_block_actions = int(resource_status.get("used_block_actions", 0))
        consecutive_failures = int(resource_status.get("consecutive_failures", 0))
        failure_threshold = int(resource_status.get("failure_threshold", 3))

        if objective in {"tighten_acl", "isolate_host"} and (
            asset_level == "critical" or (asset_id and asset_id in whitelist_assets)
        ):
            return {
                "decision": "counter_proposal",
                "reason_code": "CRITICAL_ASSET_PROTECTED",
                "message": "critical asset should not be isolated directly",
                "proposed_action": "degrade_traffic",
            }

        if objective in {"block_ip", "block_traffic", "tighten_acl", "isolate_host"} and max_block_actions > 0:
            if used_block_actions >= max_block_actions:
                return {
                    "decision": "counter_proposal",
                    "reason_code": "RESOURCE_BLOCK_LIMIT",
                    "message": "local block action budget exhausted",
                    "proposed_action": "observe_alert",
                }

        if consecutive_failures >= failure_threshold and objective in {"tighten_acl", "isolate_host", "block_traffic", "block_ip"}:
            return {
                "decision": "counter_proposal",
                "reason_code": "FAILURE_STREAK_DEGRADE",
                "message": "consecutive failures exceed threshold",
                "proposed_action": "observe_alert",
            }

        return {
            "decision": "accept",
            "reason_code": "OK",
            "message": "task is feasible",
            "proposed_action": "",
        }

    def _parse_block_traffic(self, constraints: Dict) -> Dict:
        src_ip = constraints.get("ip") or constraints.get("src_ip")
        dst_ip = constraints.get("dst_ip")
        port = int(constraints.get("port", 0))
        return {
            "capability": "block_traffic",
            "capability_args": {"src_ip": src_ip, "dst_ip": dst_ip, "port": port},
            "receiver": "firewall",
            "parameters": {
                "command": "iptables",
                "args": ["-A", "INPUT", "-s", src_ip, "-j", "DROP"] if src_ip else ["missing_ip"],
            },
        }

    def _parse_isolate_host(self, constraints: Dict, default_domain: str) -> Dict:
        ip = constraints.get("ip") or constraints.get("src_ip")
        domain = constraints.get("domain") or constraints.get("target_domain") or default_domain
        return {
            "capability": "isolate_host",
            "capability_args": {"ip": ip, "domain": domain},
            "receiver": "firewall",
            "parameters": {"command": "set_acl", "args": ["strict", domain]},
        }

    def _parse_increase_alert(self, constraints: Dict, default_domain: str) -> Dict:
        domain = constraints.get("domain") or constraints.get("target_domain") or default_domain
        return {
            "capability": "increase_alert_level",
            "capability_args": {"domain": domain},
            "receiver": "ids",
            "parameters": {"command": "set_monitoring", "args": ["high", domain]},
        }

    def parse(self, task: TaskItem) -> Dict:
        """
        将通用任务解析为结构化定义，包括任务ID、接收方和执行参数。
        """
        objective = task.objective
        task_id = f"task-{task.task_id}"
        constraints = task.constraints if isinstance(task.constraints, dict) else {}
        target_domain = task.target_domain

        mapping = {
            "block_ip": self._parse_block_traffic,
            "block_traffic": self._parse_block_traffic,
            "tighten_acl": lambda c: self._parse_isolate_host(c, target_domain),
            "isolate_host": lambda c: self._parse_isolate_host(c, target_domain),
            "enable_ids_strict": lambda c: self._parse_increase_alert(c, target_domain),
            "raise_monitoring": lambda c: self._parse_increase_alert(c, target_domain),
            "increase_alert_level": lambda c: self._parse_increase_alert(c, target_domain),
        }

        parsed = mapping.get(
            objective,
            lambda _c: {
                "capability": "collect_context",
                "capability_args": {"domain": target_domain},
                "receiver": "ids",
                "parameters": {"command": "collect_context", "args": ["--no-block"]},
            },
        )(constraints)

        return {
            "task_id": task_id,
            "receiver": parsed["receiver"],
            "capability": parsed["capability"],
            "capability_args": parsed["capability_args"],
            "parameters": parsed["parameters"],
        }
