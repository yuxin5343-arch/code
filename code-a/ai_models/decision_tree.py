from __future__ import annotations

from typing import Dict, List


class DecisionTreeModel:
    """轻量决策树（规则化）用于策略模板选择。"""

    def choose_strategy(self, analysis: Dict) -> Dict:
        risk = analysis.get("risk_level", "low")
        cross_domain = analysis.get("is_cross_domain_attack", False)
        pattern = analysis.get("attack_pattern", "unknown")

        if risk == "critical" and cross_domain:
            return {
                "strategy": "global_isolation_and_block",
                "priority": 1,
                "playbook": ["block_ip", "tighten_acl", "enable_ids_strict"],
                "pattern": pattern,
            }
        if risk in {"high", "critical"}:
            return {
                "strategy": "targeted_containment",
                "priority": 2,
                "playbook": ["block_ip", "raise_monitoring"],
                "pattern": pattern,
            }
        return {
            "strategy": "observe_and_alert",
            "priority": 4,
            "playbook": ["log_only", "notify_admin"],
            "pattern": pattern,
        }

    def correlate_alerts(self, alerts: List[Dict]) -> Dict:
        """
        根据预设的跨域攻击特征规则，将异构告警信息关联起来，还原完整的攻击链。
        """
        correlated_alerts = []
        for alert in alerts:
            if alert.get("type") == "phishing" and alert.get("domain") == "office":
                correlated_alerts.append(alert)

        for alert in alerts:
            if alert.get("type") == "scan" and alert.get("domain") == "core":
                correlated_alerts.append(alert)

        if len(correlated_alerts) > 1:
            return {
                "is_cross_domain_attack": True,
                "attack_chain": correlated_alerts,
                "risk_level": "critical",
            }

        return {
            "is_cross_domain_attack": False,
            "attack_chain": [],
            "risk_level": "low",
        }

    def generate_task_list(self, analysis: Dict) -> List[Dict]:
        """
        根据分析结果生成协同任务清单。
        """
        tasks = []
        if analysis.get("is_cross_domain_attack"):
            attack_chain = analysis.get("attack_chain", [])

            for alert in attack_chain:
                if alert.get("domain") == "office":
                    tasks.append({
                        "task_id": f"task-{alert.get('id')}",
                        "receiver": "office_executor",
                        "action": "block_ip",
                        "parameters": {
                            "ip": alert.get("source_ip"),
                        },
                    })
                elif alert.get("domain") == "core":
                    tasks.append({
                        "task_id": f"task-{alert.get('id')}",
                        "receiver": "core_executor",
                        "action": "isolate_server",
                        "parameters": {
                            "server_id": alert.get("target_server"),
                        },
                    })

        return tasks
