from __future__ import annotations

from typing import Dict, List


class DecisionTreeModel:
    """轻量决策树（规则化）用于策略模板选择。"""

    @staticmethod
    def _ordered_domains(involved_domains: List[str]) -> List[str]:
        """Use stable semantic ordering so joint-plan actions hit expected domains."""
        preferred = ["office", "portal", "core"]
        seen = set()
        ordered: List[str] = []

        for domain in preferred:
            if domain in involved_domains and domain not in seen:
                ordered.append(domain)
                seen.add(domain)

        for domain in involved_domains:
            if domain not in seen:
                ordered.append(domain)
                seen.add(domain)

        return ordered

    def _build_joint_plan(self, incident_type: str, involved_domains: List[str], mode: str) -> List[Dict]:
        if not involved_domains:
            return []

        domains = self._ordered_domains(involved_domains)
        portal_to_office = "portal" in domains and "office" in domains and incident_type == "lateral_penetration"

        # Portal is identified as the stepping-stone domain to office, so add
        # source-side blocking in portal to cut the external kill-chain.
        if portal_to_office and mode in {"strict", "balanced"}:
            return [
                {"domain": "office", "objective": "block_ip"},
                {"domain": "portal", "objective": "block_ip"},
            ]

        if mode == "strict" and incident_type == "lateral_penetration":
            return [
                {"domain": domains[0], "objective": "isolate_host"},
                {"domain": domains[-1], "objective": "increase_alert_level"},
            ]

        if mode == "strict" and incident_type == "privilege_data_theft":
            return [
                {"domain": domains[0], "objective": "block_traffic"},
                {"domain": domains[-1], "objective": "tighten_acl"},
            ]

        if mode == "balanced" and len(domains) >= 2:
            return [
                {"domain": domains[0], "objective": "block_ip"},
                {"domain": domains[-1], "objective": "raise_monitoring"},
            ]

        if mode == "observe":
            return [{"domain": d, "objective": "observe_alert"} for d in domains]

        if len(domains) >= 2:
            return [
                {"domain": domains[0], "objective": "block_ip"},
                {"domain": domains[-1], "objective": "raise_monitoring"},
            ]
        return [{"domain": domains[0], "objective": "observe_alert"}]

    def _plan_priority(self, risk: str) -> int:
        if risk == "critical":
            return 1
        if risk == "high":
            return 2
        return 4

    def _apply_local_constraints(self, joint_plan: List[Dict], local_constraints: Dict[str, Dict]) -> tuple[List[Dict], List[str]]:
        adjusted: List[Dict] = []
        notes: List[str] = []
        for step in joint_plan:
            domain = step.get("domain", "unknown")
            objective = step.get("objective", "observe_alert")
            constraint = local_constraints.get(domain, {}) if isinstance(local_constraints, dict) else {}
            resource = constraint.get("resource_status", {}) if isinstance(constraint, dict) else {}
            proposed = str(constraint.get("proposed_action", ""))
            max_block = int(resource.get("max_block_actions", 0))
            used_block = int(resource.get("used_block_actions", 0))

            if objective in {"isolate_host", "tighten_acl", "block_ip", "block_traffic"} and max_block > 0 and used_block >= max_block:
                notes.append(f"{domain}:block_budget_exhausted->keep_intent_for_negotiation")

            if objective in {"isolate_host", "tighten_acl", "block_ip", "block_traffic"} and proposed == "observe_alert":
                notes.append(f"{domain}:local_degrade->keep_intent_for_negotiation")

            adjusted.append({"domain": domain, "objective": objective})
        return adjusted, notes

    def _build_candidates(self, analysis: Dict, local_constraints: Dict[str, Dict]) -> List[Dict]:
        risk = str(analysis.get("risk_level", "low"))
        incident_type = str(analysis.get("incident_type", "none"))
        involved_domains = analysis.get("involved_domains", [])

        base_candidates = [
            {
                "plan_id": "strict_containment",
                "strategy": "global_isolation_and_block",
                "utility": "high",
                "cost": "high",
                "expected_risk_reduction": "high",
                "playbook": ["block_ip", "tighten_acl", "enable_ids_strict"],
                "mode": "strict",
            },
            {
                "plan_id": "balanced_containment",
                "strategy": "targeted_containment",
                "utility": "high",
                "cost": "medium",
                "expected_risk_reduction": "medium",
                "playbook": ["block_ip", "raise_monitoring"],
                "mode": "balanced",
            },
            {
                "plan_id": "observe_and_hunt",
                "strategy": "observe_and_alert",
                "utility": "medium",
                "cost": "low",
                "expected_risk_reduction": "low",
                "playbook": ["log_only", "notify_admin"],
                "mode": "observe",
            },
        ]

        if risk == "critical":
            ordered = [base_candidates[0], base_candidates[1], base_candidates[2]]
        elif risk == "high":
            ordered = [base_candidates[1], base_candidates[0], base_candidates[2]]
        else:
            ordered = [base_candidates[2], base_candidates[1], base_candidates[0]]

        candidates: List[Dict] = []
        for candidate in ordered:
            joint_plan = self._build_joint_plan(incident_type, involved_domains, mode=candidate["mode"])
            adjusted_plan, notes = self._apply_local_constraints(joint_plan, local_constraints)
            c = dict(candidate)
            c["joint_plan"] = adjusted_plan
            c["constraint_notes"] = notes
            c["priority"] = self._plan_priority(risk)
            candidates.append(c)
        return candidates

    def choose_strategy(self, analysis: Dict, local_constraints: Dict[str, Dict] | None = None) -> Dict:
        risk = analysis.get("risk_level", "low")
        cross_domain = analysis.get("is_cross_domain_attack", False)
        pattern = analysis.get("attack_pattern", "unknown")
        incident_type = analysis.get("incident_type", "none")
        constraints = local_constraints or {}
        candidates = self._build_candidates(analysis, constraints)
        selected = candidates[0] if candidates else {
            "strategy": "observe_and_alert",
            "priority": 4,
            "playbook": ["log_only", "notify_admin"],
            "joint_plan": [],
            "utility": "medium",
            "cost": "low",
            "expected_risk_reduction": "low",
            "plan_id": "fallback_observe",
            "constraint_notes": [],
        }

        return {
            "strategy": selected.get("strategy", "observe_and_alert"),
            "priority": int(selected.get("priority", 4)),
            "playbook": selected.get("playbook", ["log_only", "notify_admin"]),
            "pattern": pattern,
            "incident_type": incident_type,
            "joint_plan": selected.get("joint_plan", []),
            "selected_plan": selected,
            "action_plan_candidates": candidates,
            "decision_basis": {
                "risk_level": risk,
                "cross_domain": cross_domain,
                "inferred_stage": analysis.get("inferred_stage", "unknown"),
            },
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
