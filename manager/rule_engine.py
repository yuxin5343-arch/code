from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from utils.config_loader import load_yaml


class RuleEngine:
    """基于规则的跨域攻击研判引擎。"""

    STAGE_ORDER = {
        "recon": 1,
        "initial_access": 2,
        "command_execution": 3,
        "lateral_movement": 4,
        "privilege_escalation": 5,
        "collection": 6,
        "sensitive_file_access": 6,
        "exfiltration": 7,
        "impact": 8,
    }

    DEFAULT_RISK_MATRIX_CONFIG: Dict[str, Any] = {
        "domain_weights": {
            "core": 1.0,
            "office": 0.6,
            "unknown": 0.5,
        },
        "level_scores": {
            "high": 1.0,
            "medium": 0.6,
            "low": 0.2,
        },
        "calibration": {
            "enabled": True,
            "cross_domain_required": True,
            "edge_required": True,
            "high_factor_min": 0.55,
            "critical_factor_min": 0.75,
        },
    }

    def __init__(self) -> None:
        cfg_path = Path(__file__).resolve().parent / "configs" / "risk_matrix.yaml"
        loaded = load_yaml(str(cfg_path))
        if not isinstance(loaded, dict):
            loaded = {}
        self._risk_matrix_config = self._deep_merge(self.DEFAULT_RISK_MATRIX_CONFIG, loaded)

    @staticmethod
    def _deep_merge(base: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(base)
        for key, value in incoming.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = RuleEngine._deep_merge(merged[key], value)
            else:
                merged[key] = value
        return merged

    def _parse_ts(self, value: Any) -> datetime | None:
        if not value:
            return None
        text = str(value)
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        except Exception:
            pass
        try:
            return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except Exception:
            return None

    def _domain_level(self, alerts: List[Dict]) -> str:
        sev = Counter(str(a.get("severity", "low")).lower() for a in alerts)
        critical = sev.get("critical", 0)
        high = sev.get("high", 0)
        medium = sev.get("medium", 0)
        if critical >= 1 or high >= 2:
            return "high"
        if high >= 1 or medium >= 1:
            return "medium"
        return "low"

    def _infer_stage(self, alerts: List[Dict]) -> str:
        ranked: List[Tuple[int, str]] = []
        for a in alerts:
            stage = str(a.get("stage") or a.get("evidence", {}).get("stage") or a.get("attack_type") or "recon")
            ranked.append((self.STAGE_ORDER.get(stage, 1), stage))
        if not ranked:
            return "unknown"
        return sorted(ranked, key=lambda x: x[0])[-1][1]

    def _build_incident_graph(self, alerts: List[Dict], time_window_seconds: int = 5) -> Dict[str, Any]:
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        for idx, alert in enumerate(alerts):
            node_id = str(alert.get("alert_id") or f"n{idx}")
            nodes.append(
                {
                    "node_id": node_id,
                    "domain": alert.get("domain", "unknown"),
                    "src_ip": alert.get("src_ip", ""),
                    "dst_ip": alert.get("dst_ip", ""),
                    "stage": str(alert.get("stage") or alert.get("evidence", {}).get("stage") or "recon"),
                    "attack_type": str(alert.get("attack_type", "unknown")),
                    "timestamp": alert.get("timestamp", ""),
                    "severity": str(alert.get("severity", "low")),
                }
            )

        for i in range(len(nodes)):
            for j in range(i + 1, len(nodes)):
                left = nodes[i]
                right = nodes[j]
                if left["domain"] == right["domain"]:
                    continue

                same_src = bool(left.get("src_ip")) and left.get("src_ip") == right.get("src_ip")
                same_dst = bool(left.get("dst_ip")) and left.get("dst_ip") == right.get("dst_ip")
                if not (same_src or same_dst):
                    continue

                t0 = self._parse_ts(left.get("timestamp"))
                t1 = self._parse_ts(right.get("timestamp"))
                if not t0 or not t1:
                    continue

                delta_s = abs(int((t1 - t0).total_seconds()))
                if delta_s > time_window_seconds:
                    continue

                l_stage_idx = self.STAGE_ORDER.get(str(left.get("stage", "recon")), 1)
                r_stage_idx = self.STAGE_ORDER.get(str(right.get("stage", "recon")), 1)
                stage_related = abs(l_stage_idx - r_stage_idx) <= 2
                if not stage_related:
                    continue

                edges.append(
                    {
                        "from": left["node_id"],
                        "to": right["node_id"],
                        "correlation_key": {
                            "src_ip": left.get("src_ip") if same_src else "",
                            "dst_ip": left.get("dst_ip") if same_dst else "",
                            "time_window_seconds": time_window_seconds,
                            "stage_pair": [left.get("stage"), right.get("stage")],
                        },
                    }
                )

        return {
            "nodes": nodes,
            "edges": edges,
            "summary": {
                "node_count": len(nodes),
                "edge_count": len(edges),
            },
        }

    def _global_decision_matrix(self, domain_levels: Dict[str, str], edge_count: int) -> Tuple[str, str]:
        levels = list(domain_levels.values())
        cross_domain = len(domain_levels) >= 2
        node_count = len(domain_levels)
        has_portal = "portal" in domain_levels
        has_office = "office" in domain_levels
        has_core = "core" in domain_levels
        has_high = any(level == "high" for level in levels)
        has_medium = any(level == "medium" for level in levels)

        # Portal -> Office weak-signal chain: keep base risk at medium and let
        # domain-weight calibration perform the visible uplift to high when warranted.
        if cross_domain and has_portal and has_office and edge_count >= 1 and all(level in {"low", "medium"} for level in levels):
            if node_count >= 3 and has_core and edge_count >= 2:
                return "medium", "high"
            return "medium", "medium"

        if cross_domain and edge_count >= 1 and has_high:
            return "critical", "high"
        if cross_domain and edge_count >= 1 and has_medium:
            return "medium", "high"
        if cross_domain and edge_count >= 1:
            return "medium", "medium"
        if cross_domain and has_high:
            return "high", "medium"
        if has_high:
            # Single-domain high-severity incidents should still trigger a meaningful local defense,
            # otherwise the baseline degenerates into observe-only on its own turf.
            return "high", "high"
        if any(level == "medium" for level in levels):
            return "medium", "low"
        return "low", "low"

    @staticmethod
    def _risk_index(risk: str) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(str(risk), 0)

    @staticmethod
    def _risk_from_index(idx: int) -> str:
        safe = max(0, min(3, int(idx)))
        return ["low", "medium", "high", "critical"][safe]

    def _domain_weight_factor(self, domain_levels: Dict[str, str]) -> float:
        if not domain_levels:
            return 0.0

        weights = self._risk_matrix_config.get("domain_weights", {})
        level_scores = self._risk_matrix_config.get("level_scores", {})

        weighted_sum = 0.0
        total_weight = 0.0
        for domain, level in domain_levels.items():
            domain_key = str(domain or "unknown").lower()
            domain_weight = float(weights.get(domain_key, weights.get("unknown", 0.5)))
            level_weight = float(level_scores.get(str(level), level_scores.get("low", 0.2)))
            weighted_sum += domain_weight * level_weight
            total_weight += domain_weight

        if total_weight <= 0:
            return 0.0
        return round(weighted_sum / total_weight, 3)

    def _calibrate_risk_with_domain_weight(
        self,
        base_risk: str,
        domain_weight_factor: float,
        cross_domain: bool,
        edge_count: int,
    ) -> Tuple[str, bool]:
        calibration = self._risk_matrix_config.get("calibration", {})
        enabled = bool(calibration.get("enabled", True))
        if not enabled:
            return base_risk, False

        if bool(calibration.get("cross_domain_required", True)) and not cross_domain:
            return base_risk, False

        if bool(calibration.get("edge_required", True)) and edge_count < 1:
            return base_risk, False

        critical_min = float(calibration.get("critical_factor_min", 0.75))
        high_min = float(calibration.get("high_factor_min", 0.55))

        base_idx = self._risk_index(base_risk)
        target_idx = base_idx

        # Domain criticality is a lightweight calibration, capped to one-level uplift.
        if domain_weight_factor >= critical_min and base_idx >= self._risk_index("high"):
            target_idx = min(3, base_idx + 1)
        elif domain_weight_factor >= high_min and base_idx >= self._risk_index("medium"):
            target_idx = min(3, base_idx + 1)

        calibrated = target_idx != base_idx
        return self._risk_from_index(target_idx), calibrated

    def _infer_incident_type(self, attack_types: List[str], domains: set) -> str:
        if len(domains) < 2:
            return "single_domain_incident"

        lateral_markers = {"lateral_movement", "port_scan", "bruteforce", "c2_beacon"}
        theft_markers = {"sensitive_file_access", "credential_dump", "privilege_escalation"}

        if any(t in lateral_markers for t in attack_types):
            return "lateral_penetration"
        if any(t in theft_markers for t in attack_types):
            return "privilege_data_theft"
        return "cross_domain_suspicious"

    def evaluate(self, alerts: List[Dict]) -> Dict:
        if not alerts:
            return {
                "is_cross_domain_attack": False,
                "risk_level": "low",
                "base_risk_level": "low",
                "domain_weight_factor": 0.0,
                "domain_weight_calibrated": False,
                "attack_pattern": "none",
                "incident_type": "none",
                "involved_domains": [],
                "inferred_stage": "unknown",
                "evidence_set": [],
                "incident_graph": {"nodes": [], "edges": [], "summary": {"node_count": 0, "edge_count": 0}},
                "contribution_by_domain": {},
                "confidence_global": "low",
                "confidence": "low",
                "reason": "no alert data",
            }

        grouped: Dict[str, List[Dict]] = {}
        for alert in alerts:
            domain = str(alert.get("domain") or "unknown")
            grouped.setdefault(domain, []).append(alert)

        domains = set(grouped.keys())
        attack_types = [str(a.get("attack_type", "unknown")) for a in alerts]
        dominant_attack = Counter(attack_types).most_common(1)[0][0]
        cross_domain = len(domains) >= 2
        incident_type = self._infer_incident_type(attack_types, domains)

        incident_graph = self._build_incident_graph(alerts, time_window_seconds=5)
        edge_count = int(incident_graph.get("summary", {}).get("edge_count", 0))

        domain_levels = {domain: self._domain_level(items) for domain, items in grouped.items()}
        base_risk, confidence_global = self._global_decision_matrix(domain_levels=domain_levels, edge_count=edge_count)
        domain_weight_factor = self._domain_weight_factor(domain_levels=domain_levels)
        calibrated_risk, calibrated = self._calibrate_risk_with_domain_weight(
            base_risk=base_risk,
            domain_weight_factor=domain_weight_factor,
            cross_domain=cross_domain,
            edge_count=edge_count,
        )

        inferred_stage = self._infer_stage(alerts)

        contribution_by_domain: Dict[str, Dict[str, Any]] = {}
        for domain, items in grouped.items():
            stages = sorted(
                {
                    str(i.get("stage") or i.get("evidence", {}).get("stage") or "recon")
                    for i in items
                }
            )
            contribution_by_domain[domain] = {
                "domain_level": domain_levels.get(domain, "low"),
                "alert_count": len(items),
                "stages": stages,
                "attack_types": sorted({str(i.get("attack_type", "unknown")) for i in items}),
            }

        evidence_set = []
        for edge in incident_graph.get("edges", []):
            key = edge.get("correlation_key", {})
            evidence_set.append(
                {
                    "evidence_type": "cross_domain_correlation",
                    "src_ip": key.get("src_ip", ""),
                    "dst_ip": key.get("dst_ip", ""),
                    "time_window_seconds": key.get("time_window_seconds", 5),
                    "stage_pair": key.get("stage_pair", []),
                }
            )

        return {
            "is_cross_domain_attack": cross_domain,
            "risk_level": calibrated_risk,
            "base_risk_level": base_risk,
            "domain_weight_factor": domain_weight_factor,
            "domain_weight_calibrated": calibrated,
            "attack_pattern": dominant_attack,
            "incident_type": incident_type,
            "involved_domains": sorted(d for d in domains if d),
            "inferred_stage": inferred_stage,
            "evidence_set": evidence_set,
            "incident_graph": incident_graph,
            "contribution_by_domain": contribution_by_domain,
            "confidence_global": confidence_global,
            "confidence": confidence_global,
            "reason": (
                f"decision_matrix domains={len(domains)} edges={edge_count} "
                f"domain_levels={domain_levels} base_risk={base_risk} "
                f"domain_weight_factor={domain_weight_factor} calibrated={calibrated}"
            ),
        }

    def evaluate_with_timing(self, alerts: List[Dict], rules: List[Dict]) -> Dict:
        """
        根据自定义规则配置和时序特征分析告警信息。
        """
        for rule in rules:
            domain_sequence = rule.get("domain_sequence", [])
            time_window = int(rule.get("time_window", 5))

            matched_alerts = []
            for domain in domain_sequence:
                for alert in alerts:
                    if alert.get("domain") == domain:
                        matched_alerts.append(alert)

            if len(matched_alerts) == len(domain_sequence):
                timestamps = [self._parse_ts(a.get("timestamp")) for a in matched_alerts]
                timestamps = [t for t in timestamps if t is not None]
                if len(timestamps) != len(matched_alerts):
                    continue
                if (max(timestamps) - min(timestamps)).total_seconds() <= time_window * 60:
                    return {
                        "is_cross_domain_attack": True,
                        "risk_level": "critical",
                        "attack_pattern": rule.get("attack_pattern", "unknown"),
                        "matched_alerts": matched_alerts,
                    }

        return {
            "is_cross_domain_attack": False,
            "risk_level": "low",
            "attack_pattern": "none",
        }
