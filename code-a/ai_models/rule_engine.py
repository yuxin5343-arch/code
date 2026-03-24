from __future__ import annotations

from collections import Counter
from typing import Dict, List
from datetime import datetime, timedelta


class RuleEngine:
    """基于规则的跨域攻击研判引擎。"""

    def evaluate(self, alerts: List[Dict]) -> Dict:
        if not alerts:
            return {
                "is_cross_domain_attack": False,
                "risk_level": "low",
                "attack_pattern": "none",
                "reason": "no alert data",
            }

        domains = {a.get("domain") for a in alerts}
        attack_types = [a.get("attack_type", "unknown") for a in alerts]
        severity_counter = Counter(a.get("severity", "low") for a in alerts)

        dominant_attack = Counter(attack_types).most_common(1)[0][0]
        high_count = severity_counter.get("high", 0) + severity_counter.get("critical", 0)
        cross_domain = len(domains) >= 2

        if cross_domain and high_count >= 2:
            risk = "critical"
        elif cross_domain or high_count >= 1:
            risk = "high"
        else:
            risk = "medium"

        return {
            "is_cross_domain_attack": cross_domain,
            "risk_level": risk,
            "attack_pattern": dominant_attack,
            "reason": f"domains={len(domains)}, high_like_alerts={high_count}",
        }

    def evaluate_with_timing(self, alerts: List[Dict], rules: List[Dict]) -> Dict:
        """
        根据自定义规则配置和时序特征分析告警信息。
        """
        for rule in rules:
            domain_sequence = rule.get("domain_sequence", [])
            time_window = rule.get("time_window", 5)  # 默认时间窗口为5分钟

            matched_alerts = []
            for domain in domain_sequence:
                for alert in alerts:
                    if alert.get("domain") == domain:
                        matched_alerts.append(alert)

            if len(matched_alerts) == len(domain_sequence):
                timestamps = [datetime.strptime(a["timestamp"], "%Y-%m-%d %H:%M:%S") for a in matched_alerts]
                if max(timestamps) - min(timestamps) <= timedelta(minutes=time_window):
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
