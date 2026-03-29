from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List


class LocalAnalyzer:
    """执行器本地日志研判。"""

    def __init__(
        self,
        max_block_actions: int = 5,
        failure_threshold: int = 3,
        business_whitelist_assets: List[str] | None = None,
    ) -> None:
        self.max_block_actions = max(1, int(max_block_actions))
        self.failure_threshold = max(1, int(failure_threshold))
        self.business_whitelist_assets = set(business_whitelist_assets or [])

        self.risk_score = 20.0
        self.confidence = 0.35
        self.top_alert_types: List[str] = []
        self.proposed_action = "observe_alert"
        self.resource_status = {
            "max_block_actions": self.max_block_actions,
            "used_block_actions": 0,
            "consecutive_failures": 0,
            "failure_threshold": self.failure_threshold,
            "business_whitelist_assets": sorted(self.business_whitelist_assets),
        }

    @staticmethod
    def _risk_from_logs(suspicious_count: int, critical_count: int) -> tuple[float, float]:
        # 毕设原型使用静态查表，避免引入重模型。
        if critical_count >= 1:
            return 85.0, 0.90
        if suspicious_count >= 5:
            return 70.0, 0.75
        if suspicious_count >= 1:
            return 45.0, 0.60
        return 20.0, 0.35

    @staticmethod
    def _proposed_action_from_risk(risk_score: float) -> str:
        if risk_score >= 80:
            return "isolate_host"
        if risk_score >= 50:
            return "block_traffic"
        return "raise_monitoring"

    def get_local_situation(self) -> Dict:
        return {
            "risk_score": round(float(self.risk_score), 2),
            "confidence": round(float(self.confidence), 2),
            "top_alert_types": list(self.top_alert_types),
            "resource_status": dict(self.resource_status),
            "proposed_action": self.proposed_action,
        }

    def record_task_outcome(self, action: str, success: bool) -> None:
        if action in {"block_traffic", "isolate_host"}:
            used = int(self.resource_status.get("used_block_actions", 0)) + 1
            self.resource_status["used_block_actions"] = used

        if success:
            self.resource_status["consecutive_failures"] = 0
        else:
            fails = int(self.resource_status.get("consecutive_failures", 0)) + 1
            self.resource_status["consecutive_failures"] = fails

        if int(self.resource_status.get("consecutive_failures", 0)) >= self.failure_threshold:
            self.proposed_action = "observe_alert"

    def generate_alert(self, log: Dict) -> Dict:
        """
        根据日志生成标准化告警。
        """
        domain = log.get("domain", "unknown")
        attack_type = log.get("attack_type") or log.get("event_type", "unknown")
        log_id = log.get("id") or f"{domain}-{attack_type}-{log.get('timestamp', 'na')}"
        return {
            "alert_id": f"alert-{log_id}",
            "domain": domain,
            "device_type": log.get("device_type", "ids"),
            "severity": log.get("severity", "high"),
            "attack_type": attack_type,
            "src_ip": log.get("src_ip", "10.10.1.23"),
            "dst_ip": log.get("dst_ip", "10.20.5.8"),
            "timestamp": log.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "evidence": {
                "event_type": log.get("event_type", "unknown"),
                "stage": log.get("stage", "recon"),
            },
            "details": log,
        }

    def analyze(self, local_logs: List[Dict], task_objective: str) -> Dict:
        """
        分析本地日志并生成告警。
        """
        alerts = []
        recent_logs = local_logs[-50:]
        for log in local_logs[-50:]:
            if log.get("suspicious", False):
                alerts.append(self.generate_alert(log))

        suspicious_count = sum(1 for log in recent_logs if bool(log.get("suspicious", False)))
        critical_count = sum(1 for log in recent_logs if str(log.get("severity", "")).lower() == "critical")
        attack_counter = Counter(str(log.get("attack_type") or log.get("event_type") or "unknown") for log in recent_logs)
        self.top_alert_types = [k for k, _v in attack_counter.most_common(3)]
        self.risk_score, self.confidence = self._risk_from_logs(suspicious_count, critical_count)

        if int(self.resource_status.get("consecutive_failures", 0)) >= self.failure_threshold:
            self.proposed_action = "observe_alert"
        else:
            self.proposed_action = self._proposed_action_from_risk(self.risk_score)

        if alerts:
            return {
                "risk_score": self.risk_score,
                "confidence": self.confidence,
                "recommended": True,
                "alerts": alerts,
                "reason": "suspicious activity detected",
                "local_situation": self.get_local_situation(),
            }

        return {
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "recommended": True,
            "alerts": [],
            "reason": "no suspicious activity",
            "local_situation": self.get_local_situation(),
        }
