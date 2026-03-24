from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List


class LocalAnalyzer:
    """执行器本地日志研判。"""

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
        for log in local_logs[-50:]:
            if log.get("suspicious", False):
                alerts.append(self.generate_alert(log))

        if alerts:
            return {
                "confidence": 0.9,
                "recommended": True,
                "alerts": alerts,
                "reason": "suspicious activity detected",
            }

        return {
            "confidence": 0.5,
            "recommended": True,
            "alerts": [],
            "reason": "no suspicious activity",
        }
