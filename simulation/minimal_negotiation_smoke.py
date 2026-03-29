from __future__ import annotations

"""一轮协商最小联调脚本。

用途：
1) 检查 manager / executor 健康状态。
2) 注入两条可关联的跨域告警。
3) 触发 manager 决策，验证 one-shot negotiation（intent -> consensus）。
"""

import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent.parent))

from communication.async_client import AsyncAPIClient

MANAGER = os.getenv("MANAGER_SERVICE", "http://127.0.0.1:8000")
OFFICE_EXECUTOR = os.getenv("EXECUTOR_OFFICE_SERVICE", "http://127.0.0.1:8101")
CORE_EXECUTOR = os.getenv("EXECUTOR_CORE_SERVICE", "http://127.0.0.1:8102")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _check_health(client: AsyncAPIClient, endpoint: str, role: str) -> None:
    health = await client.get_json(f"{endpoint}/health")
    if str(health.get("status", "")) != "ok":
        raise RuntimeError(f"{role} health check failed: {health}")
    print(f"[health] {role}: ok")


def _build_alert(domain: str, attack_type: str, stage: str, src_ip: str, dst_ip: str) -> Dict[str, Any]:
    alert_payload = {
        "alert_id": f"smoke-{domain}-{attack_type}-{int(datetime.now(timezone.utc).timestamp())}",
        "domain": domain,
        "device_type": "ids" if domain == "office" else "firewall",
        "severity": "high" if domain == "office" else "medium",
        "attack_type": attack_type,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "timestamp": _now_iso(),
        "stage": stage,
        "evidence": {"event_type": attack_type, "stage": stage},
    }
    return {
        "message_type": "alert",
        "source": f"executor-{domain}",
        "target": "manager",
        "payload": alert_payload,
    }


def _extract_statuses(dispatch_block: List[Dict[str, Any]]) -> List[str]:
    statuses: List[str] = []
    for item in dispatch_block:
        for result in item.get("results", []):
            statuses.append(str(result.get("status", "unknown")))
    return statuses


async def main() -> int:
    client = AsyncAPIClient(timeout=10.0)

    print("=== One-Shot Negotiation Smoke Test ===")
    print(f"manager={MANAGER}")
    print(f"office_executor={OFFICE_EXECUTOR}")
    print(f"core_executor={CORE_EXECUTOR}")

    try:
        await _check_health(client, MANAGER, "manager")
        await _check_health(client, OFFICE_EXECUTOR, "executor-office")
        await _check_health(client, CORE_EXECUTOR, "executor-core")
    except Exception as exc:
        print(f"[error] service not ready: {exc}")
        return 2

    src_ip = "10.10.1.77"
    dst_ip = "10.20.9.9"

    alerts = [
        _build_alert("office", "lateral_movement", "lateral_movement", src_ip=src_ip, dst_ip=dst_ip),
        _build_alert("core", "privilege_escalation", "privilege_escalation", src_ip=src_ip, dst_ip=dst_ip),
    ]

    for msg in alerts:
        await client.post_json(f"{MANAGER}/alerts", msg)
    print(f"[inject] alerts sent: {len(alerts)}")

    decision = await client.post_json(
        f"{MANAGER}/decision/trigger",
        {"enforce_actions": True, "clear_alerts": True},
    )

    negotiation = decision.get("negotiation", {}) if isinstance(decision, dict) else {}
    intent_dispatch = negotiation.get("intent_dispatch", []) if isinstance(negotiation, dict) else []
    consensus_dispatch = negotiation.get("consensus_dispatch", []) if isinstance(negotiation, dict) else []

    print("=== Negotiation Summary ===")
    print(f"mode={negotiation.get('mode', 'unknown')}")
    print(f"max_rounds={negotiation.get('max_rounds', 'unknown')}")
    print(f"timeout_ms={negotiation.get('timeout_ms', 'unknown')}")
    print(f"intent_statuses={_extract_statuses(intent_dispatch)}")
    print(f"consensus_statuses={_extract_statuses(consensus_dispatch)}")

    incident_id = decision.get("incident_id", "")
    risk = decision.get("analysis", {}).get("risk_level", "unknown")
    stage = decision.get("analysis", {}).get("inferred_stage", "unknown")
    print(f"incident_id={incident_id}")
    print(f"analysis_risk={risk}, inferred_stage={stage}")

    print("[done] smoke test completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
