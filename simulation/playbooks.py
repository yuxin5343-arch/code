from __future__ import annotations

"""Deterministic experiment playbooks.

Each playbook defines reproducible logs and optional preconditions so experiments
can be replayed with small timing jitter for statistical evaluation.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List


@dataclass(frozen=True)
class PlaybookEvent:
    domain: str
    device_type: str
    event_type: str
    attack_type: str
    stage: str
    severity: str
    src_ip: str
    dst_ip: str
    suspicious: bool
    is_malicious: bool = True
    asset_level: str = "normal"
    asset_id: str = ""


@dataclass(frozen=True)
class Playbook:
    playbook_id: str
    title: str
    objective: str
    notes: str
    preconditions: Dict[str, Dict] = field(default_factory=dict)
    events: List[PlaybookEvent] = field(default_factory=list)


def _event_timestamp(base_time: datetime, offset_ms: int, jitter_ms: int) -> str:
    ts = base_time + timedelta(milliseconds=offset_ms + jitter_ms)
    return ts.isoformat()


def build_log(event: PlaybookEvent, run_id: str, index: int, timestamp: str) -> Dict:
    return {
        "id": f"{run_id}-{event.domain}-{index}",
        "timestamp": timestamp,
        "domain": event.domain,
        "device_type": event.device_type,
        "event_type": event.event_type,
        "attack_type": event.attack_type,
        "stage": event.stage,
        "severity": event.severity,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "suspicious": event.suspicious,
        "is_malicious": event.is_malicious,
        "asset_level": event.asset_level,
        "asset_id": event.asset_id,
        "evidence": {
            "stage": event.stage,
            "playbook": True,
        },
    }


def materialize_playbook_events(
    playbook: Playbook,
    run_id: str,
    jitter_ms_by_event: List[int],
    base_time: datetime | None = None,
) -> List[Dict]:
    now = base_time or datetime.now(timezone.utc)
    logs: List[Dict] = []
    for idx, event in enumerate(playbook.events):
        jitter_ms = jitter_ms_by_event[idx] if idx < len(jitter_ms_by_event) else 0
        timestamp = _event_timestamp(now, offset_ms=idx * 700, jitter_ms=jitter_ms)
        logs.append(build_log(event=event, run_id=run_id, index=idx, timestamp=timestamp))
    return logs


def load_playbooks() -> List[Playbook]:
    return [
        Playbook(
            playbook_id="A_happy_path",
            title="场景A：无分歧协同（Happy Path）",
            objective="验证协商链路闭环与可接受时延",
            notes="普通资产，不触发关键资产保护或资源约束。",
            events=[
                PlaybookEvent(
                    domain="office",
                    device_type="ids",
                    event_type="port_scan",
                    attack_type="lateral_movement",
                    stage="recon",
                    severity="high",
                    src_ip="10.10.1.23",
                    dst_ip="10.20.5.8",
                    suspicious=True,
                    asset_level="normal",
                    asset_id="office-web-1",
                ),
                PlaybookEvent(
                    domain="core",
                    device_type="firewall",
                    event_type="lateral_movement",
                    attack_type="lateral_movement",
                    stage="lateral_movement",
                    severity="critical",
                    src_ip="10.10.1.23",
                    dst_ip="10.20.9.3",
                    suspicious=True,
                    asset_level="normal",
                    asset_id="core-app-1",
                ),
            ],
        ),
        Playbook(
            playbook_id="D_cross_domain_weak_signal",
            title="场景B：三节点微弱信号叠加提权",
            objective="验证 Portal -> Office -> Core 的弱信号链可提前触发全局提权阻断",
            notes="黑客先在 Portal 低危扫描，再对 Office 低危爆破，最后探测 Core；三节点弱信号叠加后应提前提权，体现防御前置。",
            events=[
                PlaybookEvent(
                    domain="portal",
                    device_type="ids",
                    event_type="port_scan",
                    attack_type="port_scan",
                    stage="recon",
                    severity="medium",
                    src_ip="45.66.77.88",
                    dst_ip="172.30.10.20",
                    suspicious=True,
                    asset_level="normal",
                    asset_id="portal-edge-1",
                ),
                PlaybookEvent(
                    domain="office",
                    device_type="ids",
                    event_type="bruteforce",
                    attack_type="bruteforce",
                    stage="recon",
                    severity="medium",
                    src_ip="45.66.77.88",
                    dst_ip="10.20.5.30",
                    suspicious=True,
                    asset_level="normal",
                    asset_id="office-auth-1",
                ),
                PlaybookEvent(
                    domain="core",
                    device_type="firewall",
                    event_type="port_scan",
                    attack_type="port_scan",
                    stage="recon",
                    severity="medium",
                    src_ip="45.66.77.88",
                    dst_ip="10.20.9.7",
                    suspicious=True,
                    asset_level="normal",
                    asset_id="core-api-1",
                ),
            ],
        ),
        Playbook(
            playbook_id="B_critical_asset_counter",
            title="场景C：关键资产保护触发反提案",
            objective="验证执行器依据局部代价约束触发反提案",
            notes="Core 资产标记 critical，隔离/ACL 收紧会触发 counter_proposal。",
            preconditions={
                "office": {
                    "resource_status": {
                        "used_block_actions": "max",
                    },
                    "report_manager": False,
                }
            },
            events=[
                PlaybookEvent(
                    domain="office",
                    device_type="ids",
                    event_type="privilege_escalation",
                    attack_type="privilege_escalation",
                    stage="privilege_escalation",
                    severity="high",
                    src_ip="10.66.1.10",
                    dst_ip="10.20.5.10",
                    suspicious=True,
                    asset_level="normal",
                    asset_id="office-jump-1",
                ),
                PlaybookEvent(
                    domain="core",
                    device_type="firewall",
                    event_type="sensitive_file_access",
                    attack_type="sensitive_file_access",
                    stage="sensitive_file_access",
                    severity="critical",
                    src_ip="10.66.1.10",
                    dst_ip="10.20.9.12",
                    suspicious=True,
                    asset_level="critical",
                    asset_id="core-db",
                ),
            ],
        ),
        Playbook(
            playbook_id="E_false_positive_noise",
            title="场景D：误报拦截（纯噪音）",
            objective="验证协同可识别低置信度跨域噪音并拒绝阻断",
            notes="注入高频但良性的噪音告警，跨域无关联边，Manager 应抑制阻断动作。",
            events=[
                PlaybookEvent(
                    domain="office",
                    device_type="ids",
                    event_type="asset_inventory_scan",
                    attack_type="port_scan",
                    stage="recon",
                    severity="high",
                    src_ip="10.11.1.10",
                    dst_ip="10.20.5.70",
                    suspicious=True,
                    is_malicious=False,
                    asset_level="normal",
                    asset_id="office-asset-scanner",
                ),
                PlaybookEvent(
                    domain="office",
                    device_type="ids",
                    event_type="vuln_baseline_probe",
                    attack_type="bruteforce",
                    stage="recon",
                    severity="high",
                    src_ip="10.11.1.10",
                    dst_ip="10.20.5.71",
                    suspicious=True,
                    is_malicious=False,
                    asset_level="normal",
                    asset_id="office-asset-scanner",
                ),
                PlaybookEvent(
                    domain="core",
                    device_type="firewall",
                    event_type="backup_health_check",
                    attack_type="port_scan",
                    stage="recon",
                    severity="high",
                    src_ip="10.12.2.20",
                    dst_ip="10.20.9.80",
                    suspicious=True,
                    is_malicious=False,
                    asset_level="normal",
                    asset_id="core-backup-agent",
                ),
            ],
        ),
        Playbook(
            playbook_id="C_budget_exhaustion",
            title="场景E：资源受限协同",
            objective="验证资源预算耗尽时系统仍能给出兜底决策",
            notes="先耗尽 office 的 block 预算，再注入攻击。",
            preconditions={
                "office": {
                    "resource_status": {
                        "used_block_actions": "max",
                    },
                    "report_manager": False,
                }
            },
            events=[
                PlaybookEvent(
                    domain="office",
                    device_type="ids",
                    event_type="port_scan",
                    attack_type="lateral_movement",
                    stage="recon",
                    severity="high",
                    src_ip="10.88.9.2",
                    dst_ip="10.20.5.8",
                    suspicious=True,
                    asset_level="normal",
                    asset_id="office-endpoint-9",
                ),
                PlaybookEvent(
                    domain="core",
                    device_type="firewall",
                    event_type="lateral_movement",
                    attack_type="lateral_movement",
                    stage="lateral_movement",
                    severity="critical",
                    src_ip="10.88.9.2",
                    dst_ip="10.20.9.3",
                    suspicious=True,
                    asset_level="normal",
                    asset_id="core-app-2",
                ),
            ],
        ),
        Playbook(
            playbook_id="F_portal_bridge_fallback",
            title="场景F：门户跳板与跨域兜底协同",
            objective="验证 office 关键资产拒绝后，Manager 可改派 portal 做源头阻断",
            notes="Portal 先被公网攻破并作为跳板攻击 Office OA；Office 因关键网关白名单拒绝 block_ip，Manager 触发 portal 侧兜底。",
            preconditions={
                "office": {
                    "resource_status": {
                        "business_whitelist_assets": ["office-oa-gateway"],
                    },
                    "report_manager": True,
                }
            },
            events=[
                PlaybookEvent(
                    domain="portal",
                    device_type="firewall",
                    event_type="public_rce",
                    attack_type="c2_beacon",
                    stage="initial_access",
                    severity="critical",
                    src_ip="45.77.13.66",
                    dst_ip="172.30.10.10",
                    suspicious=True,
                    asset_level="critical",
                    asset_id="portal-web",
                ),
                PlaybookEvent(
                    domain="office",
                    device_type="ids",
                    event_type="oa_gateway_probe",
                    attack_type="lateral_movement",
                    stage="lateral_movement",
                    severity="critical",
                    src_ip="45.77.13.66",
                    dst_ip="10.20.5.20",
                    suspicious=True,
                    asset_level="critical",
                    asset_id="office-oa-gateway",
                ),
                PlaybookEvent(
                    domain="office",
                    device_type="ids",
                    event_type="oa_rce_attempt",
                    attack_type="lateral_movement",
                    stage="command_execution",
                    severity="critical",
                    src_ip="45.77.13.66",
                    dst_ip="10.20.5.21",
                    suspicious=True,
                    asset_level="normal",
                    asset_id="office-oa-app",
                ),
            ],
        ),
    ]
