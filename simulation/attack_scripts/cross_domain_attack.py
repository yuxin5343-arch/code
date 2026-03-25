from __future__ import annotations

"""跨域攻击仿真脚本。

提供攻击阶段评估、告警样例和简单攻击流程演示函数。
"""

from typing import Dict, List

from simulation.attack_scripts.malicious_behaviors import generate_malicious_behavior_log


STAGE_CHAIN = [
    "initial_access",
    "recon",
    "lateral_movement",
    "core_pivot",
    "impact",
]

CONTAINMENT_OBJECTIVES = {
    "block_ip",
    "tighten_acl",
    "enable_ids_strict",
    "isolate_host",
    "block_traffic",
    "increase_alert_level",
}


def generate_cross_domain_alerts() -> List[Dict]:
    """生成跨域攻击告警样例，供联调或单测使用。"""
    return [
        {
            "domain": "office",
            "device_type": "ids",
            "severity": "high",
            "attack_type": "lateral_movement",
            "src_ip": "10.10.1.23",
            "dst_ip": "10.20.5.8",
            "evidence": {"signature": "SMB-LM-001", "stage": "recon"},
        },
        {
            "domain": "core",
            "device_type": "firewall",
            "severity": "critical",
            "attack_type": "lateral_movement",
            "src_ip": "10.10.1.23",
            "dst_ip": "10.20.9.3",
            "evidence": {"acl_hit": "deny-legacy", "stage": "pivot"},
        },
    ]


def generate_behavior_driven_logs() -> List[Dict]:
    """生成行为脚本驱动的恶意日志样例。"""
    return [
        generate_malicious_behavior_log(
            domain="office",
            event_id="office-behavior-1",
            timestamp="2026-03-24T09:30:00+00:00",
            src_ip="10.10.1.23",
            dst_ip="10.20.5.8",
            device_type="ids",
            profile="privilege_escalation",
        ),
        generate_malicious_behavior_log(
            domain="core",
            event_id="core-behavior-1",
            timestamp="2026-03-24T09:30:10+00:00",
            src_ip="10.10.1.23",
            dst_ip="10.20.9.3",
            device_type="firewall",
            profile="sensitive_file_access",
        ),
    ]


def evaluate_attack_progression(flat_results: List[Dict]) -> Dict:
    """依据任务执行结果评估攻击是否被遏制及所处阶段。"""
    containment_candidates = [
        r for r in flat_results if r.get("objective") in CONTAINMENT_OBJECTIVES and bool(r.get("success", False))
    ]

    if containment_candidates:
        containment_time_ms = min(int(r.get("latency_ms", 0)) for r in containment_candidates)
        contained_domains = {str(r.get("domain", "unknown")) for r in containment_candidates}

        # 双域均完成有效遏制时，认为横向扩散被完全阻断。
        if {"office", "core"}.issubset(contained_domains):
            reached_stages = STAGE_CHAIN[:2]
            return {
                "attack_success": False,
                "attack_success_rate": 0.0,
                "lateral_spread_count": 0,
                "containment_time_ms": containment_time_ms,
                "reached_stages": reached_stages,
                "final_stage": reached_stages[-1],
            }

        reached_stages = STAGE_CHAIN[:3]
        return {
            "attack_success": False,
            "attack_success_rate": 0.0,
            "lateral_spread_count": 1,
            "containment_time_ms": containment_time_ms,
            "reached_stages": reached_stages,
            "final_stage": reached_stages[-1],
        }

    return {
        "attack_success": True,
        "attack_success_rate": 1.0,
        "lateral_spread_count": 3,
        "containment_time_ms": 0,
        "reached_stages": list(STAGE_CHAIN),
        "final_stage": STAGE_CHAIN[-1],
    }


def perform_phishing_attack(target_ip: str):
    print(f"Performing phishing attack on {target_ip}...")
    # 这里可扩展钓鱼攻击模拟逻辑。


def perform_brute_force_attack(target_ip: str):
    print(f"Performing brute force attack on {target_ip}...")
    # 这里可扩展暴力破解模拟逻辑。


def lateral_movement_via_ssh(target_ip: str):
    print(f"Performing lateral movement via SSH to {target_ip}...")
    # 这里可扩展 SSH 横向移动模拟逻辑。


def cross_domain_attack():
    # 阶段 1：攻击办公域。
    office_target = "10.10.1.23"
    perform_phishing_attack(office_target)
    perform_brute_force_attack(office_target)

    # 阶段 2：向核心域执行横向移动。
    core_target = "10.20.5.8"
    lateral_movement_via_ssh(core_target)


if __name__ == "__main__":
    cross_domain_attack()
