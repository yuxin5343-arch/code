from __future__ import annotations

from typing import Dict, List


STAGE_CHAIN = [
    "initial_access",
    "recon",
    "lateral_movement",
    "core_pivot",
    "impact",
]

CONTAINMENT_OBJECTIVES = {"block_ip", "tighten_acl", "enable_ids_strict"}


def generate_cross_domain_alerts() -> List[Dict]:
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


def evaluate_attack_progression(flat_results: List[Dict]) -> Dict:
    containment_candidates = [
        r for r in flat_results if r.get("objective") in CONTAINMENT_OBJECTIVES and bool(r.get("success", False))
    ]

    if containment_candidates:
        containment_time_ms = min(int(r.get("latency_ms", 0)) for r in containment_candidates)
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
    # Simulate phishing attack logic here


def perform_brute_force_attack(target_ip: str):
    print(f"Performing brute force attack on {target_ip}...")
    # Simulate brute force attack logic here


def lateral_movement_via_ssh(target_ip: str):
    print(f"Performing lateral movement via SSH to {target_ip}...")
    # Simulate SSH lateral movement logic here


def cross_domain_attack():
    # Phase 1: Attack office network
    office_target = "10.10.1.23"
    perform_phishing_attack(office_target)
    perform_brute_force_attack(office_target)

    # Phase 2: Lateral movement to core network
    core_target = "10.20.5.8"
    lateral_movement_via_ssh(core_target)


if __name__ == "__main__":
    cross_domain_attack()
