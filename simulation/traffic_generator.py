from __future__ import annotations

"""仿真流量生成器。

用于构造不同域的正常/攻击日志，供实验注入与联动测试。
"""

import random
from datetime import datetime, timedelta, timezone
from typing import Dict, List

from simulation.attack_scripts.malicious_behaviors import generate_malicious_behavior_log


class TrafficGenerator:
    def __init__(
        self,
        rng: random.Random | None = None,
        attack_mix_threshold: float = 0.45,
        scripted_attack_threshold: float = 0.25,
    ) -> None:
        self.rng = rng or random.Random()
        self.attack_mix_threshold = float(attack_mix_threshold)
        self.scripted_attack_threshold = float(scripted_attack_threshold)

    def generate_local_logs(
        self,
        domain: str,
        attack: bool = False,
        count: int = 20,
        attack_profile: str = "mixed",
    ) -> List[Dict]:
        """按域生成日志序列。

        参数:
        - domain: 网络域名称，如 office/core。
        - attack: 是否混入攻击事件。
        - count: 生成日志条数。
        - attack_profile: 恶意行为画像（mixed/privilege_escalation/sensitive_file_access/command_execution）。
        """
        events = []
        benign_events = ["dns_query", "http_request", "ssh_login", "file_access"]
        attack_events = ["port_scan", "lateral_movement", "bruteforce", "c2_beacon"]
        base_time = datetime.now(timezone.utc)

        src_ip = "10.10.1.23"
        dst_ip = "10.20.5.8" if domain == "office" else "10.20.9.3"
        device_type = "ids" if domain == "office" else "firewall"

        for idx in range(count):
            event_id = f"{domain}-{idx}"
            event_time = (base_time + timedelta(milliseconds=idx * 120)).isoformat()
            # attack=True 时以一定概率混入攻击事件，模拟真实流量中的攻击噪声。
            if attack and self.rng.random() > self.attack_mix_threshold:
                # 优先使用“行为脚本”产生日志，少量保留通用攻击事件用于背景噪声。
                if self.rng.random() > self.scripted_attack_threshold:
                    events.append(
                        generate_malicious_behavior_log(
                            domain=domain,
                            event_id=event_id,
                            timestamp=event_time,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            device_type=device_type,
                            profile=attack_profile,
                            rng=self.rng,
                        )
                    )
                else:
                    et = self.rng.choice(attack_events)
                    events.append(
                        {
                            "id": event_id,
                            "timestamp": event_time,
                            "domain": domain,
                            "device_type": device_type,
                            "event_type": et,
                            "attack_type": "lateral_movement",
                            "stage": "pivot" if domain == "core" else "recon",
                            "severity": "critical" if domain == "core" else "high",
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "suspicious": True,
                            "evidence": {"simulated": True, "source": "legacy_attack_pattern"},
                        }
                    )
            else:
                et = self.rng.choice(benign_events)
                events.append(
                    {
                        "id": event_id,
                        "timestamp": event_time,
                        "domain": domain,
                        "device_type": device_type,
                        "event_type": et,
                        "severity": "low",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "suspicious": False,
                    }
                )
        return events
