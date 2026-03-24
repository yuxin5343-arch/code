from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Dict, List


class TrafficGenerator:
    def generate_local_logs(self, domain: str, attack: bool = False, count: int = 20) -> List[Dict]:
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
            if attack and random.random() > 0.45:
                et = random.choice(attack_events)
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
                    }
                )
            else:
                et = random.choice(benign_events)
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
