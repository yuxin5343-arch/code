from __future__ import annotations

import random
import time
from typing import Dict


class DeviceController:
    """异构设备控制适配层（当前为模拟实现）。"""

    def execute(self, device_type: str, command: str, params: Dict) -> Dict:
        start = time.perf_counter()

        # 模拟设备控制耗时与偶发失败
        latency = random.randint(20, 120)
        success = random.random() > 0.08

        elapsed_ms = int((time.perf_counter() - start) * 1000) + latency
        return {
            "success": success,
            "latency_ms": elapsed_ms,
            "device_type": device_type,
            "command": command,
            "params": params,
        }
