from __future__ import annotations

"""恶意行为脚本。

该模块支持在容器内执行“真实行为尝试”（如提权尝试、敏感文件访问尝试），
并将执行结果转换为标准化事件，供现有检测/决策链路消费。
"""

import os
import random
import subprocess
import time
from datetime import datetime, timezone
from typing import Dict, List

# 支持的行为画像名称。
SUPPORTED_PROFILES = {
    "mixed",
    "privilege_escalation",
    "sensitive_file_access",
    "command_execution",
    "credential_dump",
    "persistence_attempt",
}


def _simulate_privilege_escalation() -> Dict:
    return {
        "event_type": "privilege_escalation_attempt",
        "attack_type": "privilege_escalation",
        "stage": "execution",
        "severity": "high",
        "evidence": {
            "indicator": "sudo_abuse",
            "command": "sudo -l && sudo su",
            "result": "permission_denied_or_prompted",
        },
    }


def _simulate_sensitive_file_access() -> Dict:
    return {
        "event_type": "sensitive_file_access_attempt",
        "attack_type": "sensitive_file_access",
        "stage": "collection",
        "severity": "high",
        "evidence": {
            "indicator": "sensitive_path_probe",
            "path": "/etc/shadow",
            "result": "access_denied_or_blocked",
        },
    }


def _simulate_command_execution() -> Dict:
    return {
        "event_type": "suspicious_command_execution",
        "attack_type": "command_execution",
        "stage": "execution",
        "severity": "high",
        "evidence": {
            "indicator": "encoded_or_obfuscated_command",
            "command": "bash -c 'cat /etc/passwd | wc -l'",
            "result": "executed_in_sandbox",
        },
    }


def _simulate_credential_dump() -> Dict:
    return {
        "event_type": "credential_dump_attempt",
        "attack_type": "credential_dump",
        "stage": "credential_access",
        "severity": "critical",
        "evidence": {
            "indicator": "credential_material_access",
            "target": "lsass_or_shadow_like_source",
            "result": "blocked_or_detected",
        },
    }


def _simulate_persistence_attempt() -> Dict:
    return {
        "event_type": "persistence_attempt",
        "attack_type": "persistence",
        "stage": "persistence",
        "severity": "high",
        "evidence": {
            "indicator": "autorun_or_cron_modification",
            "target": "crontab",
            "result": "change_detected",
        },
    }


def _behavior_command(profile: str) -> List[str]:
    """返回行为画像对应的命令（固定白名单）。"""
    commands = {
        # 尝试无密码 sudo，常见于提权探测场景。
        "privilege_escalation": ["sudo", "-n", "id"],
        # 尝试访问敏感文件，但不回传内容。
        "sensitive_file_access": ["sh", "-lc", "cat /etc/shadow > /dev/null"],
        # 可疑命令执行探测（仅做信息查询）。
        "command_execution": ["sh", "-lc", "id && uname -a > /dev/null"],
        # 凭据读取类尝试（仅检测可访问性，不输出数据）。
        "credential_dump": ["sh", "-lc", "grep -E '^(root|daemon):' /etc/passwd > /dev/null"],
        # 持久化行为尝试（尝试写入用户级 crontab）。
        "persistence_attempt": ["sh", "-lc", "echo '* * * * * /bin/true' | crontab -"],
    }
    return commands[profile]


def _run_command(argv: List[str], timeout_sec: float = 2.0) -> Dict:
    """执行命令并返回受控结果。"""
    t0 = time.perf_counter()
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        return {
            "exit_code": int(completed.returncode),
            "timed_out": False,
            "latency_ms": elapsed_ms,
            "stdout": (completed.stdout or "")[:200],
            "stderr": (completed.stderr or "")[:200],
            "error": None,
        }
    except subprocess.TimeoutExpired as exc:
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        return {
            "exit_code": 124,
            "timed_out": True,
            "latency_ms": elapsed_ms,
            "stdout": ((exc.stdout or "") if isinstance(exc.stdout, str) else "")[:200],
            "stderr": ((exc.stderr or "") if isinstance(exc.stderr, str) else "")[:200],
            "error": "timeout",
        }
    except FileNotFoundError:
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        return {
            "exit_code": 127,
            "timed_out": False,
            "latency_ms": elapsed_ms,
            "stdout": "",
            "stderr": "command not found",
            "error": "command_not_found",
        }


def _resolve_profile(profile: str) -> str:
    if profile in SUPPORTED_PROFILES:
        return profile
    return "mixed"


def _pick_behavior(profile: str, rng: random.Random | None = None) -> Dict:
    rng_obj = rng or random
    mapping = {
        "privilege_escalation": _simulate_privilege_escalation,
        "sensitive_file_access": _simulate_sensitive_file_access,
        "command_execution": _simulate_command_execution,
        "credential_dump": _simulate_credential_dump,
        "persistence_attempt": _simulate_persistence_attempt,
    }

    normalized = _resolve_profile(profile)
    if normalized == "mixed":
        return rng_obj.choice(list(mapping.values()))()
    return mapping[normalized]()


def generate_malicious_behavior_log(
    domain: str,
    event_id: str,
    timestamp: str,
    src_ip: str,
    dst_ip: str,
    device_type: str,
    profile: str = "mixed",
    rng: random.Random | None = None,
) -> Dict:
    """生成一条标准化恶意行为日志。"""
    behavior = _pick_behavior(profile, rng=rng)
    return {
        "id": event_id,
        "timestamp": timestamp,
        "domain": domain,
        "device_type": device_type,
        "event_type": behavior["event_type"],
        "attack_type": behavior["attack_type"],
        "stage": behavior["stage"],
        "severity": behavior["severity"],
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "suspicious": True,
        "evidence": {
            **behavior.get("evidence", {}),
            "simulated": True,
            "script": "malicious_behaviors",
        },
    }


def execute_malicious_behavior_attempt(
    domain: str,
    event_id: str,
    src_ip: str,
    dst_ip: str,
    device_type: str,
    profile: str = "mixed",
    rng: random.Random | None = None,
) -> Dict:
    """在当前容器内执行一次行为尝试并返回标准化事件。"""
    rng_obj = rng or random
    normalized = _resolve_profile(profile)
    if normalized == "mixed":
        normalized = rng_obj.choice(
            [
                "privilege_escalation",
                "sensitive_file_access",
                "command_execution",
                "credential_dump",
                "persistence_attempt",
            ]
        )

    behavior_meta = _pick_behavior(normalized, rng=rng_obj)
    command = _behavior_command(normalized)
    result = _run_command(command)

    # 非零退出码并不意味着无价值，很多“尝试”本身就会被拒绝。
    suspicious = True
    severity = behavior_meta["severity"]
    if result["exit_code"] == 0 and normalized in {"sensitive_file_access", "credential_dump"}:
        severity = "critical"

    return {
        "id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        "device_type": device_type,
        "event_type": behavior_meta["event_type"],
        "attack_type": behavior_meta["attack_type"],
        "stage": behavior_meta["stage"],
        "severity": severity,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "suspicious": suspicious,
        "evidence": {
            **behavior_meta.get("evidence", {}),
            "simulated": False,
            "script": "malicious_behaviors",
            "command": " ".join(command),
            "exit_code": result["exit_code"],
            "timed_out": result["timed_out"],
            "latency_ms": result["latency_ms"],
            "stderr": result["stderr"],
            "stdout": result["stdout"],
            "error": result["error"],
            "container_user": os.getenv("USER", "unknown"),
        },
    }


def list_supported_profiles() -> List[str]:
    """返回可用的行为画像列表。"""
    return sorted(SUPPORTED_PROFILES)
