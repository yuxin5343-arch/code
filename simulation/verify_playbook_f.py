from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from typing import Any, Dict


PLAYBOOK_ID = "F_portal_bridge_fallback"


def _pick_baseline_mode(data: Dict[str, Any]) -> str:
    by_mode_playbook = data.get("summary", {}).get("by_mode_playbook", {})
    if not isinstance(by_mode_playbook, dict):
        return "single_domain_baseline"
    for mode in ("single_domain_baseline", "no_collab"):
        if mode in by_mode_playbook:
            return mode
    return "single_domain_baseline"


def _latest_result_file() -> str:
    files = sorted(glob.glob("results/experiment_*.json"), key=os.path.getmtime)
    if not files:
        raise FileNotFoundError("No experiment JSON found under results/")
    return files[-1]


def _get_f_metrics(data: Dict[str, Any], mode: str) -> Dict[str, Any]:
    return (
        data.get("summary", {})
        .get("by_mode_playbook", {})
        .get(mode, {})
        .get(PLAYBOOK_ID, {})
    )


def _safe_float(metrics: Dict[str, Any], key: str) -> float:
    try:
        return float(metrics.get(key, 0.0))
    except Exception:
        return 0.0


def _safe_int(metrics: Dict[str, Any], key: str) -> int:
    try:
        return int(metrics.get(key, 0))
    except Exception:
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Quick pass/fail verifier for Playbook F")
    parser.add_argument("--file", default="", help="Path to experiment JSON. Default: latest in results/")
    parser.add_argument("--max-collab-attack-success", type=float, default=0.2)
    parser.add_argument("--min-nocollab-attack-success", type=float, default=0.8)
    parser.add_argument("--min-counter-rate", type=float, default=0.3)
    parser.add_argument("--min-fallback-rate", type=float, default=0.2)
    parser.add_argument("--min-collab-block-rate", type=float, default=0.5)
    args = parser.parse_args()

    path = args.file or _latest_result_file()
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    collab = _get_f_metrics(data, "oneshot_collab")
    baseline_mode = _pick_baseline_mode(data)
    no_collab = _get_f_metrics(data, baseline_mode)

    if not collab or not no_collab:
        print("FAIL: Missing Playbook F metrics in result file")
        print(f"file={path}")
        return 2

    c_attack = _safe_float(collab, "attack_success_rate")
    n_attack = _safe_float(no_collab, "attack_success_rate")
    c_counter = _safe_float(collab, "counter_rate")
    c_fallback = _safe_float(collab, "fallback_rate")
    c_block = _safe_float(collab, "block_rate")

    checks = {
        "collab_attack_success_low": c_attack <= args.max_collab_attack_success,
        "no_collab_attack_success_high": n_attack >= args.min_nocollab_attack_success,
        "counter_triggered": c_counter >= args.min_counter_rate,
        "fallback_triggered": c_fallback >= args.min_fallback_rate,
        "collab_block_effective": c_block >= args.min_collab_block_rate,
    }

    passed = all(checks.values())

    print(f"file={path}")
    print(f"playbook={PLAYBOOK_ID}")
    print(f"baseline_mode={baseline_mode}")
    print("--- metrics ---")
    print(f"oneshot_collab.attack_success_rate={c_attack:.3f}")
    print(f"{baseline_mode}.attack_success_rate={n_attack:.3f}")
    print(f"oneshot_collab.counter_rate={c_counter:.3f}")
    print(f"oneshot_collab.fallback_rate={c_fallback:.3f}")
    print(f"oneshot_collab.block_rate={c_block:.3f}")
    print(f"oneshot_collab.fallback_total={_safe_int(collab, 'fallback_total')}")
    print(f"oneshot_collab.adopt_counter_total={_safe_int(collab, 'adopt_counter_total')}")

    print("--- checks ---")
    for name, ok in checks.items():
        print(f"{name}={'PASS' if ok else 'FAIL'}")

    if passed:
        print("RESULT=PASS")
        return 0

    print("RESULT=FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main())
