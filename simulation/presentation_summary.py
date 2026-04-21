from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parent.parent))

from simulation.report_generator import generate_report


PLAYBOOK_ORDER = [
    "A_happy_path",
    "D_cross_domain_weak_signal",
    "B_critical_asset_counter",
    "E_false_positive_noise",
    "C_budget_exhaustion",
    "F_portal_bridge_fallback",
    "G_single_domain_baseline_validation",
]

PLAYBOOK_LABEL = {
    "A_happy_path": "场景A",
    "D_cross_domain_weak_signal": "场景B",
    "B_critical_asset_counter": "场景C",
    "E_false_positive_noise": "场景D",
    "C_budget_exhaustion": "场景E",
    "F_portal_bridge_fallback": "场景F",
    "G_single_domain_baseline_validation": "场景G",
}


def _pick_baseline_mode(bmp: Dict[str, Any]) -> str:
    for mode in ("single_domain_baseline", "no_collab"):
        if mode in bmp:
            return mode
    return "single_domain_baseline"


def _latest_result_file() -> Path:
    files = sorted(glob.glob("results/experiment_*.json"), key=os.path.getmtime)
    if not files:
        raise FileNotFoundError("No experiment JSON found under results/")
    return Path(files[-1])


def _metric(obj: Dict[str, Any], key: str) -> float:
    try:
        return float(obj.get(key, 0.0))
    except Exception:
        return 0.0


def _rows(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    bmp = data.get("summary", {}).get("by_mode_playbook", {})
    collab = bmp.get("oneshot_collab", {}) if isinstance(bmp, dict) else {}
    baseline_mode = _pick_baseline_mode(bmp if isinstance(bmp, dict) else {})
    no_collab = bmp.get(baseline_mode, {}) if isinstance(bmp, dict) else {}
    ids = [pid for pid in PLAYBOOK_ORDER if pid in set(collab.keys()) | set(no_collab.keys())]

    rows: List[Dict[str, Any]] = []
    for pid in ids:
        c = collab.get(pid, {}) if isinstance(collab.get(pid, {}), dict) else {}
        n = no_collab.get(pid, {}) if isinstance(no_collab.get(pid, {}), dict) else {}
        c_attack = _metric(c, "attack_success_rate")
        n_attack = _metric(n, "attack_success_rate")
        rows.append(
            {
                "playbook": pid,
                "scene": PLAYBOOK_LABEL.get(pid, pid),
                "c_attack": c_attack,
                "n_attack": n_attack,
                "delta": n_attack - c_attack,
                "counter": _metric(c, "counter_rate"),
                "fallback": _metric(c, "fallback_rate"),
                "block": _metric(c, "block_rate"),
                "baseline_mode": baseline_mode,
            }
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate demo-friendly summary and report")
    parser.add_argument("--file", default="", help="experiment json path; default latest")
    args = parser.parse_args()

    path = Path(args.file) if args.file else _latest_result_file()
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    rows = _rows(data)
    print(f"[demo] source={path}")
    print(f"[demo] total_samples={int(data.get('total_samples', 0))}")
    baseline_mode = rows[0].get("baseline_mode", "single_domain_baseline") if rows else "single_domain_baseline"
    print("\n[demo] playbook verdicts")
    print(f"scene                                  collab_attack  {baseline_mode}_attack  delta    verdict")
    print("----------------------------------------------------------------------------------------------")
    for r in rows:
        verdict = "PASS" if float(r["delta"]) > 0 else "CHECK"
        print(
            f"{r['scene']:<38} {r['c_attack']:<13.3f} {r['n_attack']:<16.3f} {r['delta']:<7.3f} {verdict}"
        )

    out = path.with_name(path.name.replace("experiment_", "presentation_").replace(".json", ".html"))
    generate_report(data, out)
    print(f"\n[demo] html={out.resolve()}")


if __name__ == "__main__":
    main()
