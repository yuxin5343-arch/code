from __future__ import annotations

import argparse
import glob
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Sequence

import matplotlib.pyplot as plt
import seaborn as sns


PLAYBOOK_ORDER = [
    "A_happy_path",
    "D_cross_domain_weak_signal",
    "B_critical_asset_counter",
    "E_false_positive_noise",
    "C_budget_exhaustion",
    "F_portal_bridge_fallback",
]

PLAYBOOK_LABEL = {
    "A_happy_path": "基线协同场景",
    "B_critical_asset_counter": "关键资产约束场景",
    "C_budget_exhaustion": "资源受限场景",
    "D_cross_domain_weak_signal": "弱信号提权场景",
    "E_false_positive_noise": "噪声抑制场景",
    "F_portal_bridge_fallback": "跨域补偿场景",
}

SCENE_LABEL_PAPER = {
    "A_happy_path": "场景A：无分歧协同",
    "B_critical_asset_counter": "场景B：关键资产约束",
    "C_budget_exhaustion": "场景C：资源受限",
    "D_cross_domain_weak_signal": "场景D：弱信号提权",
    "E_false_positive_noise": "场景E：噪声抑制",
    "F_portal_bridge_fallback": "场景F：跨域补偿",
}

MODE_LABEL = {
    "oneshot_collab": "协同模式",
    "single_domain_baseline": "单域基线模式",
}

STAGE_ORDER = ["initial_access", "recon", "lateral_movement", "core_pivot", "impact"]
STAGE_LABEL = {
    "initial_access": "初始入侵",
    "recon": "侦察探测",
    "lateral_movement": "横向移动",
    "core_pivot": "核心枢纽突破",
    "impact": "达成影响",
}

ROOT_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT_DIR / "results"


def _latest_result_file() -> Path:
    files = sorted(glob.glob(str(RESULTS_DIR / "experiment_*.json")), key=os.path.getmtime)
    if not files:
        raise FileNotFoundError("No experiment JSON found under results/")
    return Path(files[-1])


def _load_experiment(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _metric(obj: Dict[str, Any], key: str) -> float:
    try:
        return float(obj.get(key, 0.0))
    except Exception:
        return 0.0


def _mode_label(mode: str) -> str:
    return MODE_LABEL.get(mode, mode)


def _stage_label(stage: str) -> str:
    return STAGE_LABEL.get(stage, stage)


def _percent(value: float) -> float:
    return value * 100.0


def _percent_text(value: float) -> str:
    return f"{value:.1f}%"


def _annotate_bars(
    ax: plt.Axes,
    bars: Sequence[Any],
    fmt: str = "{:.1f}%",
    dy: float = 1.0,
    fontsize: int = 9,
) -> None:
    for bar in bars:
        h = float(bar.get_height())
        if h <= 0:
            continue
        ax.annotate(
            fmt.format(h),
            (bar.get_x() + bar.get_width() / 2.0, h),
            ha="center",
            va="bottom",
            fontsize=fontsize,
            xytext=(0, dy),
            textcoords="offset points",
        )


def _annotate_zero_values(
    ax: plt.Axes,
    bars: Sequence[Any],
    text: str,
    y: float,
    fontsize: int = 8,
    dy: float = 1.5,
) -> None:
    for bar in bars:
        h = float(bar.get_height())
        if abs(h) > 1e-12:
            continue
        ax.annotate(
            text,
            (bar.get_x() + bar.get_width() / 2.0, y),
            ha="center",
            va="bottom",
            fontsize=fontsize,
            color="#6c757d",
            xytext=(0, dy),
            textcoords="offset points",
        )


def _mode_metric(summary: Dict[str, Any], mode: str, key: str) -> float:
    by_mode = summary.get("by_mode", {}) if isinstance(summary, dict) else {}
    mode_obj = by_mode.get(mode, {}) if isinstance(by_mode.get(mode, {}), dict) else {}
    return _metric(mode_obj, key)


def _mode_playbook_metric(summary: Dict[str, Any], mode: str, playbook_id: str, key: str) -> float:
    bmp = summary.get("by_mode_playbook", {}) if isinstance(summary, dict) else {}
    mode_obj = bmp.get(mode, {}) if isinstance(bmp.get(mode, {}), dict) else {}
    playbook_obj = mode_obj.get(playbook_id, {}) if isinstance(mode_obj.get(playbook_id, {}), dict) else {}
    return _metric(playbook_obj, key)


def _ensure_plot_dir() -> Path:
    out = RESULTS_DIR / "plots"
    out.mkdir(parents=True, exist_ok=True)
    return out


def _setup_style() -> None:
    sns.set_theme(style="whitegrid", context="paper")
    plt.rcParams["font.family"] = "sans-serif"
    plt.rcParams["font.sans-serif"] = [
        "Microsoft YaHei",
        "SimHei",
        "Arial Unicode MS",
        "DejaVu Sans",
    ]
    plt.rcParams["axes.unicode_minus"] = False
    plt.rcParams["axes.titlesize"] = 12
    plt.rcParams["axes.labelsize"] = 10
    plt.rcParams["xtick.labelsize"] = 9
    plt.rcParams["ytick.labelsize"] = 9
    plt.rcParams["legend.fontsize"] = 9
    plt.rcParams["pdf.fonttype"] = 3
    plt.rcParams["ps.fonttype"] = 3
    plt.rcParams["svg.fonttype"] = "none"
    plt.rcParams["figure.dpi"] = 140
    plt.rcParams["savefig.dpi"] = 300


def _save_figure(fig: plt.Figure, output_dir: Path, stem: str) -> None:
    pdf_path = output_dir / f"{stem}.pdf"
    svg_path = output_dir / f"{stem}.svg"
    fig.savefig(pdf_path, format="pdf", bbox_inches="tight")
    fig.savefig(svg_path, format="svg", bbox_inches="tight")
    plt.close(fig)


def plot_521_dual_axis(experiment: Dict[str, Any], output_dir: Path) -> None:
    summary = experiment.get("summary", {}) if isinstance(experiment, dict) else {}
    modes = ["oneshot_collab", "single_domain_baseline"]
    mode_labels = [_mode_label(m) for m in modes]

    asr_values = [_percent(_mode_metric(summary, m, "attack_success_rate")) for m in modes]
    decision_values = [_mode_metric(summary, m, "decision_elapsed_ms") for m in modes]
    containment_collab = _mode_metric(summary, "oneshot_collab", "containment_time_ms")
    baseline_mode = "single_domain_baseline"
    no_collab_containment = _mode_metric(summary, baseline_mode, "containment_time_ms")
    no_collab_block_rate = _mode_metric(summary, baseline_mode, "block_rate")

    fig, (ax_left, ax_right) = plt.subplots(1, 2, figsize=(12.0, 4.8))
    x = list(range(len(modes)))

    asr_bars = ax_left.bar(x, asr_values, width=0.56, color=["#1f77b4", "#ff7f0e"])
    ax_left.set_xticks(x)
    ax_left.set_xticklabels(mode_labels)
    ax_left.set_ylabel("攻击成功率 ASR (%)")
    ax_left.set_ylim(0, max(105.0, max(asr_values) * 1.15))
    ax_left.set_title("攻击成功率对比")
    _annotate_bars(ax_left, asr_bars, fmt="{:.1f}%", dy=2)

    width = 0.34
    decision_bars = ax_right.bar(
        [xi - width / 2 for xi in x],
        decision_values,
        width=width,
        label="决策时延",
        color="#2a9d8f",
    )
    containment_bars = ax_right.bar(
        [x[0] + width / 2],
        [containment_collab],
        width=width,
        label="首个有效遏制动作时延",
        color="#e76f51",
    )

    ax_right.set_xticks(x)
    ax_right.set_xticklabels(mode_labels)
    ax_right.set_ylabel("时延 (ms)")
    ymax = max(decision_values + [containment_collab, 1.0]) * 1.25
    ax_right.set_ylim(0, ymax)
    ax_right.set_title("时延指标对比")
    _annotate_bars(ax_right, decision_bars, fmt="{:.0f} ms", dy=2)
    _annotate_bars(ax_right, containment_bars, fmt="{:.0f} ms", dy=2)

    containment_na = no_collab_containment <= 0.0 and no_collab_block_rate <= 0.0
    if containment_na:
        na_x = x[1] + width / 2
        na_y = ymax * 0.09
        ax_right.annotate(
            "N/A",
            (na_x, na_y),
            ha="center",
            va="bottom",
            fontsize=10,
            fontweight="bold",
            color="#7f5539",
        )
        ax_right.annotate(
            "无有效遏制动作",
            (na_x, na_y),
            ha="center",
            va="top",
            fontsize=8,
            color="#7f5539",
            xytext=(0, -11),
            textcoords="offset points",
        )
    else:
        no_collab_containment_bar = ax_right.bar(
            [x[1] + width / 2],
            [no_collab_containment],
            width=width,
            color="#e76f51",
        )
        _annotate_bars(ax_right, no_collab_containment_bar, fmt="{:.0f} ms", dy=2)

    ax_right.legend(loc="upper left")
    fig.tight_layout()
    _save_figure(fig, output_dir, "sec_5_2_1_dual_axis_asr_latency")


def plot_522_asr_by_scene(experiment: Dict[str, Any], output_dir: Path) -> None:
    summary = experiment.get("summary", {}) if isinstance(experiment, dict) else {}
    attack_scene_ids = [
        "A_happy_path",
        "B_critical_asset_counter",
        "C_budget_exhaustion",
        "D_cross_domain_weak_signal",
        "E_false_positive_noise",
        "F_portal_bridge_fallback",
    ]
    baseline_mode = "single_domain_baseline"
    
    fig, (ax_left, ax_right) = plt.subplots(1, 2, figsize=(13.0, 5.2))
    width = 0.36

    # 左侧图：各场景 ASR 对比
    x_left = list(range(len(attack_scene_ids)))
    collab_asr = [_percent(_mode_playbook_metric(summary, "oneshot_collab", pid, "attack_success_rate")) for pid in attack_scene_ids]
    no_asr = [_percent(_mode_playbook_metric(summary, baseline_mode, pid, "attack_success_rate")) for pid in attack_scene_ids]
    labels_left = [SCENE_LABEL_PAPER.get(pid, PLAYBOOK_LABEL.get(pid, pid)) for pid in attack_scene_ids]

    bars_left_1 = ax_left.bar([i - width / 2 for i in x_left], collab_asr, width, label=_mode_label("oneshot_collab"), color="#264653")
    bars_left_2 = ax_left.bar([i + width / 2 for i in x_left], no_asr, width, label=_mode_label(baseline_mode), color="#e76f51")

    ax_left.set_xticks(x_left)
    ax_left.set_xticklabels(labels_left, rotation=15)
    ax_left.set_ylabel("攻击成功率 ASR (%)")
    ax_left.set_ylim(0, 115)
    ax_left.set_title("5.2.2 (a) 各场景攻击成功率 (ASR) 对比")
    ax_left.legend()
    _annotate_bars(ax_left, bars_left_1, fmt="{:.1f}%", fontsize=8)
    _annotate_bars(ax_left, bars_left_2, fmt="{:.1f}%", fontsize=8)

    # 右侧图：各场景 业务连续性得分 (BCS) 对比
    collab_bcs = [_mode_playbook_metric(summary, "oneshot_collab", pid, "business_continuity_score") for pid in attack_scene_ids]
    no_bcs = [_mode_playbook_metric(summary, baseline_mode, pid, "business_continuity_score") for pid in attack_scene_ids]

    bars_right_1 = ax_right.bar([i - width / 2 for i in x_left], collab_bcs, width, label=_mode_label("oneshot_collab"), color="#2a9d8f")
    bars_right_2 = ax_right.bar([i + width / 2 for i in x_left], no_bcs, width, label=_mode_label(baseline_mode), color="#f4a261")

    ax_right.set_xticks(x_left)
    ax_right.set_xticklabels(labels_left, rotation=15)
    ax_right.set_ylabel("业务连续性得分 (BCS)")
    ax_right.set_ylim(0, 115)
    ax_right.set_title("5.2.2 (b) 各场景业务连续性得分 (BCS) 对比")
    ax_right.legend()
    _annotate_bars(ax_right, bars_right_1, fmt="{:.1f}", fontsize=8)
    _annotate_bars(ax_right, bars_right_2, fmt="{:.1f}", fontsize=8)

    # 在 B/C 场景添加高亮连接线或说明
    for i, pid in enumerate(attack_scene_ids):
        if pid in ["B_critical_asset_counter", "C_budget_exhaustion"]:
            ax_right.annotate("通过反提案/降级\n提升可用性", 
                             xy=(i, collab_bcs[i]), xytext=(0, 20),
                             textcoords="offset points", ha='center',
                             arrowprops=dict(arrowstyle="->", color="green"),
                             fontsize=8, color="green", fontweight="bold")

    fig.tight_layout()
    _save_figure(fig, output_dir, "sec_5_2_2_asr_bcs_by_scene")

        [i - width / 2 for i in x_left],
        collab_asr,
        width=width,
        color="#1f77b4",
        label=_mode_label("oneshot_collab"),
    )
    bars_left_2 = ax_left.bar(
        [i + width / 2 for i in x_left],
        no_asr,
        width=width,
        color="#ff7f0e",
        label=_mode_label(baseline_mode),
    )
    ax_left.set_xticks(x_left)
    ax_left.set_xticklabels(labels_left, rotation=18, ha="right")
    ax_left.set_ylabel("攻击成功率 ASR (%)")
    ax_left.set_title("攻击场景下的攻击成功率对比")
    ax_left.set_ylim(0, max(105.0, max(collab_asr + no_asr + [0.0]) * 1.15))
    _annotate_bars(ax_left, bars_left_1, fmt="{:.1f}%", dy=2)
    _annotate_bars(ax_left, bars_left_2, fmt="{:.1f}%", dy=2)
    ax_left.legend(loc="upper left")

    x_right = [0, 1]
    noise_collab = _percent(_mode_playbook_metric(summary, "oneshot_collab", noise_scene_id, "false_positive_rate"))
    noise_no = _percent(_mode_playbook_metric(summary, baseline_mode, noise_scene_id, "false_positive_rate"))
    bars_right = ax_right.bar(
        x_right,
        [noise_collab, noise_no],
        width=0.54,
        color=["#1f77b4", "#ff7f0e"],
    )
    ax_right.set_xticks(x_right)
    ax_right.set_xticklabels([_mode_label("oneshot_collab"), _mode_label(baseline_mode)])
    ax_right.set_ylabel("误报率 (%)")
    ax_right.set_ylim(0, max(100.0, noise_collab, noise_no) * 1.2)
    ax_right.set_title(f"{SCENE_LABEL_PAPER.get(noise_scene_id, '场景E：噪声抑制')} 的误报率对比")
    _annotate_bars(ax_right, bars_right, fmt="{:.1f}%", dy=2)

    fig.tight_layout()
    _save_figure(fig, output_dir, "sec_5_2_2_asr_by_scene")
    bars_right = ax_right.bar(
        x_right,
        [noise_collab, noise_no],
        width=0.54,
        color=["#1f77b4", "#ff7f0e"],
    )
    ax_right.set_xticks(x_right)
    ax_right.set_xticklabels([_mode_label("oneshot_collab"), _mode_label(baseline_mode)])
    ax_right.set_ylabel("误报率 (%)")
    ax_right.set_ylim(0, max(100.0, noise_collab, noise_no) * 1.2)
    ax_right.set_title(f"{SCENE_LABEL_PAPER.get(noise_scene_id, '场景D：噪声抑制')} 的误报率对比")
    _annotate_bars(ax_right, bars_right, fmt="{:.1f}%", dy=2)

    fig.tight_layout()
    _save_figure(fig, output_dir, "sec_5_2_2_asr_by_scene")


def _extract_mode_stage_counts(samples: List[Dict[str, Any]], mode: str) -> Counter:
    stage_counter: Counter = Counter()
    for sample in samples:
        if str(sample.get("mode", "")) != mode:
            continue
        final_stage = str(sample.get("final_stage", "")).strip()
        if not final_stage:
            reached = sample.get("reached_stages", [])
            if isinstance(reached, list) and reached:
                final_stage = str(reached[-1])
        if final_stage:
            stage_counter[final_stage] += 1
    return stage_counter


def _mode_sample_count(experiment: Dict[str, Any], mode: str) -> int:
    spm = experiment.get("samples_per_mode", {}) if isinstance(experiment.get("samples_per_mode"), dict) else {}
    if mode in spm:
        return int(spm.get(mode, 0) or 0)
    samples = experiment.get("samples", []) if isinstance(experiment.get("samples"), list) else []
    return sum(1 for s in samples if str(s.get("mode", "")) == mode)


def plot_522_stage_stacked(experiment: Dict[str, Any], output_dir: Path) -> None:
    samples = experiment.get("samples", []) if isinstance(experiment.get("samples"), list) else []
    baseline_mode = "single_domain_baseline"
    collab_counts = _extract_mode_stage_counts(samples, "oneshot_collab")
    no_counts = _extract_mode_stage_counts(samples, baseline_mode)

    if not (collab_counts or no_counts):
        return

    collab_total = float(sum(collab_counts.values()))
    no_total = float(sum(no_counts.values()))
    if collab_total <= 0 and no_total <= 0:
        return

    present_stages = [
        stage
        for stage in STAGE_ORDER
        if float(collab_counts.get(stage, 0)) > 0 or float(no_counts.get(stage, 0)) > 0
    ]

    fig, ax = plt.subplots(figsize=(9.2, 5.1))
    mode_names = [_mode_label("oneshot_collab"), _mode_label(baseline_mode)]
    base = [0.0, 0.0]
    palette = sns.color_palette("crest", n_colors=max(3, len(present_stages)))

    largest = {
        "oneshot_collab": ("", -1.0),
        baseline_mode: ("", -1.0),
    }

    for idx, stage in enumerate(present_stages):
        collab_pct = 100.0 * float(collab_counts.get(stage, 0)) / collab_total if collab_total > 0 else 0.0
        no_pct = 100.0 * float(no_counts.get(stage, 0)) / no_total if no_total > 0 else 0.0
        values = [collab_pct, no_pct]
        bars = ax.bar(mode_names, values, bottom=base, color=palette[idx], label=_stage_label(stage), width=0.58)

        if collab_pct > largest["oneshot_collab"][1]:
            largest["oneshot_collab"] = (stage, collab_pct)
        if no_pct > largest[baseline_mode][1]:
            largest[baseline_mode] = (stage, no_pct)

        for i, pct in enumerate(values):
            if pct >= 18.0:
                ax.annotate(
                    _percent_text(pct),
                    (bars[i].get_x() + bars[i].get_width() / 2.0, base[i] + pct / 2.0),
                    ha="center",
                    va="center",
                    fontsize=8,
                    color="white",
                    fontweight="bold",
                )
        base = [base[0] + values[0], base[1] + values[1]]

    ax.set_ylim(0, 100)
    ax.set_ylabel("样本占比 (%)")
    ax.set_xlabel("防御模式")
    ax.set_title("两种模式下攻击最终到达阶段分布（100%堆叠）")
    ax.legend(title="最终到达阶段", bbox_to_anchor=(1.02, 1.0), loc="upper left")

    for idx, mode in enumerate(["oneshot_collab", baseline_mode]):
        stage, pct = largest[mode]
        if pct > 0:
            ax.annotate(
                f"主导阶段：{_stage_label(stage)} {_percent_text(pct)}",
                (idx, 102.0),
                ha="center",
                va="bottom",
                fontsize=8,
                color="#264653",
            )

    collab_n = _mode_sample_count(experiment, "oneshot_collab")
    no_n = _mode_sample_count(experiment, baseline_mode)
    ax.text(0.99, -0.16, f"n(协同)={collab_n}，n(基线)={no_n}", transform=ax.transAxes, ha="right", fontsize=9, color="#495057")

    fig.tight_layout()
    _save_figure(fig, output_dir, "sec_5_2_2_reached_stages_stacked")
    mode_names = [_mode_label("oneshot_collab"), _mode_label("no_collab")]
    base = [0.0, 0.0]
    palette = sns.color_palette("crest", n_colors=max(3, len(present_stages)))

    largest = {
        "oneshot_collab": ("", -1.0),
        baseline_mode: ("", -1.0),
    }

    for idx, stage in enumerate(present_stages):
        collab_pct = 100.0 * float(collab_counts.get(stage, 0)) / collab_total if collab_total > 0 else 0.0
        no_pct = 100.0 * float(no_counts.get(stage, 0)) / no_total if no_total > 0 else 0.0
        values = [collab_pct, no_pct]
        bars = ax.bar(mode_names, values, bottom=base, color=palette[idx], label=_stage_label(stage), width=0.58)

        if collab_pct > largest["oneshot_collab"][1]:
            largest["oneshot_collab"] = (stage, collab_pct)
        if no_pct > largest[baseline_mode][1]:
            largest[baseline_mode] = (stage, no_pct)

        for i, pct in enumerate(values):
            if pct >= 18.0:
                ax.annotate(
                    _percent_text(pct),
                    (bars[i].get_x() + bars[i].get_width() / 2.0, base[i] + pct / 2.0),
                    ha="center",
                    va="center",
                    fontsize=8,
                    color="white",
                    fontweight="bold",
                )
        base = [base[0] + values[0], base[1] + values[1]]

    ax.set_ylim(0, 100)
    ax.set_ylabel("样本占比 (%)")
    ax.set_xlabel("防御模式")
    ax.set_title("两种模式下攻击最终到达阶段分布（100%堆叠）")
    ax.legend(title="最终到达阶段", bbox_to_anchor=(1.02, 1.0), loc="upper left")

    for idx, mode in enumerate(["oneshot_collab", baseline_mode]):
        stage, pct = largest[mode]
        if pct > 0:
            ax.annotate(
                f"主导阶段：{_stage_label(stage)} {_percent_text(pct)}",
                (idx, 102.0),
                ha="center",
                va="bottom",
                fontsize=8,
                color="#264653",
            )

    collab_n = _mode_sample_count(experiment, "oneshot_collab")
    no_n = _mode_sample_count(experiment, baseline_mode)
    ax.text(0.99, -0.16, f"n(协同)={collab_n}，n(基线)={no_n}", transform=ax.transAxes, ha="right", fontsize=9, color="#495057")

    fig.tight_layout()
    _save_figure(fig, output_dir, "sec_5_2_2_reached_stages_stacked")


def _collect_negotiation_rates(summary: Dict[str, Any], playbook_id: str, mode: str) -> List[float]:
    return [
        _percent(_mode_playbook_metric(summary, mode, playbook_id, "counter_rate")),
        _percent(_mode_playbook_metric(summary, mode, playbook_id, "adopt_counter_rate")),
        _percent(_mode_playbook_metric(summary, mode, playbook_id, "downgrade_adoption_rate")),
    ]


def plot_532_negotiation_distribution(experiment: Dict[str, Any], output_dir: Path) -> None:
    summary = experiment.get("summary", {}) if isinstance(experiment, dict) else {}
    target_playbooks = ["B_critical_asset_counter", "F_portal_bridge_fallback"]
    metric_labels = ["反提案触发率", "反提案采纳率", "降级方案采纳率"]
    baseline_mode = "single_domain_baseline"
    mode_order = ["oneshot_collab", baseline_mode]

    fig, axes = plt.subplots(1, 2, figsize=(12.8, 4.9), sharey=True)
    width = 0.34
    x = list(range(len(metric_labels)))

    for ax, pid in zip(axes, target_playbooks):
        collab_values = _collect_negotiation_rates(summary, pid, "oneshot_collab")
        no_values = _collect_negotiation_rates(summary, pid, baseline_mode)
        bars1 = ax.bar(
            [i - width / 2 for i in x],
            collab_values,
            width=width,
            color="#1f77b4",
            label=_mode_label(mode_order[0]),
        )
        bars2 = ax.bar(
            [i + width / 2 for i in x],
            no_values,
            width=width,
            color="#ff7f0e",
            label=_mode_label(mode_order[1]),
        )
        ax.set_xticks(x)
        ax.set_xticklabels(metric_labels)
        ax.set_title(SCENE_LABEL_PAPER.get(pid, PLAYBOOK_LABEL.get(pid, pid)))
        ax.set_ylim(0, 105)
        _annotate_bars(ax, bars1, fmt="{:.1f}%", dy=2)
        _annotate_bars(ax, bars2, fmt="{:.1f}%", dy=2)
        _annotate_zero_values(ax, bars1, text="0.0%", y=0.0, fontsize=8)
        _annotate_zero_values(ax, bars2, text="0.0%", y=0.0, fontsize=8)

    axes[0].set_ylabel("比例 (%)")
    axes[0].legend(loc="upper left")
    fig.tight_layout()
    _save_figure(fig, output_dir, "sec_5_3_2_negotiation_distribution")


def plot_533_fallback_path(experiment: Dict[str, Any], output_dir: Path) -> None:
    summary = experiment.get("summary", {}) if isinstance(experiment, dict) else {}
    baseline_mode = "single_domain_baseline"
    mode_order = ["oneshot_collab", baseline_mode]
    scene_ids = ["C_budget_exhaustion", "F_portal_bridge_fallback"]
    width = 0.34

    fig, (ax_left, ax_right) = plt.subplots(1, 2, figsize=(13.0, 5.0))

    x_left = list(range(len(scene_ids)))
    collab_rates = [_percent(_mode_playbook_metric(summary, "oneshot_collab", pid, "fallback_rate")) for pid in scene_ids]
    no_rates = [_percent(_mode_playbook_metric(summary, baseline_mode, pid, "fallback_rate")) for pid in scene_ids]
    left_labels = [SCENE_LABEL_PAPER.get(pid, PLAYBOOK_LABEL.get(pid, pid)) for pid in scene_ids]

    left_bars_1 = ax_left.bar(
        [i - width / 2 for i in x_left],
        collab_rates,
        width=width,
        color="#1f77b4",
        label=_mode_label(mode_order[0]),
    )
    left_bars_2 = ax_left.bar(
        [i + width / 2 for i in x_left],
        no_rates,
        width=width,
        color="#ff7f0e",
        label=_mode_label(mode_order[1]),
    )
    ax_left.set_xticks(x_left)
    ax_left.set_xticklabels(left_labels, rotation=12, ha="right")
    ax_left.set_ylabel("替代遏制触发率 fallback_rate (%)")
    ax_left.set_ylim(0, max(100.0, max(collab_rates + no_rates + [0.0]) * 1.2))
    ax_left.set_title("资源受限与跨域补偿场景的替代遏制触发率")
    _annotate_bars(ax_left, left_bars_1, fmt="{:.1f}%", dy=2)
    _annotate_bars(ax_left, left_bars_2, fmt="{:.1f}%", dy=2)
    _annotate_zero_values(ax_left, left_bars_1, text="0.0%", y=0.0, fontsize=8)
    _annotate_zero_values(ax_left, left_bars_2, text="0.0%", y=0.0, fontsize=8)
    ax_left.legend(loc="upper left")

    f_pid = "F_portal_bridge_fallback"
    x_right = list(range(len(mode_order)))
    f_totals = [_mode_playbook_metric(summary, m, f_pid, "fallback_total") for m in mode_order]
    f_rates = [_percent(_mode_playbook_metric(summary, m, f_pid, "fallback_rate")) for m in mode_order]

    total_bars = ax_right.bar(
        x_right,
        f_totals,
        width=0.52,
        color="#457b9d",
        alpha=0.92,
        label="替代调度次数",
    )
    ax_right.set_xticks(x_right)
    ax_right.set_xticklabels([_mode_label(m) for m in mode_order])
    ax_right.set_ylabel("替代调度次数 (次)")
    ax_right.set_title("跨域补偿场景：替代调度次数与触发率")
    _annotate_bars(ax_right, total_bars, fmt="{:.0f} 次", dy=2)
    _annotate_zero_values(ax_right, total_bars, text="0 次", y=0.0, fontsize=8)

    ax_right_2 = ax_right.twinx()
    rate_line = ax_right_2.plot(
        x_right,
        f_rates,
        color="#e63946",
        marker="o",
        linewidth=2.0,
        label="替代遏制触发率",
    )
    ax_right_2.set_ylabel("替代遏制触发率 (%)")
    ax_right_2.set_ylim(0, max(100.0, max(f_rates + [0.0]) * 1.25))
    for i, y in enumerate(f_rates):
        ax_right_2.annotate(_percent_text(y), (x_right[i], y), ha="center", va="bottom", fontsize=9, xytext=(0, 3), textcoords="offset points")
        if abs(y) <= 1e-12:
            ax_right_2.annotate(
                "0.0%",
                (x_right[i], 0.0),
                ha="center",
                va="bottom",
                fontsize=8,
                color="#6c757d",
                xytext=(0, 12),
                textcoords="offset points",
            )

    ax_right.legend([total_bars, rate_line[0]], ["替代调度次数", "替代遏制触发率"], loc="upper right")

    fig.tight_layout()
    _save_figure(fig, output_dir, "sec_5_3_3_fallback_path")


def plot_531_weak_signal_escalation(experiment: Dict[str, Any], output_dir: Path) -> None:
    summary = experiment.get("summary", {}) if isinstance(experiment, dict) else {}
    bmp = summary.get("by_mode_playbook", {}) if isinstance(summary, dict) else {}
    collab_map = bmp.get("oneshot_collab", {}) if isinstance(bmp.get("oneshot_collab", {}), dict) else {}
    weak = collab_map.get("D_cross_domain_weak_signal", {}) if isinstance(collab_map.get("D_cross_domain_weak_signal", {}), dict) else {}

    base = weak.get("base_risk_distribution", {}) if isinstance(weak.get("base_risk_distribution"), dict) else {}
    final = weak.get("final_risk_distribution", {}) if isinstance(weak.get("final_risk_distribution"), dict) else {}
    if not base and not final:
        by_mode = summary.get("by_mode", {}) if isinstance(summary, dict) else {}
        collab = by_mode.get("oneshot_collab", {}) if isinstance(by_mode.get("oneshot_collab", {}), dict) else {}
        base = collab.get("base_risk_distribution", {}) if isinstance(collab.get("base_risk_distribution"), dict) else {}
        final = collab.get("final_risk_distribution", {}) if isinstance(collab.get("final_risk_distribution"), dict) else {}

    risk_levels = ["low", "medium", "high", "critical"]
    labels = ["低", "中", "高", "严重"]
    base_values = [float(base.get(k, 0)) for k in risk_levels]
    final_values = [float(final.get(k, 0)) for k in risk_levels]
    if sum(base_values) <= 0 and sum(final_values) <= 0:
        return

    fig, ax = plt.subplots(figsize=(7.6, 4.8))
    x = list(range(len(risk_levels)))
    width = 0.36
    bars1 = ax.bar([i - width / 2 for i in x], base_values, width=width, color="#8ecae6", label="风险评估前")
    bars2 = ax.bar([i + width / 2 for i in x], final_values, width=width, color="#219ebc", label="风险校准后")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("样本数")
    ax.set_title("弱信号提权场景的风险等级前后对比")
    _annotate_bars(ax, bars1, fmt="{:.0f}", dy=2)
    _annotate_bars(ax, bars2, fmt="{:.0f}", dy=2)
    ax.legend(loc="upper left")
    fig.tight_layout()
    _save_figure(fig, output_dir, "sec_5_3_1_weak_signal_escalation")


def generate_all_plots(experiment: Dict[str, Any], output_dir: Path) -> None:
    plot_521_dual_axis(experiment, output_dir)
    plot_522_asr_by_scene(experiment, output_dir)
    plot_522_stage_stacked(experiment, output_dir)
    plot_531_weak_signal_escalation(experiment, output_dir)
    plot_532_negotiation_distribution(experiment, output_dir)
    plot_533_fallback_path(experiment, output_dir)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate academic paper plots under results/plots/")
    parser.add_argument("--file", default="", help="Experiment JSON path, default latest under results/")
    args = parser.parse_args()

    _setup_style()
    data_file = Path(args.file) if args.file else _latest_result_file()
    experiment = _load_experiment(data_file)
    out_dir = _ensure_plot_dir()

    generate_all_plots(experiment, out_dir)
    print(f"[paper_plots] source={data_file}")
    print(f"[paper_plots] output_dir={out_dir.resolve()}")
    print("[paper_plots] generated: sec_5_2_1_dual_axis_asr_latency.(pdf|svg)")
    print("[paper_plots] generated: sec_5_2_2_asr_by_scene.(pdf|svg)")
    print("[paper_plots] generated: sec_5_2_2_reached_stages_stacked.(pdf|svg)")
    print("[paper_plots] generated: sec_5_3_1_weak_signal_escalation.(pdf|svg)")
    print("[paper_plots] generated: sec_5_3_2_negotiation_distribution.(pdf|svg)")
    print("[paper_plots] generated: sec_5_3_3_fallback_path.(pdf|svg)")


if __name__ == "__main__":
    main()
