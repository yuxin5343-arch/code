from __future__ import annotations

"""实验可视化报告生成器。

使用 Plotly 生成对比图表，并导出为 HTML 文件。
"""

from pathlib import Path
from typing import Dict

from plotly.subplots import make_subplots
import plotly.graph_objects as go


def _get_metric(result: Dict, key: str) -> float:
    """安全读取数值指标，缺失时返回 0。"""
    value = result.get(key, 0)
    return float(value if value is not None else 0)


def _generate_playbook_report(experiment: Dict, output: Path) -> Path:
    summary = experiment.get("summary", {}) if isinstance(experiment, dict) else {}
    by_mode = summary.get("by_mode", {}) if isinstance(summary, dict) else {}
    by_mode_playbook = summary.get("by_mode_playbook", {}) if isinstance(summary, dict) else {}

    collab = by_mode.get("oneshot_collab", {})
    no_collab = by_mode.get("no_collab", {})

    collab_intent = collab.get("intent_statuses", {}) if isinstance(collab, dict) else {}
    collab_intent_ratios = collab_intent.get("ratios", {}) if isinstance(collab_intent, dict) else {}

    d_collab = by_mode_playbook.get("oneshot_collab", {}).get("D_cross_domain_weak_signal", {})
    d_no_collab = by_mode_playbook.get("no_collab", {}).get("D_cross_domain_weak_signal", {})

    collab_base_risk = collab.get("base_risk_distribution", {}) if isinstance(collab, dict) else {}
    collab_final_risk = collab.get("final_risk_distribution", {}) if isinstance(collab, dict) else {}
    collab_downgrade_adopt_total = int(collab.get("downgrade_adopt_total", 0)) if isinstance(collab, dict) else 0
    collab_downgrade_reject_total = int(collab.get("downgrade_reject_total", 0)) if isinstance(collab, dict) else 0

    fig = make_subplots(
        rows=5,
        cols=2,
        subplot_titles=(
            "Attack Success Rate (Collab vs No-Collab)",
            "False Negative Rate on Playbook D",
            "Intent Status Ratios (Collab)",
            "Negotiation Game Outcomes",
            "Lateral Spread Block Count",
            "Average Latency (ms)",
            "Low-Confidence Rejected by Manager",
            "Downgrade Adoption Rate (Collab)",
            "Base Risk vs Calibrated Risk (Collab)",
            "Domain-Weight Calibration Metrics",
        ),
        specs=[
            [{"type": "xy"}, {"type": "xy"}],
            [{"type": "xy"}, {"type": "xy"}],
            [{"type": "xy"}, {"type": "xy"}],
            [{"type": "xy"}, {"type": "domain"}],
            [{"type": "xy"}, {"type": "xy"}],
        ],
    )

    # Defense efficacy comparison.
    fig.add_trace(
        go.Bar(
            x=["oneshot_collab", "no_collab"],
            y=[
                _get_metric(collab, "attack_success_rate"),
                _get_metric(no_collab, "attack_success_rate"),
            ],
            marker_color=["#007f5f", "#9c6644"],
            name="attack_success_rate",
        ),
        row=1,
        col=1,
    )

    # D scenario FNR focus.
    fig.add_trace(
        go.Bar(
            x=["oneshot_collab", "no_collab"],
            y=[
                _get_metric(d_collab, "false_negative_rate"),
                _get_metric(d_no_collab, "false_negative_rate"),
            ],
            marker_color=["#386641", "#bc4749"],
            name="fnr_playbook_d",
        ),
        row=1,
        col=2,
    )

    # Intent status ratios.
    fig.add_trace(
        go.Bar(
            x=["accept", "counter_proposal", "reject", "other"],
            y=[
                float(collab_intent_ratios.get("accept", 0.0)),
                float(collab_intent_ratios.get("counter_proposal", 0.0)),
                float(collab_intent_ratios.get("reject", 0.0)),
                float(collab_intent_ratios.get("other", 0.0)),
            ],
            marker_color=["#2a9d8f", "#e76f51", "#f4a261", "#8d99ae"],
            name="intent_status_ratio_collab",
        ),
        row=2,
        col=1,
    )

    # Game outcomes: counter total / adopt rate / fallback rate.
    fig.add_trace(
        go.Bar(
            x=["counter_total", "adopt_counter_rate", "fallback_rate"],
            y=[
                _get_metric(collab, "counter_total"),
                _get_metric(collab, "adopt_counter_rate"),
                _get_metric(collab, "fallback_rate"),
            ],
            marker_color=["#264653", "#e9c46a", "#e76f51"],
            name="game_outcome_collab",
        ),
        row=2,
        col=2,
    )

    fig.add_trace(
        go.Bar(
            x=["oneshot_collab", "no_collab"],
            y=[
                _get_metric(collab, "lateral_spread_block_count"),
                _get_metric(no_collab, "lateral_spread_block_count"),
            ],
            marker_color=["#588157", "#a3b18a"],
            name="lateral_spread_block_count",
        ),
        row=3,
        col=1,
    )

    fig.add_trace(
        go.Bar(
            x=["oneshot_collab", "no_collab"],
            y=[
                _get_metric(collab, "avg_latency_ms"),
                _get_metric(no_collab, "avg_latency_ms"),
            ],
            marker_color=["#3a5a40", "#6b705c"],
            name="avg_latency_ms",
        ),
        row=3,
        col=2,
    )

    risk_levels = ["low", "medium", "high", "critical"]

    # Low-confidence downgrade proposals rejected by manager (count).
    fig.add_trace(
        go.Bar(
            x=["oneshot_collab", "no_collab"],
            y=[
                _get_metric(collab, "low_confidence_reject_total"),
                _get_metric(no_collab, "low_confidence_reject_total"),
            ],
            marker_color=["#d62828", "#9d0208"],
            name="low_confidence_reject_total",
        ),
        row=4,
        col=1,
    )

    # Dedicated pie: downgrade adoption vs rejection.
    fig.add_trace(
        go.Pie(
            labels=["adopted", "rejected"],
            values=[collab_downgrade_adopt_total, collab_downgrade_reject_total],
            marker_colors=["#2a9d8f", "#e76f51"],
            hole=0.45,
            name="downgrade_adoption_rate",
        ),
        row=4,
        col=2,
    )

    # Dedicated line comparison: base risk vs calibrated risk.
    fig.add_trace(
        go.Scatter(
            x=risk_levels,
            y=[int(collab_base_risk.get(level, 0)) for level in risk_levels],
            mode="lines+markers",
            marker_color="#8d99ae",
            name="base_risk_distribution",
        ),
        row=5,
        col=1,
    )
    fig.add_trace(
        go.Scatter(
            x=risk_levels,
            y=[int(collab_final_risk.get(level, 0)) for level in risk_levels],
            mode="lines+markers",
            marker_color="#ef476f",
            name="final_risk_distribution",
        ),
        row=5,
        col=1,
    )

    fig.add_trace(
        go.Bar(
            x=["domain_weight_factor_avg", "risk_calibrated_rate"],
            y=[
                _get_metric(collab, "domain_weight_factor_avg"),
                _get_metric(collab, "risk_calibrated_rate"),
            ],
            marker_color=["#118ab2", "#06d6a0"],
            name="domain_weight_metrics",
        ),
        row=5,
        col=2,
    )

    fig.update_layout(
        title=(
            f"Playbook-Driven {int(experiment.get('total_samples', 0))}-Sample Report "
            f"({experiment.get('generated_at', 'N/A')}) | "
            f"max_rounds={int(collab.get('max_rounds', 1))}, timeout_ms={int(collab.get('timeout_ms', 0))}"
        ),
        template="plotly_white",
        height=1750,
        barmode="group",
        legend_title="Metrics",
    )

    fig.update_yaxes(title_text="rate", row=1, col=1)
    fig.update_yaxes(title_text="rate", row=1, col=2)
    fig.update_yaxes(title_text="ratio", row=2, col=1)
    fig.update_yaxes(title_text="数量", row=2, col=2)
    fig.update_yaxes(title_text="数量", row=3, col=1)
    fig.update_yaxes(title_text="latency (ms)", row=3, col=2)
    fig.update_yaxes(title_text="数量", row=4, col=1)
    fig.update_yaxes(title_text="数量", row=5, col=1)
    fig.update_yaxes(title_text="value", row=5, col=2)

    fig.write_html(str(output), include_plotlyjs="cdn", full_html=True)
    return output


def generate_report(experiment: Dict, output_path: str | Path) -> Path:
    """根据实验结果生成可交互的 HTML 报告。"""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    if str(experiment.get("experiment_type", "")) == "playbook_driven" and isinstance(experiment.get("summary"), dict):
        return _generate_playbook_report(experiment, output)

    with_defense = experiment.get("with_defense", {})
    without_defense = experiment.get("without_defense", {})

    with_tasks = int(with_defense.get("tasks", 0))
    with_success = int(with_defense.get("success", 0))
    with_failed = max(with_tasks - with_success, 0)

    domain_stats = with_defense.get("domain_stats", {})
    domains = list(domain_stats.keys())
    domain_success_rates = [float(domain_stats[d].get("success_rate", 0)) * 100 for d in domains]
    domain_avg_latencies = [float(domain_stats[d].get("avg_latency_ms", 0)) for d in domains]

    # 构建 2x2 子图：攻击成功率、遏制时间、任务成功占比、横向扩散与时延。
    fig = make_subplots(
        rows=2,
        cols=2,
        subplot_titles=(
            "Attack Success Rate Comparison",
            "Containment Time Comparison (ms)",
            "With-Defense Task Success vs Failure",
            "Lateral Spread / Avg Latency",
        ),
        specs=[
            [{"type": "xy"}, {"type": "xy"}],
            [{"type": "domain"}, {"type": "xy", "secondary_y": True}],
        ],
    )

    fig.add_trace(
        go.Bar(
            x=["With Defense", "Without Defense"],
            y=[
                _get_metric(with_defense, "attack_success_rate"),
                _get_metric(without_defense, "attack_success_rate"),
            ],
            marker_color=["#1f77b4", "#ff7f0e"],
            name="attack_success_rate",
        ),
        row=1,
        col=1,
    )

    fig.add_trace(
        go.Bar(
            x=["With Defense", "Without Defense"],
            y=[
                _get_metric(with_defense, "containment_time_ms"),
                _get_metric(without_defense, "containment_time_ms"),
            ],
            marker_color=["#2ca02c", "#d62728"],
            name="containment_time_ms",
        ),
        row=1,
        col=2,
    )

    fig.add_trace(
        go.Pie(
            labels=["Success", "Failed"],
            values=[with_success, with_failed],
            marker_colors=["#2ca02c", "#d62728"],
            hole=0.45,
            name="task_outcome",
        ),
        row=2,
        col=1,
    )

    spread_values = [
        _get_metric(with_defense, "lateral_spread_count"),
        _get_metric(without_defense, "lateral_spread_count"),
    ]
    fig.add_trace(
        go.Bar(
            x=["With Defense", "Without Defense"],
            y=spread_values,
            marker_color=["#17becf", "#bcbd22"],
            name="lateral_spread_count",
            text=[f"{v:.0f}" for v in spread_values],
            textposition="outside",
        ),
        row=2,
        col=2,
        secondary_y=False,
    )

    # 当存在分域数据时，叠加各域平均时延折线。
    if domains:
        fig.add_trace(
            go.Scatter(
                x=domains,
                y=domain_avg_latencies,
                mode="lines+markers",
                marker_color="#9467bd",
                name="domain_avg_latency_ms",
                text=[f"{v:.0f} ms" for v in domain_avg_latencies],
                textposition="top center",
            ),
            row=2,
            col=2,
            secondary_y=True,
        )

    fig.update_layout(
        title=f"Cross-Domain Defense Experiment Report ({experiment.get('generated_at', 'N/A')})",
        barmode="group",
        template="plotly_white",
        height=900,
        legend_title="Metrics",
    )
    fig.update_yaxes(title_text="Attack Success Rate", row=1, col=1)
    fig.update_yaxes(title_text="Containment Time (ms)", row=1, col=2)
    fig.update_yaxes(title_text="Lateral Spread Count", row=2, col=2, secondary_y=False)
    fig.update_yaxes(title_text="Latency (ms)", row=2, col=2, secondary_y=True)

    # 导出完整 HTML，前端静态查看即可打开。
    fig.write_html(str(output), include_plotlyjs="cdn", full_html=True)
    return output
