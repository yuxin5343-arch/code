from __future__ import annotations

from pathlib import Path
from typing import Dict

from plotly.subplots import make_subplots
import plotly.graph_objects as go


def _get_metric(result: Dict, key: str) -> float:
    value = result.get(key, 0)
    return float(value if value is not None else 0)


def generate_report(experiment: Dict, output_path: str | Path) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    with_defense = experiment.get("with_defense", {})
    without_defense = experiment.get("without_defense", {})

    with_tasks = int(with_defense.get("tasks", 0))
    with_success = int(with_defense.get("success", 0))
    with_failed = max(with_tasks - with_success, 0)

    domain_stats = with_defense.get("domain_stats", {})
    domains = list(domain_stats.keys())
    domain_success_rates = [float(domain_stats[d].get("success_rate", 0)) * 100 for d in domains]
    domain_avg_latencies = [float(domain_stats[d].get("avg_latency_ms", 0)) for d in domains]

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

    fig.write_html(str(output), include_plotlyjs="cdn", full_html=True)
    return output
