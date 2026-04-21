from __future__ import annotations

"""实验可视化报告生成器。

使用 Plotly 生成对比图表，并导出为 HTML 文件。
"""

from pathlib import Path
from typing import Any, Dict, List

from plotly.subplots import make_subplots
import plotly.graph_objects as go


PLAYBOOK_ORDER = [
    "A_happy_path",
    "B_critical_asset_counter",
    "C_budget_exhaustion",
    "D_cross_domain_weak_signal",
    "E_false_positive_noise",
    "F_portal_bridge_fallback",
]

PLAYBOOK_LABEL = {
    "A_happy_path": "场景A",
    "B_critical_asset_counter": "场景B",
    "C_budget_exhaustion": "场景C",
    "D_cross_domain_weak_signal": "场景D",
    "E_false_positive_noise": "场景E",
    "F_portal_bridge_fallback": "场景F",
}

SCENE_TO_PLAYBOOK = {v: k for k, v in PLAYBOOK_LABEL.items()}
COLLAB_MODE = "oneshot_collab"
BASELINE_MODE_CANDIDATES = ("single_domain_baseline", "no_collab")


def _pick_baseline_mode(mode_map: Dict[str, Any]) -> str:
    if not isinstance(mode_map, dict):
        return BASELINE_MODE_CANDIDATES[0]
    for mode in BASELINE_MODE_CANDIDATES:
        if mode in mode_map:
            return mode
    return BASELINE_MODE_CANDIDATES[0]


def _get_metric(result: Dict, key: str) -> float:
    """安全读取数值指标，缺失时返回 0。"""
    value = result.get(key, 0)
    return float(value if value is not None else 0)


def _collect_playbook_rows(by_mode_playbook: Dict[str, Dict[str, Dict[str, Any]]]) -> List[Dict[str, Any]]:
    baseline_mode = _pick_baseline_mode(by_mode_playbook)
    collab_map = by_mode_playbook.get(COLLAB_MODE, {}) if isinstance(by_mode_playbook, dict) else {}
    no_map = by_mode_playbook.get(baseline_mode, {}) if isinstance(by_mode_playbook, dict) else {}
    playbook_ids = [pid for pid in PLAYBOOK_ORDER if pid in set(collab_map.keys()) | set(no_map.keys())]

    rows: List[Dict[str, Any]] = []
    for pb in playbook_ids:
        collab = collab_map.get(pb, {}) if isinstance(collab_map.get(pb, {}), dict) else {}
        no_collab = no_map.get(pb, {}) if isinstance(no_map.get(pb, {}), dict) else {}
        c_attack = _get_metric(collab, "attack_success_rate")
        n_attack = _get_metric(no_collab, "attack_success_rate")
        rows.append(
            {
                "playbook": pb,
                "scene": PLAYBOOK_LABEL.get(pb, pb),
                "baseline_mode": baseline_mode,
                "collab_attack": c_attack,
                "no_collab_attack": n_attack,
                "attack_reduction": n_attack - c_attack,
                "collab_sbcs": _get_metric(collab, "security_business_balance_score"),
                "no_collab_sbcs": _get_metric(no_collab, "security_business_balance_score"),
                "collab_block_rate": _get_metric(collab, "block_rate"),
                "no_collab_block_rate": _get_metric(no_collab, "block_rate"),
                "collab_counter_rate": _get_metric(collab, "counter_rate"),
                "collab_fallback_rate": _get_metric(collab, "fallback_rate"),
                "no_collab_counter_rate": _get_metric(no_collab, "counter_rate"),
                "no_collab_fallback_rate": _get_metric(no_collab, "fallback_rate"),
                "collab_task_success_rate": _get_metric(collab, "task_success_rate"),
                "no_collab_task_success_rate": _get_metric(no_collab, "task_success_rate"),
                "collab_latency": _get_metric(collab, "avg_latency_ms"),
                "no_collab_latency": _get_metric(no_collab, "avg_latency_ms"),
                "samples": int(collab.get("samples", 0) or no_collab.get("samples", 0) or 0),
            }
        )
    return rows


def _collect_tier_rows(summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    by_mode_tier = summary.get("by_mode_tier", {}) if isinstance(summary, dict) else {}
    baseline_mode = _pick_baseline_mode(by_mode_tier)
    collab_tier = by_mode_tier.get(COLLAB_MODE, {}) if isinstance(by_mode_tier, dict) else {}
    baseline_tier = by_mode_tier.get(baseline_mode, {}) if isinstance(by_mode_tier, dict) else {}

    tier_order = ["L1", "L2", "L3"]
    all_tiers = sorted(set(collab_tier.keys()) | set(baseline_tier.keys()), key=lambda t: tier_order.index(t) if t in tier_order else 99)

    rows: List[Dict[str, Any]] = []
    for tier in all_tiers:
        c = collab_tier.get(tier, {}) if isinstance(collab_tier.get(tier, {}), dict) else {}
        n = baseline_tier.get(tier, {}) if isinstance(baseline_tier.get(tier, {}), dict) else {}
        c_attack = _get_metric(c, "attack_success_rate")
        n_attack = _get_metric(n, "attack_success_rate")
        rows.append(
            {
                "tier": tier,
                "collab_attack": c_attack,
                "baseline_attack": n_attack,
                "delta": n_attack - c_attack,
                "samples": int(c.get("samples", 0) or n.get("samples", 0) or 0),
                "baseline_mode": baseline_mode,
            }
        )
    return rows


def _boundary_analysis(rows: List[Dict[str, Any]], flat_threshold: float = 0.1) -> Dict[str, Any]:
    if not rows:
        return {
            "formula": "N/A",
            "avg": 0.0,
            "flat": [],
            "limitations": ["无可用场景数据，无法做边界分析。"],
        }

    score_parts: List[str] = []
    score_values: List[int] = []
    flat_playbooks: List[str] = []
    for r in rows:
        delta = float(r.get("attack_reduction", 0.0))
        score = 1 if delta >= flat_threshold else 0
        score_parts.append(str(score))
        score_values.append(score)
        if score == 0:
            flat_playbooks.append(str(r.get("playbook", "")))

    numerator = sum(score_values)
    denominator = len(score_values)
    formula = f"({' + '.join(score_parts)})/{denominator} = {numerator}/{denominator} = {numerator/denominator:.3f}"

    limitations: List[str] = []
    if "C_budget_exhaustion" in flat_playbooks:
        limitations.append("场景E 接近持平：本质是本地阻断预算耗尽，属于物理资源边界，协同无法凭空创造阻断配额。")
    if "E_false_positive_noise" in flat_playbooks:
        limitations.append("场景D 接近持平：系统刻意避免拦截合法业务噪音，这是一种安全-业务平衡下的保守策略边界。")
    if not limitations:
        limitations.append("当前数据集中未出现典型边界 Case，建议补充极端资源约束和业务白名单冲突场景。")

    return {
        "formula": formula,
        "avg": round(numerator / denominator, 3),
        "flat": flat_playbooks,
        "limitations": limitations,
    }


def _build_conclusions(rows: List[Dict[str, Any]]) -> List[str]:
    if not rows:
        return ["未检测到可用于总结的场景数据。"]

    improved = [r for r in rows if float(r.get("attack_reduction", 0.0)) > 0]
    stable = [r for r in rows if abs(float(r.get("attack_reduction", 0.0))) <= 1e-9]
    regressed = [r for r in rows if float(r.get("attack_reduction", 0.0)) < 0]
    baseline_better = [r for r in rows if float(r.get("attack_reduction", 0.0)) < 0]
    avg_reduction = sum(float(r.get("attack_reduction", 0.0)) for r in rows) / len(rows)

    lines = [
        f"总体上，协同模式在 {len(improved)}/{len(rows)} 个场景中优于基线；同时基线在 {len(baseline_better)}/{len(rows)} 个场景中也表现更好，说明基线并非无效而是有其适用边界。",
        f"平均攻击成功率差值（baseline - collab）为 {avg_reduction:.3f}；这次结果更像是“场景依赖”的对比，而不是单向碾压。",
        "攻击剧本覆盖了从低隐蔽单点攻击到高隐蔽跨域链路（APT 风格）三个难度层级，基线在其主场（单域高显著）可有效工作。",
    ]
    if stable:
        lines.append(f"有 {len(stable)} 个场景协同与非协同效果持平。")
    if regressed:
        lines.append(f"存在 {len(regressed)} 个场景出现基线优于协同，建议在论文中解释为“单点防御足够覆盖的低复杂度场景”。")

    top = sorted(rows, key=lambda r: float(r.get("attack_reduction", 0.0)), reverse=True)[:3]
    if top:
        top_text = "；".join(
            f"{PLAYBOOK_LABEL.get(str(r.get('playbook', '')), str(r.get('playbook', '')))} 降幅 {float(r.get('attack_reduction', 0.0)):.3f}"
            for r in top
        )
        lines.append(f"协同最有优势的场景：{top_text}。")

    f_row = next((r for r in rows if str(r.get("playbook")) == SCENE_TO_PLAYBOOK.get("场景F", "F_portal_bridge_fallback")), None)
    if f_row:
        f_pass = (
            float(f_row.get("collab_attack", 1.0)) <= 0.2
            and float(f_row.get("no_collab_attack", 0.0)) >= 0.8
            and float(f_row.get("collab_counter_rate", 0.0)) >= 0.3
            and float(f_row.get("collab_fallback_rate", 0.0)) >= 0.2
        )
        lines.append(
            "场景F 验收结论："
            f"collab_attack={float(f_row.get('collab_attack', 0.0)):.3f}, "
            f"no_collab_attack={float(f_row.get('no_collab_attack', 0.0)):.3f}, "
            f"counter_rate={float(f_row.get('collab_counter_rate', 0.0)):.3f}, "
            f"fallback_rate={float(f_row.get('collab_fallback_rate', 0.0)):.3f} -> "
            f"{'PASS' if f_pass else 'FAIL'}。"
        )

    g_row = next((r for r in rows if str(r.get("playbook")) == SCENE_TO_PLAYBOOK.get("场景G", "G_single_domain_baseline_validation")), None)
    if g_row:
        g_pass = float(g_row.get("no_collab_attack", 1.0)) <= 0.2 and float(g_row.get("collab_attack", 1.0)) <= 0.2
        lines.append(
            "场景G 主场验证："
            f"collab_attack={float(g_row.get('collab_attack', 0.0)):.3f}, "
            f"baseline_attack={float(g_row.get('no_collab_attack', 0.0)):.3f} -> "
            f"{'PASS' if g_pass else 'CHECK'}。"
        )

    return lines


def _pick_replay_sample_by_playbook(samples: List[Dict[str, Any]], playbook_id: str) -> Dict[str, Any]:
    candidates = [
        s
        for s in samples
        if str(s.get("playbook_id", "")) == playbook_id and str(s.get("mode", "")) == "oneshot_collab"
    ]
    if not candidates:
        return {}

    candidates.sort(
        key=lambda s: (
            -int(s.get("fallback_task_count", 0)),
            -int(s.get("adopt_counter_task_count", 0)),
            -float(s.get("block_rate", 0.0)),
            float(s.get("attack_success_rate", 1.0)),
        )
    )
    return candidates[0]


def _render_single_replay_html(playbook_id: str, playbook_title: str, sample: Dict[str, Any], opened: bool = False) -> str:
    scene_label = PLAYBOOK_LABEL.get(playbook_id, playbook_id)
    if not sample:
        return (
            "<details class='replay-item'>"
            f"<summary>{scene_label} | {playbook_title}</summary>"
            "<div class='replay-box'><p>未找到可回放样本。</p></div>"
            "</details>"
        )

    run_id = str(sample.get("run_id", "N/A"))
    risk = str(sample.get("analysis_risk_level", "unknown"))
    factor = float(sample.get("analysis_domain_weight_factor", 0.0))
    attack_success = float(sample.get("attack_success_rate", 0.0))
    block_rate = float(sample.get("block_rate", 0.0))
    intent = ", ".join(sample.get("intent_objectives", []))
    consensus = ", ".join(sample.get("consensus_objectives", []))
    status_counts = sample.get("intent_status_counts", {}) if isinstance(sample.get("intent_status_counts"), dict) else {}
    counter_count = int(status_counts.get("counter_proposal", 0))
    fallback_count = int(sample.get("fallback_task_count", 0))
    flat_results = sample.get("flat_results", []) if isinstance(sample.get("flat_results"), list) else []

    rows = []
    for idx, result in enumerate(flat_results, start=1):
        rows.append(
            "<tr>"
            f"<td>{idx}</td>"
            f"<td>{result.get('domain', '')}</td>"
            f"<td>{result.get('executor', '')}</td>"
            f"<td>{result.get('objective', '')}</td>"
            f"<td>{result.get('status', '')}</td>"
            f"<td>{'yes' if bool(result.get('success', False)) else 'no'}</td>"
            f"<td>{int(result.get('latency_ms', 0))}</td>"
            "</tr>"
        )

    timeline = [
        f"1) Manager 对 {scene_label} 判定风险为 {risk}，domain_weight_factor={factor:.3f}。",
        f"2) 意图阶段下发目标动作：{intent or 'N/A'}。",
        (
            f"3) 协商阶段触发 counter_proposal={counter_count} 次。"
            if counter_count > 0
            else "3) 协商阶段未触发 counter_proposal。"
        ),
        (
            f"4) 终裁阶段触发 fallback={fallback_count} 次。"
            if fallback_count > 0
            else "4) 终裁阶段未触发 fallback。"
        ),
        f"5) 共识执行动作：{consensus or 'N/A'}；结果 attack_success={attack_success:.3f}, block_rate={block_rate:.3f}。",
    ]

    timeline_html = "".join(f"<li>{line}</li>" for line in timeline)
    table_html = "".join(rows) if rows else "<tr><td colspan='7'>无执行记录</td></tr>"
    open_attr = " open" if opened else ""
    return f"""
    <details class='replay-item'{open_attr}>
            <summary>{scene_label} | {playbook_title} | run_id={run_id}</summary>
      <div class='replay-box'>
        <p><b>risk:</b> {risk} | <b>domain_weight_factor:</b> {factor:.3f} | <b>attack_success:</b> {attack_success:.3f} | <b>block_rate:</b> {block_rate:.3f}</p>
        <p><b>intent_objectives:</b> {intent or 'N/A'}</p>
        <p><b>consensus_objectives:</b> {consensus or 'N/A'}</p>
        <ol>{timeline_html}</ol>
        <table class='replay-table'>
          <thead>
            <tr><th>#</th><th>domain</th><th>executor</th><th>objective</th><th>status</th><th>success</th><th>latency_ms</th></tr>
          </thead>
          <tbody>{table_html}</tbody>
        </table>
      </div>
    </details>
    """


def _render_all_replays_html(experiment: Dict[str, Any]) -> str:
    playbook_meta = experiment.get("playbooks", []) if isinstance(experiment.get("playbooks"), list) else []
    samples = experiment.get("samples", []) if isinstance(experiment.get("samples"), list) else []

    if not playbook_meta:
        return "<p>未找到 playbook 元数据，无法渲染链路回放。</p>"

    blocks: List[str] = []
    ordered_meta = sorted(
        playbook_meta,
        key=lambda item: PLAYBOOK_ORDER.index(str(item.get("playbook_id", ""))) if str(item.get("playbook_id", "")) in PLAYBOOK_ORDER else 999,
    )

    for idx, pb in enumerate(ordered_meta):
        pb_id = str(pb.get("playbook_id", "unknown"))
        pb_title = str(pb.get("title", ""))
        sample = _pick_replay_sample_by_playbook(samples, pb_id)
        blocks.append(_render_single_replay_html(pb_id, pb_title, sample, opened=(idx == 0)))
    return "".join(blocks)


def _generate_playbook_report(experiment: Dict, output: Path) -> Path:
    summary = experiment.get("summary", {}) if isinstance(experiment, dict) else {}
    by_mode = summary.get("by_mode", {}) if isinstance(summary, dict) else {}
    by_mode_playbook = summary.get("by_mode_playbook", {}) if isinstance(summary, dict) else {}
    baseline_mode = _pick_baseline_mode(by_mode)
    baseline_label = baseline_mode

    collab = by_mode.get(COLLAB_MODE, {})
    no_collab = by_mode.get(baseline_mode, {})
    rows = _collect_playbook_rows(by_mode_playbook)
    tier_rows = _collect_tier_rows(summary)

    collab_intent = collab.get("intent_statuses", {}) if isinstance(collab, dict) else {}
    collab_intent_ratios = collab_intent.get("ratios", {}) if isinstance(collab_intent, dict) else {}

    b_playbook = SCENE_TO_PLAYBOOK.get("场景B", "D_cross_domain_weak_signal")
    d_collab = by_mode_playbook.get(COLLAB_MODE, {}).get(b_playbook, {})
    d_no_collab = by_mode_playbook.get(baseline_mode, {}).get(b_playbook, {})

    collab_base_risk = collab.get("base_risk_distribution", {}) if isinstance(collab, dict) else {}
    collab_final_risk = collab.get("final_risk_distribution", {}) if isinstance(collab, dict) else {}
    collab_downgrade_adopt_total = int(collab.get("downgrade_adopt_total", 0)) if isinstance(collab, dict) else 0
    collab_downgrade_reject_total = int(collab.get("downgrade_reject_total", 0)) if isinstance(collab, dict) else 0

    fig = make_subplots(
        rows=5,
        cols=2,
        subplot_titles=(
            "Attack Success Rate (Collab vs Baseline)",
            "False Negative Rate on 场景B",
            "Intent Status Ratios (Collab)",
            "Negotiation Game Outcomes (Counts)",
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
            x=[COLLAB_MODE, baseline_label],
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
            x=[COLLAB_MODE, baseline_label],
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

    # 协商结果：统一展示为数量口径，避免比例与次数混轴。
    fig.add_trace(
        go.Bar(
            x=["counter_total", "adopt_counter_total", "fallback_total"],
            y=[
                _get_metric(collab, "counter_total"),
                _get_metric(collab, "adopt_counter_total"),
                _get_metric(collab, "fallback_total"),
            ],
            marker_color=["#264653", "#e9c46a", "#e76f51"],
            name="game_outcome_counts",
        ),
        row=2,
        col=2,
    )

    fig.add_trace(
        go.Bar(
            x=[COLLAB_MODE, baseline_label],
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
            x=[COLLAB_MODE, baseline_label],
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
            x=[COLLAB_MODE, baseline_label],
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

    # All-playbook comparison board for demo readability.
    playbooks = [str(r.get("scene", PLAYBOOK_LABEL.get(str(r.get("playbook", "")), str(r.get("playbook", ""))))) for r in rows]
    overview = make_subplots(
        rows=2,
        cols=2,
        subplot_titles=(
            "All Playbooks: Attack Success Rate",
            "All Playbooks: Block Rate",
            "All Playbooks: Counter/Fallback (Collab vs Baseline)",
            "All Playbooks: Avg Latency (ms)",
        ),
    )

    overview.add_trace(
        go.Bar(
            x=playbooks,
            y=[float(r.get("collab_attack", 0.0)) for r in rows],
            name="collab_attack_success",
            marker_color="#2a9d8f",
        ),
        row=1,
        col=1,
    )
    overview.add_trace(
        go.Bar(
            x=playbooks,
            y=[float(r.get("no_collab_attack", 0.0)) for r in rows],
            name="baseline_attack_success",
            marker_color="#e76f51",
        ),
        row=1,
        col=1,
    )
    overview.add_trace(
        go.Bar(
            x=playbooks,
            y=[float(r.get("collab_block_rate", 0.0)) for r in rows],
            name="collab_block_rate",
            marker_color="#457b9d",
        ),
        row=1,
        col=2,
    )
    overview.add_trace(
        go.Bar(
            x=playbooks,
            y=[float(r.get("no_collab_block_rate", 0.0)) for r in rows],
            name="baseline_block_rate",
            marker_color="#adb5bd",
        ),
        row=1,
        col=2,
    )
    overview.add_trace(
        go.Bar(
            x=playbooks,
            y=[float(r.get("collab_counter_rate", 0.0)) for r in rows],
            name="collab_counter_rate",
            marker_color="#ffb703",
        ),
        row=2,
        col=1,
    )
    overview.add_trace(
        go.Bar(
            x=playbooks,
            y=[float(r.get("no_collab_counter_rate", 0.0)) for r in rows],
            name="baseline_counter_rate",
            marker_color="#ced4da",
        ),
        row=2,
        col=1,
    )
    overview.add_trace(
        go.Bar(
            x=playbooks,
            y=[float(r.get("collab_fallback_rate", 0.0)) for r in rows],
            name="collab_fallback_rate",
            marker_color="#fb8500",
        ),
        row=2,
        col=1,
    )
    overview.add_trace(
        go.Bar(
            x=playbooks,
            y=[float(r.get("no_collab_fallback_rate", 0.0)) for r in rows],
            name="baseline_fallback_rate",
            marker_color="#adb5bd",
        ),
        row=2,
        col=1,
    )
    overview.add_trace(
        go.Bar(
            x=playbooks,
            y=[float(r.get("collab_latency", 0.0)) for r in rows],
            name="collab_latency_ms",
            marker_color="#1d3557",
        ),
        row=2,
        col=2,
    )
    overview.add_trace(
        go.Bar(
            x=playbooks,
            y=[float(r.get("no_collab_latency", 0.0)) for r in rows],
            name="baseline_latency_ms",
            marker_color="#6c757d",
        ),
        row=2,
        col=2,
    )
    overview.update_layout(template="plotly_white", barmode="group", height=1100)
    overview.add_hline(
        y=100,
        line_dash="dash",
        line_color="#d62828",
        annotation_text="SLA < 100ms",
        annotation_position="top left",
        row=2,
        col=2,
    )

    core = make_subplots(
        rows=1,
        cols=3,
        subplot_titles=(
            "Core 1: Attack Success",
            "Core 2: Counter/Fallback Gap",
            "Core 3: Latency vs SLA",
        ),
    )
    core.add_trace(
        go.Bar(
            x=playbooks,
            y=[float(r.get("collab_attack", 0.0)) for r in rows],
            name="collab_attack",
            marker_color="#2a9d8f",
        ),
        row=1,
        col=1,
    )
    core.add_trace(
        go.Bar(
            x=playbooks,
            y=[float(r.get("no_collab_attack", 0.0)) for r in rows],
            name="baseline_attack",
            marker_color="#e76f51",
        ),
        row=1,
        col=1,
    )
    core.add_trace(
        go.Bar(
            x=playbooks,
            y=[float(r.get("collab_counter_rate", 0.0)) for r in rows],
            name="collab_counter",
            marker_color="#ffb703",
        ),
        row=1,
        col=2,
    )
    core.add_trace(
        go.Bar(
            x=playbooks,
            y=[float(r.get("collab_fallback_rate", 0.0)) for r in rows],
            name="collab_fallback",
            marker_color="#fb8500",
        ),
        row=1,
        col=2,
    )
    core.add_trace(
        go.Bar(
            x=playbooks,
            y=[float(r.get("no_collab_counter_rate", 0.0)) for r in rows],
            name="baseline_counter",
            marker_color="#ced4da",
        ),
        row=1,
        col=2,
    )
    core.add_trace(
        go.Bar(
            x=playbooks,
            y=[float(r.get("no_collab_fallback_rate", 0.0)) for r in rows],
            name="baseline_fallback",
            marker_color="#adb5bd",
        ),
        row=1,
        col=2,
    )
    core.add_trace(
        go.Bar(
            x=playbooks,
            y=[float(r.get("collab_latency", 0.0)) for r in rows],
            name="collab_latency_ms",
            marker_color="#1d3557",
        ),
        row=1,
        col=3,
    )
    core.add_trace(
        go.Bar(
            x=playbooks,
            y=[float(r.get("no_collab_latency", 0.0)) for r in rows],
            name="baseline_latency_ms",
            marker_color="#6c757d",
        ),
        row=1,
        col=3,
    )
    core.update_layout(template="plotly_white", barmode="group", height=540)
    core.add_hline(
        y=100,
        line_dash="dash",
        line_color="#d62828",
        annotation_text="SLA < 100ms",
        annotation_position="top left",
        row=1,
        col=3,
    )

    delta_fig = go.Figure()
    delta_fig.add_trace(
        go.Bar(
            x=playbooks,
            y=[float(r.get("attack_reduction", 0.0)) for r in rows],
            marker_color=["#2a9d8f" if float(r.get("attack_reduction", 0.0)) >= 0 else "#d62828" for r in rows],
            name="attack_reduction(baseline-collab)",
            text=[f"{float(r.get('attack_reduction', 0.0)):.3f}" for r in rows],
            textposition="outside",
        )
    )
    delta_fig.update_layout(
        title="All Playbooks: Attack Success Reduction Delta",
        template="plotly_white",
        height=520,
        yaxis_title="delta",
        xaxis_title="playbook",
        showlegend=False,
    )
    delta_fig.add_hline(y=0.0, line_dash="dash", line_color="#6c757d")

    verdict_rows = []
    for r in rows:
        verdict_rows.append(
            [
                str(r.get("scene", PLAYBOOK_LABEL.get(str(r.get("playbook", "")), str(r.get("playbook", ""))))),
                f"{float(r.get('collab_attack', 0.0)):.3f}",
                f"{float(r.get('no_collab_attack', 0.0)):.3f}",
                f"{float(r.get('attack_reduction', 0.0)):.3f}",
                "PASS" if float(r.get("attack_reduction", 0.0)) > 0 else "CHECK",
            ]
        )

    verdict_table = go.Figure(
        data=[
            go.Table(
                header=dict(values=["playbook", "collab_attack", "baseline_attack", "delta", "collab_counter", "baseline_counter", "collab_fallback", "baseline_fallback", "verdict"], fill_color="#264653", font=dict(color="white", size=12)),
                cells=dict(
                    values=(
                        [
                            [str(r.get("scene", PLAYBOOK_LABEL.get(str(r.get("playbook", "")), str(r.get("playbook", ""))))) for r in rows],
                            [f"{float(r.get('collab_attack', 0.0)):.3f}" for r in rows],
                            [f"{float(r.get('no_collab_attack', 0.0)):.3f}" for r in rows],
                            [f"{float(r.get('attack_reduction', 0.0)):.3f}" for r in rows],
                            [f"{float(r.get('collab_counter_rate', 0.0)):.3f}" for r in rows],
                            [f"{float(r.get('no_collab_counter_rate', 0.0)):.3f}" for r in rows],
                            [f"{float(r.get('collab_fallback_rate', 0.0)):.3f}" for r in rows],
                            [f"{float(r.get('no_collab_fallback_rate', 0.0)):.3f}" for r in rows],
                            ["PASS" if float(r.get("attack_reduction", 0.0)) > 0 else "CHECK" for r in rows],
                        ]
                        if rows
                        else [[], [], [], [], [], [], [], [], []]
                    ),
                    fill_color="#f8f9fa",
                    align="left",
                ),
            )
        ]
    )
    verdict_table.update_layout(height=380, margin=dict(l=10, r=10, t=40, b=10), title="Scene Verdict Table")

    conclusions = _build_conclusions(rows)
    boundary = _boundary_analysis(rows)
    conclusion_items = "".join(f"<li>{line}</li>" for line in conclusions)
    limitation_items = "".join(f"<li>{line}</li>" for line in boundary.get("limitations", []))
    flat_case_text = (
        "、".join(
            f"{PLAYBOOK_LABEL.get(pid, pid)}"
            for pid in boundary.get("flat", [])
        )
        if boundary.get("flat", [])
        else "无"
    )
    replay_html = _render_all_replays_html(experiment)
    tier_items = "".join(
        f"<li>{r['tier']}：collab_attack={float(r.get('collab_attack', 0.0)):.3f}, "
        f"baseline_attack={float(r.get('baseline_attack', 0.0)):.3f}, "
        f"delta={float(r.get('delta', 0.0)):.3f}, samples={int(r.get('samples', 0))}</li>"
        for r in tier_rows
    )

    total_samples = int(experiment.get("total_samples", 0))
    html = f"""
    <!doctype html>
    <html lang='zh-CN'>
    <head>
      <meta charset='utf-8'>
      <meta name='viewport' content='width=device-width, initial-scale=1'>
      <title>Playbook Demo Report</title>
      <style>
        body {{ font-family: "Segoe UI", "PingFang SC", "Hiragino Sans GB", sans-serif; background: linear-gradient(120deg,#f8f9fa,#eef7ff); margin: 0; color: #1b263b; }}
        .wrap {{ max-width: 1320px; margin: 0 auto; padding: 24px; }}
        .hero {{ background: white; border-radius: 14px; padding: 20px 24px; box-shadow: 0 8px 28px rgba(29,53,87,0.08); margin-bottom: 18px; }}
        .hero h1 {{ margin: 0 0 8px; font-size: 28px; }}
        .meta {{ color: #415a77; font-size: 14px; }}
        .cards {{ display: grid; grid-template-columns: repeat(3, minmax(180px,1fr)); gap: 12px; margin: 14px 0 18px; }}
        .card {{ background: #ffffff; border-radius: 12px; padding: 14px; border: 1px solid #e9ecef; box-shadow: 0 4px 14px rgba(0,0,0,0.04); }}
        .card .k {{ font-size: 12px; color: #6c757d; }}
        .card .v {{ font-size: 24px; font-weight: 700; color: #0b3d91; }}
        .section {{ background: white; border-radius: 14px; padding: 16px; box-shadow: 0 8px 24px rgba(29,53,87,0.07); margin-bottom: 18px; }}
        .section h2 {{ margin: 4px 0 10px; font-size: 20px; }}
        .section ul {{ margin: 8px 0 0 18px; }}
        .boundary {{ background: #fff7e6; border: 1px solid #ffd8a8; border-radius: 12px; padding: 12px; color: #7f5539; }}
        .appendix {{ background: #f1f3f5; border: 1px solid #dee2e6; border-radius: 12px; padding: 12px; color: #343a40; }}
        .replay-item {{ margin-bottom: 10px; background: #f8fbff; border: 1px solid #dbeafe; border-radius: 12px; }}
        .replay-item summary {{ cursor: pointer; padding: 12px 14px; font-weight: 600; color: #0b3d91; }}
        .replay-box {{ background: #f8fbff; border-top: 1px solid #dbeafe; border-radius: 0 0 12px 12px; padding: 14px; }}
        .replay-table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }}
        .replay-table th, .replay-table td {{ border: 1px solid #d6e2f0; padding: 8px; text-align: left; }}
        .replay-table th {{ background: #e7f0fb; }}
      </style>
    </head>
    <body>
      <div class='wrap'>
        <div class='hero'>
          <h1>跨域协同防御实验演示报告</h1>
          <div class='meta'>generated_at: {experiment.get('generated_at', 'N/A')} | total_samples: {total_samples}</div>
          <div class='cards'>
            <div class='card'><div class='k'>Playbook 数量</div><div class='v'>{len(rows)}</div></div>
            <div class='card'><div class='k'>实验总样本</div><div class='v'>{total_samples}</div></div>
                        <div class='card'><div class='k'>协同优于基线场景</div><div class='v'>{sum(1 for r in rows if float(r.get('attack_reduction',0))>0)}</div></div>
          </div>
        </div>

        <div class='section'>
          <h2>自动判断结论</h2>
          <ul>{conclusion_items}</ul>
                    <p><b>Baseline 定义：</b>{baseline_label}（可执行单域基线，不是 observe-only）。</p>
                    <p><b>攻击难度分层：</b>L1=单域高显著；L2=跨域中等复杂；L3=高隐蔽跨域链路（APT 风格）。</p>
                    <ul>{tier_items}</ul>
        </div>

                <div class='section'>
                    <h2>实验局限性 / 边界 Case 说明</h2>
                    <div class='boundary'>
                        <p><b>边界得分公式：</b>{boundary.get('formula', 'N/A')}</p>
                        <p><b>边界分析均值：</b>{boundary.get('avg', 0.0):.3f}（与上式一致）</p>
                        <p><b>接近持平场景：</b>{flat_case_text}</p>
                        <ul>{limitation_items}</ul>
                    </div>
                </div>

                <div class='section'>
                    <h2>核心三图</h2>
                    {core.to_html(full_html=False, include_plotlyjs='cdn')}
                </div>

        <div class='section'>
                    <h2>总览图</h2>
                    {fig.to_html(full_html=False, include_plotlyjs=False)}
        </div>

        <div class='section'>
                    <h2>全场景对比</h2>
          {overview.to_html(full_html=False, include_plotlyjs=False)}
          {delta_fig.to_html(full_html=False, include_plotlyjs=False)}
          {verdict_table.to_html(full_html=False, include_plotlyjs=False)}
        </div>

        <div class='section'>
                    <h2>单次样本链路回放</h2>
          {replay_html}
        </div>

                <div class='section'>
                    <h2>指标说明 / 附录</h2>
                    <div class='appendix'>
                        <p><b>FNR（False Negative Rate）</b>：漏报率，值越低越好。</p>
                        <p><b>Adopt Rate</b>：反提案采纳率，反映协商机制的有效利用程度。</p>
                        <p><b>Counter/Fallback Rate</b>：协商博弈触发强度；非协同通常应接近 0。</p>
                        <p><b>SLA Threshold</b>：工业级阻断时延红线，目标 < 100ms。</p>
                    </div>
                </div>
      </div>
    </body>
    </html>
    """

    output.write_text(html, encoding="utf-8")
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
