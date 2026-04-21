# Cross-Domain Defense Prototype (跨域协同防御原型系统)

本项目用于毕业论文验证，目标是构建并评估一个可解释、可复现实验的跨域协同防御闭环系统。
系统采用 Manager + Executor 双层智能体架构，覆盖从告警注入、跨域关联、反提案协商到终裁执行反馈的完整链路。

## 项目简介

核心目标：
- 在跨域弱信号场景中降低漏报。
- 在本地资源受限/关键资产约束下支持反提案（counter proposal）协商，而非单向强制执行。
- 在误报噪音场景中避免过度阻断，实现“既能抓攻击，也尽量不扰民”。

## 核心特性

- 标准异步通信：统一消息协议（告警、任务、执行回执、本地态势）。
- 全局融合研判：Manager 基于 incident graph + 决策矩阵 + 域权重进行风险判定。
- 本地自治协商：Executor 可返回 accept/reject/counter_proposal 三态结果。
- 数据驱动终裁：Manager 按 action_policy.yaml 的收益阈值进行反提案采纳，或回退到兜底动作（fallback）。
- 自动化实验输出：批量跑剧本并生成 JSON 与 HTML 报告。

## 目录与架构

```text
code-a/
├── manager/                              # 全局研判与协同终裁
│   ├── api_server.py                     # Manager API 入口；决策触发、协商与终裁编排
│   ├── decision_tree.py                  # 策略候选与联合行动计划生成
│   ├── rule_engine.py                    # 跨域关联图构建、基础风险评估与域权重校准
│   ├── model_loader.py                   # 模型/规则加载入口
│   └── configs/
│       ├── action_policy.yaml            # 动作收益/代价、min_gain、兜底动作（fallback）与约束策略
│       └── risk_matrix.yaml              # 风险矩阵与域权重校准阈值配置
├── executor/                             # 本地自治执行与设备动作映射
│   ├── api_server.py                     # Executor API 入口；任务接收、回执与本地态势上报
│   ├── local_analyzer.py                 # 本地日志研判、风险/置信度估计与告警生成
│   ├── task_parser.py                    # 通用任务预检与设备能力解析（含反提案）
│   ├── device_controller.py              # 防火墙/IDS 动作模拟执行层
│   └── base_executor.py                  # 执行器基类与公共行为
├── communication/                        # 组件间异步通信与协议定义
│   ├── message_protocol.py               # 消息类型与数据结构（告警/任务/回执）
│   ├── async_client.py                   # 异步 HTTP 客户端封装
│   └── message_queue.py                  # 内存消息队列实现
├── simulation/                           # 剧本实验与报告生成
│   ├── playbooks.py                      # A-G 场景定义与事件物化
│   ├── experiment_runner.py              # 批量实验执行、指标聚合与结果落盘
│   ├── report_generator.py               # Plotly 报告绘制与 HTML 导出
│   ├── minimal_negotiation_smoke.py      # 一轮协商最小联调脚本
│   └── attack_scripts/                   # 攻击过程与效果评估脚本
├── utils/                                # 通用工具
│   ├── logger.py                         # 日志格式与实例化
│   └── config_loader.py                  # YAML 配置加载
├── results/                              # 实验输出目录（JSON/HTML）
├── docker-compose.yml                    # 服务编排与容器运行参数
├── Dockerfile                            # 统一镜像构建文件
├── requirements.txt                      # Python 依赖清单
└── README.md                             # 项目说明文档
```

## 快速部署（Docker，推荐）

1. 启动核心服务（Manager + 3 个执行器）

```bash
docker compose up -d --build manager executor_office executor_core executor-portal
```

2. 运行实验

```bash
docker compose build experiment
docker compose run --rm experiment
```

3. 查看结果

- 结果目录：results/
- 结构化结果：results/experiment_*.json
- 可视化报告：results/report_*.html

4. 权限说明（results 目录）

项目根目录已提供 .env（UID/GID），experiment 容器默认以当前用户身份写入 results。
若历史运行产生 root 所有文件，可执行：

```bash
sudo chown -R $(id -u):$(id -g) results
chmod 775 results
```

注意：请避免使用 sudo docker compose ...，否则会再次生成 root 权限产物。

## 实验与仿真验证

### Playbook 场景

当前为 7 个核心场景，双模式对照：
- 模式 1：oneshot_collab（一轮协同）
- 模式 2：single_domain_baseline（可执行单域基线，不启用跨域协同改写）

场景定义：
- A_happy_path：无分歧协同，验证闭环时延与阻断效果。
- D_cross_domain_weak_signal：Portal -> Office -> Core 三节点微弱信号叠加提权，验证防御前置。
- B_critical_asset_counter：关键资产触发反提案（如 degrade_traffic）。
- E_false_positive_noise：误报噪音场景，验证低置信度拒绝阻断。
- C_budget_exhaustion：资源预算受限下的反提案协商与兜底动作（fallback）。
- F_portal_bridge_fallback：Portal 失陷后跳板攻击 Office，Office 因关键资产拒绝阻断，Manager 改派 Portal 源头封堵。
- G_single_domain_baseline_validation：单域高显著攻击（仅 Portal 域），用于验证传统单点基线在主场场景可有效阻断。

默认样本规模：
- 每场景每模式 50 次
- 总样本数 = 7 * 50 * 2 = 700

难度分层建议：
- L1：单域高显著攻击（传统基线主场）
- L2：跨域中等复杂链路
- L3：高隐蔽跨域链路（APT 风格）

论文叙事建议：
- 强调 L3 场景模拟的是高级持续性威胁（APT）与高度隐蔽跨域攻击，常规单点检测在该类场景下性能下降属于预期现象。
- 同时给出 L1 场景结果，证明基线在其主场并非失效，而是跨域复杂场景适应性不足。

### 常用参数

```bash
export PLAYBOOK_RUNS=50
export PLAYBOOK_JITTER_MS=120
export INTER_EVENT_SLEEP_JITTER_MS=60
export EXPERIMENT_SEED=20260327
docker compose run --rm experiment
```

说明：
- 若你修改了 manager 或 experiment 代码，请先重建镜像再运行：

```bash
docker compose build manager experiment
docker compose run --rm experiment
```

### 演示模式（老师答辩推荐）

1. 一键输出全场景结论 + 生成演示版 HTML

```bash
python3 presentation_summary.py
```

或显式使用子目录脚本：

```bash
python3 simulation/presentation_summary.py
```

输出内容包含：
- 全部 Playbook 的协同/非协同攻击成功率对比与 PASS/CHECK 结论
- Playbook F 的快速验收结论（PASS/FAIL）
- 演示版报告 HTML：results/presentation_*.html（含全场景图表 + 自动结论 + 单次样本链路回放）

2. 仅验证 Playbook F 是否通过

```bash
python3 simulation/verify_playbook_f.py
```

## 核心协同机制（论文重点）

### 1) 动态风险校准

Manager 先给出 base_risk_level，再结合 domain_weight_factor 做校准，输出 risk_level。
在 D 场景中，单域中危弱信号可在跨域关联后校准到更高风险等级。

关键输出字段：
- base_risk_level
- domain_weight_factor
- domain_weight_calibrated
- risk_level

### 2) 反提案协商与局部自治

Executor 对任务做本地预检，返回三态：
- accept
- reject
- counter_proposal

典型触发：
- 关键资产保护（CRITICAL_ASSET_PROTECTED）
- 资源阻断额度耗尽（RESOURCE_BLOCK_LIMIT）
- 连续失败降级（FAILURE_STREAK_DEGRADE）

### 3) 数据驱动终裁（含兜底动作）

Manager 读取 manager/configs/action_policy.yaml 进行终裁。

当前阈值：
- Critical -> 5
- High -> 4
- Medium -> 3
- Low -> 2

当前域偏移：
- core -> 0
- office -> 0

终裁逻辑：
- 反提案 security_gain 达阈值则采纳。
- 反提案不达阈值时，按 fallback_by_risk 和 reason_disallow_actions 选择兜底动作（fallback）。
- 对低置信降级提案可附加额外门槛（confidence_policy）。

## 报告指标概览

HTML 报告默认包含：
- 协同 vs 非协同攻击成功率
- D 场景漏报率对比
- 协商状态比例与博弈结果
- 降级反提案采纳率（饼图）
- 低置信阻断拒绝计数（柱状图）
- 基础风险 vs 校准风险（折线图）
- 时延、横向扩散阻断、域权重校准指标

## 附录：API 与本地启动

### 最小联调脚本

```bash
python3 simulation/minimal_negotiation_smoke.py
```

可选环境变量：

```bash
export MANAGER_SERVICE=http://127.0.0.1:8000
export EXECUTOR_OFFICE_SERVICE=http://127.0.0.1:8101
export EXECUTOR_CORE_SERVICE=http://127.0.0.1:8102
export EXECUTOR_PORTAL_SERVICE=http://127.0.0.1:8103
```

### 本地非 Docker 启动

1. 安装依赖

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. 启动 Manager

```bash
uvicorn manager.api_server:app --host 0.0.0.0 --port 8000
```

3. 启动 Executor（三个终端）

```bash
export EXECUTOR_DOMAIN=office
export EXECUTOR_ID=executor-office
uvicorn executor.api_server:app --host 0.0.0.0 --port 8101
```

```bash
export EXECUTOR_DOMAIN=core
export EXECUTOR_ID=executor-core
uvicorn executor.api_server:app --host 0.0.0.0 --port 8102
```

```bash
export EXECUTOR_DOMAIN=portal
export EXECUTOR_ID=executor-portal
export CRITICAL_ASSETS=portal-web,nginx-gateway
uvicorn executor.api_server:app --host 0.0.0.0 --port 8103
```

4. 运行实验

```bash
python3 simulation/experiment_runner.py
```

## 说明

本原型重点展示跨域协同架构、可解释风险研判与协商闭环。
实际设备动作由 executor/device_controller.py 模拟，可按真实防火墙/IDS API 进行替换。
