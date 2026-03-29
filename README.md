# Cross-Domain Defense Prototype

本项目是一个用于毕业论文验证的“跨域协同防御”原型系统，采用“管理器（Manager）+执行器（Executor）”双层智能体架构，支持跨进程/跨设备异步通信、全局协同决策与本地战术响应。

## 目录结构（整理后）

```text
code-a/
├── manager/                 # 管理器侧规则/策略模型
├── communication/           # 异步通信与消息协议
├── executor/                # 执行器侧 API 与本地执行逻辑
├── simulation/              # 实验仿真与报告生成
├── utils/                   # 通用工具
├── results/                 # 实验输出（JSON/HTML）
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## 核心能力

- 标准化消息协议（告警、任务、控制指令、执行回执）
- 基于异步队列的跨组件通信
- 管理器：多源告警汇聚、跨域攻击研判、协同任务生成与下发
- 执行器：本地日志研判、通用任务解析、设备级控制指令转换
- 仿真：支持跨域攻击脚本、全流程实验（攻击-侦察-上报-决策-阻断）

## 环境准备（本地）

```bash
python -m venv .venv
. .venv/Scripts/activate  # Windows PowerShell: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 启动方式（Docker）

1) 启动 Manager + 2 个 Executor：

```bash
docker compose up -d --build manager executor_office executor_core

```

2) 运行实验脚本：

```bash
docker compose build experiment
docker compose run --rm experiment
```

权限说明（避免 `results` 目录出现 root 文件）：

- 项目根目录已提供 `.env`（`UID/GID`），`experiment` 容器会默认以当前用户身份写入 `results/`。
- 如果历史上跑过 root 容器导致 `results/` 变成 root 所有，可执行一次修复：

```bash
sudo chown -R $(id -u):$(id -g) results
chmod 775 results
```

3) 查看结果：

- 实验结束后会自动生成：
  - `results/experiment_*.json`（结构化结果）
  - `results/report_*.html`（可视化图表报告）
- 直接用浏览器打开 `results/report_*.html` 即可查看对比图（阻断率、时延、成功失败占比、域维度统计）。

4) 结果可复现参数（可选）：

```bash
# 实验侧
export EXPERIMENT_SEED=20260325
export SCENARIO_ID=A_lateral_penetration
export ATTACK_MIX_THRESHOLD=0.45
export SCRIPTED_ATTACK_THRESHOLD=0.25

# 执行器侧（分别设置 office/core）
export EXECUTOR_SEED=20260326
export EXECUTOR_SUCCESS_RATE=0.92
export EXECUTOR_LATENCY_MIN_MS=20
export EXECUTOR_LATENCY_MAX_MS=120
```

同一套参数下重复运行，`results/experiment_*.json` 中的 `reproducibility` 字段会记录本次实验配置，便于复跑与论文附录留档。

场景建议值：
- `A_lateral_penetration`：Web 域受控后向核心域横向渗透。
- `B_privilege_data_theft`：办公域权限扩散并尝试访问核心敏感数据。

5) 切换场景（具体步骤）：

方式 A：单次运行临时切换（不改配置文件）

```bash
docker compose run --rm -e SCENARIO_ID=A_lateral_penetration experiment
docker compose run --rm -e SCENARIO_ID=B_privilege_data_theft experiment
```

方式 B：固定默认场景（修改 compose 后多次复用）

```bash
# 1) 编辑 docker-compose.yml 中 experiment 服务的 SCENARIO_ID
# 2) 重新运行
docker compose build experiment
docker compose run --rm experiment
```

方式 C：本地脚本切换

```bash
export SCENARIO_ID=A_lateral_penetration
python simulation/experiment_runner.py

export SCENARIO_ID=B_privilege_data_theft
python simulation/experiment_runner.py
```

运行时会在控制台打印 `scenario=...`，并写入结果 JSON 的 `reproducibility.scenario_id` 字段。

## 启动方式（本地）

1) 启动管理器 API：

```bash
start uvicorn manager.api_server:app --host 0.0.0.0 --port 8000
```

2) 启动两个执行器 API（不同端口、不同域）：

```bash
$env:EXECUTOR_DOMAIN="office"; $env:EXECUTOR_ID="executor-office"; start uvicorn executor.api_server:app --host 0.0.0.0 --port 8101
$env:EXECUTOR_DOMAIN="core"; $env:EXECUTOR_ID="executor-core"; start uvicorn executor.api_server:app --host 0.0.0.0 --port 8102
```

3) 运行实验：

```bash
python simulation/experiment_runner.py
```

## 默认实验流程

- 攻击脚本模拟跨域横向移动行为
- 执行器上报本地告警到管理器
- 管理器研判并生成协同任务
- 执行器将通用任务转化为 IDS/防火墙控制指令
- 对比“启用协同防御/未启用”两组结果（阻断率、响应时延）

## 剧本驱动实验（论文统计版）

实验脚本已切换为确定性 playbook 模式（`simulation/playbooks.py`），不再依赖完全随机流量。

- 四个核心场景：
  - A：无分歧协同（Happy Path）
  - B：关键资产保护触发反提案
  - C：资源受限协同（预算耗尽）
  - D：跨域弱信号融合
- 每个场景在两种模式下各运行 50 次：
  - `oneshot_collab`（一轮协同）
  - `no_collab`（无协同对照）
- 默认总样本数：`4 * 50 * 2 = 400`

可选参数：

```bash
export PLAYBOOK_RUNS=50
export PLAYBOOK_JITTER_MS=120
export INTER_EVENT_SLEEP_JITTER_MS=60
export EXPERIMENT_SEED=20260327
python3 simulation/experiment_runner.py
```

说明：
- `PLAYBOOK_JITTER_MS` 用于时间戳级微扰动（保证可复现实验下的统计离散性）。
- `INTER_EVENT_SLEEP_JITTER_MS` 用于注入时的微小发送间隔抖动。
- 脚本会自动执行 manager/executor 的调试重置接口，保证每次 run 状态独立。

## 自治决策设计（毕设原型版）

为控制复杂度并保持可解释性，本项目在策略层采用“静态规则 + 离散状态”方案，不引入机器学习评分模型。

### 执行器（Executor）本地自治单元

- 本地态势状态：`risk_score`、`confidence`、`top_alert_types`、`resource_status`。
- 任务预检三态：`accept` / `reject` / `counter_proposal`。
- 标准化理由码：通过 `reason_code` 输出，便于 Manager 汇总与答辩解释。
- 典型规则：关键资产（`asset_level=critical`）命中隔离类任务时，返回 `counter_proposal(degrade_traffic)`。

执行器关键环境变量：

```bash
export EXECUTOR_MAX_BLOCK_ACTIONS=5
export EXECUTOR_FAILURE_THRESHOLD=3
export EXECUTOR_WHITELIST_ASSETS=core-db,erp-master
```

### 管理器（Manager）全局融合（离散矩阵）

- 关联键：`src_ip`、`dst_ip`、时间窗（默认 5 秒）、攻击阶段 `stage`。
- 输出结构：`incident_graph`、`evidence_set`、`inferred_stage`、`contribution_by_domain`。
- 全局置信度：采用离散决策矩阵（`low/medium/high`），不使用连续加权系数。
- 策略生成：输出候选计划集 `action_plan_candidates`，每个候选使用离散等级 `utility/cost/expected_risk_reduction`。

全局矩阵增强（Domain Weight Factor）：

- 在基础决策矩阵之后，引入域权重因子（`domain_weight_factor`）做轻量校准。
- 核心思想：同等风险证据下，Core 域参与占比越高，整体风险等级可上调一级（受阈值约束）。
- 配置文件：`manager/configs/risk_matrix.yaml`
- 输出字段：`base_risk_level`、`domain_weight_factor`、`domain_weight_calibrated`。

### 终裁策略（Data-Driven）

Manager 的终裁阶段采用数据驱动动作策略表，不再使用纯硬编码分支：

- 配置文件：`manager/configs/action_policy.yaml`
- 关键字段：`security_gain`（安全增益）、`business_cost`（业务代价）
- 最低安全增益阈值 `min_gain` 按全局风险自动设定：
  - `Critical -> 8`
  - `High -> 6`
  - `Medium -> 4`
  - `Low -> 2`

终裁规则：

1) 若 Executor 反提案 `security_gain >= min_gain`，Manager 采纳反提案。
2) 若反提案低于阈值，Manager 按 `fallback_by_risk` 选择兜底动作。
3) 兜底动作会结合 `reason_code` 约束（`reason_disallow_actions`）过滤不可执行动作。

增强规则：

- Domain Criticality：`domain_min_gain_offset` 参与阈值计算，`core` 域可配置更高门槛（更低容忍降级）。
- Confidence Gate：当反提案会降低防御强度且 Executor `confidence` 低于阈值（`min_confidence_for_downgrade`）时，Manager 会提高有效门槛，倾向拒绝低置信度降级建议。

运行时可通过环境变量覆盖策略文件：

```bash
export ACTION_POLICY_FILE=/app/manager/configs/action_policy.yaml
```

示例决策矩阵（说明性）：

- Web 域 `medium` + Core 域 `low` + 5 秒内出现跨域关联边 => 全局 `high`。
- 多域存在 `high` 且存在跨域关联边 => 全局 `critical`。

## 关键接口（新增）

### Executor API

- `GET /local-situation`：查询执行器本地态势快照。
- `POST /tasks`：返回执行结果时支持三态 `status`，并在 `details` 中提供 `reason_code`、`proposed_action`。

### Manager API

- `POST /executors/local-situation`：接收执行器本地态势上报。
- `GET /executors/local-situation`：查询当前各执行器态势。
- `POST /decision/trigger`：返回 `analysis`（含证据融合）与 `decision`（含候选计划）。

## 最小响应示例

当任务触发关键资产保护时，Executor 可能返回：

```json
{
  "task_id": "...",
  "status": "counter_proposal",
  "success": false,
  "details": {
    "decision_source": "task_parser",
    "reason_code": "CRITICAL_ASSET_PROTECTED",
    "proposed_action": "degrade_traffic"
  }
}
```

该行为可用于证明“执行器并非被动执行，而是可基于本地约束参与协同决策”。

## 一轮协商最小联调脚本

新增脚本：`simulation/minimal_negotiation_smoke.py`

用途：

- 检查 `manager`、`executor_office`、`executor_core` 健康状态。
- 注入两条可跨域关联的告警。
- 触发一次 `decision/trigger`，并输出 one-shot negotiation 摘要（intent -> consensus）。

运行示例：

```bash
python3 simulation/minimal_negotiation_smoke.py
```

可选环境变量：

```bash
export MANAGER_SERVICE=http://127.0.0.1:8000
export EXECUTOR_OFFICE_SERVICE=http://127.0.0.1:8101
export EXECUTOR_CORE_SERVICE=http://127.0.0.1:8102
python3 simulation/minimal_negotiation_smoke.py
```

成功时会打印：

- `mode=one_shot`
- `intent_statuses=[...]`
- `consensus_statuses=[...]`
- `analysis_risk=...`

## 文件逻辑说明

### Manager / 决策侧
- `manager/api_server.py`：Manager 侧 API 服务入口（告警接收 / 决策触发）。
- `manager/rule_engine.py`：规则引擎，评估跨域攻击与风险等级。
- `manager/decision_tree.py`：策略选择与任务清单生成。
- `manager/model_loader.py`：加载规则引擎 / 决策树模型。

### Communication / 通信侧
- `communication/async_client.py`：异步 HTTP 客户端（组件间通信）。
- `communication/message_protocol.py`：消息协议与数据结构定义。
- `communication/message_queue.py`：内存异步消息队列。

### Executor / 执行侧
- `executor/api_server.py`：Executor 侧 API 服务入口（接收任务 / 本地日志）。
- `executor/base_executor.py`：执行器基类（日志处理接口）。
- `executor/local_analyzer.py`：本地日志研判与告警生成。
- `executor/task_parser.py`：任务解析（通用任务 -> 设备操作）。
- `executor/device_controller.py`：设备控制适配层（模拟实现）。

### Simulation / 仿真与报告
- `simulation/experiment_runner.py`：实验脚本入口（对比启用/不启用防御）。
- `simulation/traffic_generator.py`：本地日志/流量生成器。
- `simulation/report_generator.py`：实验报告 HTML 生成。
- `simulation/attack_scripts/cross_domain_attack.py`：跨域攻击样例与告警生成。

### Utilities / 工具
- `utils/logger.py`：统一日志格式。
- `utils/config_loader.py`：YAML 配置读取。

### 部署与依赖
- `docker-compose.yml`：一键启动 Manager / Executor / 实验脚本。
- `Dockerfile`：实验与服务的基础镜像构建。
- `requirements.txt`：Python 依赖。

## 说明

- 本原型重点展示架构与流程完整性，设备控制通过 `device_controller.py` 中的模拟接口实现。
- 如需对接真实 IDS/防火墙，只需替换设备控制适配逻辑。
