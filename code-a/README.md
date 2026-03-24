# Cross-Domain Defense Prototype

本项目是一个用于毕业论文验证的“跨域协同防御”原型系统，采用“管理器（Manager）+执行器（Executor）”双层智能体架构，支持跨进程/跨设备异步通信、全局协同决策与本地战术响应。

## 目录结构（整理后）

```text
code-a/
├── ai_models/               # 管理器侧规则/策略模型
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

3) 查看结果：

- 实验结束后会自动生成：
  - `results/experiment_*.json`（结构化结果）
  - `results/report_*.html`（可视化图表报告）
- 直接用浏览器打开 `results/report_*.html` 即可查看对比图（阻断率、时延、成功失败占比、域维度统计）。

## 启动方式（本地）

1) 启动管理器 API：

```bash
start uvicorn ai_models.api_server:app --host 0.0.0.0 --port 8000
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

## 文件逻辑说明

### Manager / 决策侧
- `ai_models/api_server.py`：Manager 侧 API 服务入口（告警接收 / 决策触发）。
- `ai_models/rule_engine.py`：规则引擎，评估跨域攻击与风险等级。
- `ai_models/decision_tree.py`：策略选择与任务清单生成。
- `ai_models/model_loader.py`：加载规则引擎 / 决策树模型。

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
