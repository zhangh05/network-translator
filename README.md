# Network-Translator-Agent v2

# 🌐 网络配置翻译助手（Graph/IR Edition）

基于 **Graph + IR** 架构构建的 AI 网络配置翻译智能体，支持 Cisco / 华为 / 华三 / 锐捷 配置的语义等价互译。

> 不是正则替换翻译器，而是由 LLM 驱动、规则引擎兜底的 Graph 工作流智能体。

---

## 部署

### 依赖

```bash
# 创建虚拟环境
python3 -m venv venv
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

### 配置

复制环境变量模板并编辑：

```bash
cp .env.example .env
# 编辑 .env，至少设置 LLM_API_KEY
```

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `LLM_API_KEY` | LLM API 密钥 | — |
| `LLM_BASE_URL` | LLM API 地址 | `https://api.minimaxi.com/anthropic` |
| `LLM_MODEL` | 模型名称 | `MiniMax-M2.7` |
| `PORT` | 监听端口 | `5008` |
| `HOST` | 监听地址 | `0.0.0.0` |
| `WORKERS` | Gunicorn 工作进程数 | `4` |

### 启动

```bash
# 启动服务（gunicorn，默认端口 5008）
./scripts/start.sh

# 检测状态
./scripts/status.sh

# 停止
./scripts/stop.sh

# 重启
./scripts/restart.sh
```

### 验证

```bash
# 健康检查
curl --noproxy '*' http://localhost:5008/healthz

# 就绪检查
curl --noproxy '*' http://localhost:5008/readyz

# 版本信息
curl --noproxy '*' http://localhost:5008/api/version
```

详细运维手册见 [docs/OPERATIONS.md](docs/OPERATIONS.md)，
发布检查清单见 [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md)。

---

## 核心架构

```
用户输入
    ↓
web_app.py / run.py
    ↓
project_store.run_translation()
    ↓
GraphAgent.run()
    ↓
execute_translation_flow(graph)
         ┌─────────────────────────────────────────────────────┐
         │                                                      │
         ▼                                                      ▼
  ┌──────────┐    ┌────────────┐    ┌────────────┐    ┌─────────────┐
  │ ParseNode │───▶│KnowledgeNode│───▶│TranslateNode│───▶│SemanticVal │
  └──────────┘    └────────────┘    └────────────┘    └─────────────┘
         │                                         │
         ▼                                         ▼
  ┌──────────┐    ┌──────────┐    ┌────────────┐    ┌─────────────┐
  │ RouteNode │◀──│FallbackNode│   │ ValidateNode│───▶│  DiffNode   │
  └──────────┘    └──────────┘    └────────────┘    └─────────────┘
                                               │
                                               ▼
                                        ┌─────────────┐
                                        │ MemoryNode  │
                                        └─────────────┘
```

**节点说明：**

| 节点 | 作用 |
|------|------|
| **ParseNode** | 结构化解析配置 → 特征检测（vendor/platform/feature） |
| **KnowledgeNode** | 按特征检索 `knowledge_data/` Markdown，写入 prompt context |
| **TranslateNode** | LLM 驱动：parse_to_ir → translate_ir（单次调用，无双次翻译） |
| **SemanticValidatorNode** | 规则引擎比对 IR block，检测语义丢失 |
| **RouteNode** | 无错误 → ValidateNode；有问题 → FallbackNode |
| **FallbackNode** | 无 LLM 时：RuleBasedTranslator 规则引擎兜底 |
| **ValidateNode** | 平台残留检测（40+ 模式）+ 风格检查 + must_include/must_not_include |
| **DiffNode** | 原文 vs 译文 diff 输出 |
| **MemoryNode** | 翻译事件持久化到 `events.jsonl` |

**风险决策模型：** `RiskDecision` 决定 deployability + manual_review_required：
- platform residue → deployable=false, mr=true
- critical content warnings → deployable=false
- non-blocking warnings → deployable=true, mr=true
- clean → deployable=true, mr=false

### 文件结构

```
network-translator/
├── core/
│   ├── __init__.py          # LLM singleton (Anthropic+OpenAI), lazy, thread-safe
│   ├── graph/                # Node/Edge/State 图执行引擎
│   │   ├── nodes.py          # 9 个工作流节点
│   │   └── translation_graph.py  # DAG 定义
│   ├── ir.py                 # Intermediate Representation (parse_to_ir / translate_ir / compare_ir)
│   ├── semantic_compare.py   # 规则引擎语义比对
│   ├── rule_translator.py     # RuleBasedTranslator fallback
│   ├── risk_decision.py      # RiskDecision 模型
│   └── context.py            # GSSC 流水线 (Gather→Select→Structure→Compress)
├── tools/
│   └── __init__.py          # ConfigParser, ConfigDiffer, ConfigValidator, KnowledgeRetriever
├── bench/
│   ├── run_cases.py          # 基准测试 runner (tier: smoke/core/full)
│   └── cases/               # 测试用例 (corpus/ + extra/)
├── knowledge_data/           # 生产知识库 Markdown
├── corpus/                   # 语料库 (sanitized + annotations)
├── reports/                  # 测试报告、coverage matrix
├── scripts/
│   └── service.sh           # gunicorn 启动脚本 (GUNICORN_TIMEOUT=240)
├── web_app.py                # Flask Web 界面
├── run.py                    # CLI 入口
└── MAINTENANCE.md           # 已知限制
```

---

## 质量指标

```
Release gates:     8/8 PASS
Static bench:     15/15 corpus / 50/50 total
Pytest:           486/486 passed
Live corpus:      14/15 (93%)  ← fw-nat-001 为已知 LLM 非确定性问题
Timeout 对齐:     GUNICORN_TIMEOUT=240 ≥ LLM_TIMEOUT=180 + 60s buffer
```

**Production tag：** `v11-phase7-production-ready`

**Known limitation：**
`fw-nat-001` NAT 场景存在 LLM 输出非确定性，validator 在出现 MANUAL_REVIEW 标记时正确阻断 deployability。未观察到 false deployable。

---

## 运行方式

### CLI

```bash
cd network-translator
source venv/bin/activate
export LLM_API_KEY=your_key
export LLM_MODEL=MiniMax-M2.7
export LLM_BASE_URL=https://api.minimaxi.com/anthropic
export LLM_TIMEOUT=180
python3 run.py
```

### Web

```bash
python3 web_app.py
# 访问 http://localhost:5008
```

### 测试

```bash
# 单元测试
PYTHONPATH=. ./venv/bin/pytest tests/ -q

# 基准测试（静态）
python3 bench/run_cases.py --corpus-only --static-only

# 基准测试（Live，需 gunicorn 运行）
PYTHONPATH=. python3 bench/run_cases.py --corpus-only \
  --api-base http://127.0.0.1:5008 \
  --live-report-json bench/live_report.json

# 发布门禁
python3 scripts/release_gate.py --mode release
```

---

## 已知缺陷

> 以下为当前生产版本仍存在的限制，部分已通过机制缓解。

### 高级别

**1. LLM 语义翻译依赖 API，无本地 fallback**
RuleBasedTranslator 只覆盖高频命令（ACL/VLAN/静态路由），NAT/AAA/QoS 等复杂特性完全依赖 LLM。

**2. SemanticMemory 使用朴素词法匹配**
`knowledge_data/` 按特征精准注入，不依赖 embedding。retrieve 逻辑为 TF-IDF hash 向量占位（待接真实 Embedding API）。

### 已缓解

**fw-nat-001 NAT 非确定性**：`validator` 在 LLM 输出 MANUAL_REVIEW 标记时正确阻断 deployability。无 false deployable 观察记录。

**HTTP 500 / gunicorn timeout**：GUNICORN_TIMEOUT=240（> LLM_TIMEOUT=180），LLM 请求在 gunicorn worker 超时前有充足缓冲。

---

## 下一步改进方向

1. **fw-nat-001 prompt/knowledge 优化** — 减少 NAT 场景 LLM 非确定性
2. **Async LLM workers** — gunicorn worker 池效率长期改进
3. **LLM semantic comparison** — 替换关键词匹配 SemanticComparator 为 IR 对比

---

## 依赖

```
hello-agents>=0.2.7
flask>=2.3.0
requests>=2.28.0
pytest>=7.0.0  # 测试
```

## 许可证

MIT
