# AGENTS.md — Network Translator (Production)

## 项目概述

Graph-driven 网络配置翻译智能体，支持 Cisco/华为/华三/锐捷 配置语义等价互译。

## 入口

| 入口 | 命令 | 端口 |
|------|------|------|
| CLI | `PYTHONPATH=. python3 run.py` | - |
| Web | `PYTHONPATH=. python3 web_app.py` | 5000 (env `PORT`) |

## 环境变量

```bash
LLM_API_KEY=sk-xxx        # 必须: LLM API key
LLM_MODEL=MiniMax-M2.7    # 可选
LLM_BASE_URL=https://...  # 可选
LLM_TIMEOUT=45            # 可选
API_SECRET=xxx            # 可选: 设置后所有 API 需 X-API-Secret header
FLASK_DEBUG=1             # 可选: 开启 debug 模式
PORT=5000                 # 可选
```

## 运行测试

```bash
cd /root/network-translator
PYTHONPATH=. ./venv/bin/pytest tests/ -v
```

## 架构

```
web_app.py ──→ project_store.run_translation()
                    └── GraphAgent.run()
                         └── execute_translation_flow(graph)
                              ├── ParseNode          → parse config, detect vendor
                              ├── KnowledgeNode      → retrieve from knowledge_data/
                              ├── TranslateNode      → LLM IR translate (parse_to_ir + translate_ir)
                              ├── SemanticValidatorNode → rule-based IR comparison
                              ├── RouteNode          → success → validate / failure → fallback
                              ├── ValidateNode       → rule-based syntax validation
                              ├── DiffNode           → diff original vs translated
                              ├── FallbackNode       → RuleBasedTranslator (no-LLM fallback)
                              └── MemoryNode         → persist to events.jsonl
```

### 关键模块

- `core/__init__.py` — LLM 类 (Anthropic + OpenAI 兼容), 全局 singleton
- `core/graph/` — Node/Edge/State 图执行引擎
- `core/graph/nodes.py` — 9 个工作流节点
- `core/graph/translation_graph.py` — 翻译工作流图定义
- `core/ir.py` — Intermediate Representation (配置→语义块, LLM-driven)
- `core/semantic_compare.py` — IR 语义等价校验 (rule-based, no LLM)
- `core/rule_translator.py` — 规则引擎 fallback (无 LLM)
- `core/context.py` — GSSC 上下文流水线
- `tools/__init__.py` — ConfigParser, ConfigDiffer, ConfigValidator, KnowledgeRetriever
- `tools/knowledge_manager.py` — IR-driven 知识检索 (file-based cache, per-IR-type)
- `knowledge_data/{cisco,huawei,h3c}/` — 22 个 .md 文件/厂商

## 关键约定

- **knowledge_data/ 是知识库根目录** — 按 `{vendor}/{feature}.md` 组织
- **API key 从环境变量 `LLM_API_KEY` 读取** — `llmsetting.json` 存非敏感配置
- **数据目录**: `projects/`, `memory_data/`
- **测试必须 `PYTHONPATH=.` 运行** — 项目不安装为包
- **LLM 是 Agent 内部懒加载单例** — `get_llm()` 受 threading.Lock 保护
- **无 LLM 时 fallback 到 RuleBasedTranslator**
- **TranslateNode 先检索知识(IO,<1ms)再翻译(LLM,1次)，不再做双次翻译**

## 服务管理

```bash
./scripts/start.sh          # 启动 (优先 gunicorn, fallback flask)
./scripts/stop.sh           # 停止
./scripts/service.sh status # 状态
./scripts/service.sh logs   # 日志
```

## 已知限制

- Rule fallback 不完全覆盖 NAT/AAA/QoS 高级特性
- SemanticMemory 使用朴素词法匹配而非 embedding
- Web 使用 Flask dev server — 生产应用 gunicorn (scripts/service.sh 自动检测)
- ProjectStore 使用文件锁而非数据库 — 高并发场景考虑 SQLite WAL
- 知识库按 IR 类型精准注入，只覆盖有对应 .md 文件的特性