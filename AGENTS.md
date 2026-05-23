# AGENTS.md — Network Translator (Production)

## 项目概述

多设备域、多厂商平台的网络配置迁移与审计系统。
支持 SWITCH / ROUTER / FIREWALL 三种设备域，覆盖 Cisco/Huawei/H3C/Ruijie/Hillstone/Topsec/DPtech 平台。

核心承诺：结构化解析 → 语义迁移 → 覆盖率校验 → 残留检测 → 风险/人工复核报告。

## 当前状态 (2026-05-23)

项目已完成 Phase 6 (语义+覆盖率 baseline 集成)、Phase 7 (OSPF 深度校验/能力映射矩阵/7层集成)、Phase 8A (20任务性能基线)、Phase 8B (CI 质量门禁)、Phase 8C+8D (审计归档/运行手册/发布清单)、Beta 优化轮次 (配置收敛/安全脱敏/可靠性/审计闭环)。

**Beta 阶段就绪**: `BETA_READY = YES (conditional)` — 见 `docs/BETA_READINESS_REPORT.md`

Beta 冻结状态：不得新增 parser/renderer/graph pipeline 或大功能。
允许：GitHub Actions 实测、历史债务 reconciliation、文档修正、bugfix。

### 现网 (旧架构，兼容运行)
- LLM-driven 单次翻译管线 (ParseNode → TranslateNode → ValidateNode)
- 支持 Cisco/Huawei/H3C LLM 翻译，H3C→Cisco 有规则 fallback
- knowledge_data/{vendor}/ 知识库

### 新架构 (建设中，逐步上线)
- Domain-first: SWITCH / ROUTER / FIREWALL
- Parser → 强类型 IR → Renderer 确定性翻译路径
- 8 个 VendorPlatformProfile (cisco_ios_xe/h3c_comware/huawei_vrp/huawei_usg/ruijie_rgos/hillstone_stoneos/topsec_tos/dptech_fw)
- CompositeValidator (残留/覆盖/转换/语法/能力差距/语义)
- ConversionPolicy 注册表 + Fallback 注册表

### 目录结构

```
core/
├── domain/              # NEW (建设中): DeviceDomain, DomainProfile, DomainDetector
│   ├── __init__.py
│   ├── base.py
│   └── detector.py
├── domain_legacy.py     # OLD (兼容): 旧 core/domain.py 重命名
├── vendor/              # NEW (建设中): VendorPlatformProfile 注册表
├── ir_models/           # NEW (建设中): 强类型 IR 数据模型
├── parser/              # NEW (建设中): BaseParser 体系
├── renderer/            # NEW (建设中): BaseRenderer 体系
├── validator/           # NEW (建设中): CompositeValidator 体系
├── fallback/            # NEW (建设中): 注册表式 fallback
├── policy/              # NEW (建设中): ConversionPolicy 注册表
├── ir.py                # DEPRECATED (兼容保留)
├── h3c_to_cisco.py      # RETAINED (包装为 fallback)
├── rule_translator.py   # RETAINED (包装为 fallback)
├── cisco_output_validator.py  # DEPRECATED (迁移后删除)
└── ...旧模块
```

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
cd /Users/zhangh01/Desktop/codex_net_trans/network-translator
PYTHONPATH=. venv/bin/python3 -m pytest tests/ -v
```

## 架构 (旧管道——兼容运行中)

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

## 关键模块 (旧)

- `core/__init__.py` — LLM 类 (Anthropic + OpenAI 兼容), 全局 singleton
- `core/graph/` — Node/Edge/State 图执行引擎
- `core/graph/nodes.py` — 14 个工作流节点
- `core/graph/translation_graph.py` — 翻译工作流图定义
- `core/ir.py` — Intermediate Representation (配置→语义块, LLM-driven) [DEPRECATED]
- `core/semantic_compare.py` — IR 语义等价校验 (rule-based, no LLM)
- `core/rule_translator.py` — 规则引擎 fallback [RETAINED: fallback wrapper]
- `core/h3c_to_cisco.py` — H3C→Cisco 规则翻译 [RETAINED: fallback wrapper]
- `core/context.py` — GSSC 上下文流水线
- `tools/__init__.py` — ConfigParser, ConfigDiffer, ConfigValidator, KnowledgeRetriever
- `tools/knowledge_manager.py` — IR-driven 知识检索 (file-based cache, per-IR-type)
- `knowledge_data/{cisco,huawei,h3c}/` — 22 个 .md 文件/厂商 (兼容保留)

## 关键约定

- **knowledge_data/ 是知识库根目录** — 旧 vendor-first 结构兼容保留，新 domain-first 结构可选新增
- **API key 从环境变量 `LLM_API_KEY` 读取** — `llmsetting.json` 存非敏感配置
- **数据目录**: `projects/`, `memory_data/` (不纳入架构改造)
- **测试必须 `PYTHONPATH=.` 运行** — 项目不安装为包
- **LLM 是 Agent 内部懒加载单例** — `get_llm()` 受 threading.Lock 保护
- **新旧路径并存期**：新路径上线后旧路径继续作为 fallback 保留
- **旧文件不随意删除**：参见 docs/superpowers/specs/ 附录 A 迁移策略

## 旧文件迁移策略

旧文件归类（详见设计文档附录 A）：
- **兼容保留**: `ir.py`, `graph/nodes.py` 旧节点
- **包装为 fallback**: `h3c_to_cisco.py` → H3CToCiscoFallback, `rule_translator.py` → RuleBasedFallback
- **逐步迁移后删除**: `cisco_output_validator.py`, 旧 vendor 硬编码校验

删除条件：
1. 无 import 引用
2. 新模块完全覆盖功能
3. 新旧结果对比测试通过
4. 全量测试通过
5. test_config.txt 样例链路通过
6. 回归风险可控

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
- 新架构核心模块（parser/renderer/validator）尚在建设中