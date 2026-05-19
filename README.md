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
BaseAgent.think()
    ↓
① Plan-and-Solve: LLM 生成翻译计划（Plan）
    ↓
② ReAct 循环: 按计划执行工具，观察结果
    ↓
③ Reflection: 翻译后质量检查
    ↓
GSSC Context: Working + Episodic + Semantic Memory 注入
    ↓
动态 System Prompt → LLM → 翻译结果
```

### 文件结构

```
network-translator/
├── core/
│   ├── __init__.py       # BaseAgent (v2) + LLM + Message + Plan + Reflection
│   └── context.py        # GSSC 流水线: Gather → Select → Structure → Compress
├── agents/
│   └── __init__.py      # NetworkTranslatorAgent（继承 BaseAgent）
├── tools/
│   └── __init__.py      # ConfigParser / ConfigDiffer / ConfigValidator / KnowledgeRetriever
├── memory/
│   └── __init__.py      # WorkingMemory / EpisodicMemory / SemanticMemory
├── knowledge_data/      # 当前生产知识库（Markdown）
├── tests/
│   └── test_all.py      # 当前回归/能力测试（pytest）
├── bench/
│   └── harness.py       # 5 套 Harness（质量测试）
│   └── results.json     # 性能基准数据
│   └── baseline.json    # 回归测试历史
├── memory_data/         # 翻译历史（自动创建）
├── run.py               # CLI 入口
└── web_app.py           # Web 界面
```

---

## 设计说明

### 1. BaseAgent v2 — 三大范式

**Plan-and-Solve**
```python
plan = agent.plan(user_query)
# LLM 分析请求 → 生成 JSON Plan（步骤列表）
# 例如: [{step: parse_config}, {step: get_knowledge}, {step: translate_with_llm}]
for step in plan.steps:
    execute_tool(step.action, step.args)
```
先规划再执行，避免盲目工具调用。

**ReAct（工具执行）**
```python
response = llm.chat(messages + tool_results)
for tool_call in response.tool_calls:
    result = execute_tool(tool_call.name, tool_call.args)
    messages.append(tool_call)
    messages.append(tool_result)  # 注入结果供下一步推理
```
边推理边执行，观察工具输出后决定下一步。

**Reflection（自我检查）**
```python
quality, issues = agent.reflect(query, answer)
# LLM 评估答案质量（0-1）、识别问题
# 质量 < 0.5 时自动尝试改进答案
```
翻译完成后检查语义等价性，识别遗漏和错误。

### 2. GSSC Context 流水线

笔记中的 GSSC 四步流水线实现于 `core/context.py`：

| 步骤 | 实现 |
|------|------|
| **Gather** | 从 WorkingMemory / EpisodicMemory / SemanticMemory / ToolResults 多源汇集 |
| **Select** | `ContextItem.relevance_score()` 基于关键词命中 × 新近性评分，取 Top-K |
| **Structure** | 按 source 分区组织（session / history / knowledge / tool） |
| **Compress** | 超过 `max_context_tokens` 时截断，保留头部最重要内容 |

注入位置：`Agent.build_system_prompt()` → 动态拼入 System Prompt

### 3. 三层记忆系统

| 记忆类型 | 说明 | TTL |
|----------|------|-----|
| **WorkingMemory** | TTL LRU Cache，存储当前翻译会话上下文 | 2h，可配置 |
| **EpisodicMemory** | 翻译历史事件，持久化到 JSONL，支持检索 | 永久 |
| **SemanticMemory** | 知识库向量检索（TF-IDF hash 向量占位，待接 Embedding API） | — |

### 4. 工具系统（LLM Function Calling）

Agent 注册的工具通过 `tools_schema` 传给 LLM，由 LLM 决定何时调用：

| 工具 | 作用 |
|------|------|
| `parse_config` | 结构化解析配置（接口/VLAN/路由协议/ACL） |
| `get_knowledge` | 读取 knowledge/ 目录的映射参考 |
| `translate_with_llm` | 调用 LLM 执行语义级翻译（核心工具） |
| `diff_config` | 对比原文/译文差异 |
| `validate_config` | 语法校验 + 最佳实践建议 |
| `get_history` | 查询翻译历史（EpisodicMemory） |

### 5. 动态 System Prompt

```python
def build_system_prompt(self, query, session_meta):
    parts = [BASE_SYSTEM_PROMPT]
    ctx = self.build_context(query, session_meta)  # GSSC
    if ctx:
        parts.append(f"\n\n【会话上下文】\n{ctx}")
    # session_meta 注入翻译方向、配置片段等
    return "\n\n".join(parts)
```

不再是一成不变的静态字符串，而是根据当前会话动态生成。

---

## 性能基准

```
ConfigParser.parse (200行)              0.5ms
ConfigValidator.validate                 0.1ms
WorkingMemory.set / get                0.001ms
EpisodicMemory.record                   0.06ms
EpisodicMemory.search_query (20条)      1.8ms
SemanticMemory.retrieve                20ms  ← 瓶颈（hash 向量未接 Embedding API）
Agent._tool_parse_config               0.5ms
Agent._tool_get_knowledge              22ms  ← SemanticMemory 拖累
Agent.think (fake LLM, 1轮 ReAct)       0.03ms
```

纯计算层快（µs 级），瓶颈在 SemanticMemory 向量检索。

---

## 运行方式

### CLI

```bash
cd network-translator
source venv/bin/activate
export LLM_API_KEY=your_key
export LLM_MODEL=MiniMax-M2.2-full
python3 run.py
```

### Web

```bash
python3 web_app.py
# 访问 http://localhost:5000
```

### 测试

```bash
# 单元测试（37个）
python3 -m pytest -q

# 性能基准 + Harness
python3 bench/harness.py

# 单独跑某项
python3 -c "
from bench.harness import TranslationQualityScore
from agents import NetworkTranslatorAgent
r = TranslationQualityScore(NetworkTranslatorAgent()).run()
print(f\"平均质量分: {r['avg_score']}\")
"
```

---

## 已实现 vs 笔记要求

| 笔记要求 | 状态 | 说明 |
|----------|------|------|
| ReAct | ✅ | BaseAgent `_react_loop()` |
| Plan-and-Solve | ✅ | BaseAgent `plan()` + `_execute_plan()` |
| Reflection | ✅ | BaseAgent `reflect()` |
| WorkingMemory | ✅ | TTL LRU Cache |
| EpisodicMemory | ✅ | JSONL 持久化 |
| SemanticMemory | ✅ | TF-IDF hash 向量（占位） |
| GSSC Context | ✅ | `core/context.py` GSSCPipeline |
| 动态 System Prompt | ✅ | `build_system_prompt()` |
| TranslationQualityScore Harness | ✅ | 5 维度综合评分 |
| MultiTurnReActTest Harness | ✅ | 4 轮对话模拟 |
| ErrorRecoveryTest Harness | ✅ | 工具失败恢复 |
| ContextBudgetTest Harness | ✅ | 超长配置压缩 |
| RegressionTest Harness | ✅ | baseline 历史 |

---

## 已知缺陷

> 坦诚列出，不回避。

### 🔴 高优先级

**1. SemanticMemory 向量检索是占位实现**
```python
def embed(self, texts):
    # 简单 hash 向量，实际应接 Embedding API（如 MiniMax Embedding）
    for text in texts:
        words = text.lower().split()
        vec = [hashlib.md5(w.encode()).digest()[0] for w in words[:256]]
```
cosine similarity 的精度完全不可信，`retrieve()` 结果仅供参考。

**2. LLM 语义翻译依赖 API，不走本地规则**
如果 LLM API 不可用或 key 失效，整个翻译流程完全失败。没有本地 fallback（正则规则已全部删除）。

**3. translate_with_llm 工具是硬编码 LLM 调用**
```python
result = self.llm.chat(messages=[], system=translate_system, ...)
# translate_system 是写死的 prompt 模板，不能动态注入 context
```
工具内部没有使用 Agent 的 GSSC context，工具和 Agent 的上下文是割裂的。

### 🟡 中优先级

**4. ErrorRecoveryTest 中错误处理质量低**
Harness 显示错误恢复率 100%（不崩溃），但 `has_error_handling` 标记为 ❌。说明 Agent 返回了错误结果，但错误信息不够友好（需要反射/改善错误提示质量）。

**5. 没有 multi-turn 记忆跨轮次传递**
每轮 `think()` 会清空 WorkingMemory（部分），EpisodicMemory 虽持久化但 ReAct 循环中没有自动注入历史作为 context。`MultiTurnReActTest` 是模拟的，不是真实多轮对话测试。

**6. Plan 生成质量不稳定**
`plan()` 调用的 LLM 如果返回的 JSON 格式错误，会 fallback 到空 plan 走纯 ReAct。缺少 JSON 解析重试逻辑。

**7. 没有实现 Thinking 模型**
笔记中提到 thinking/budget_tokens 支持（`LLM.thinking_budget` 参数已加），但实际没有在 `think()` 中启用。配置了 thinking 的模型（如 MiniMax-M2.1-mini）不会启用思考过程。

### 🟢 低优先级（可后续迭代）

**8. ConfigParser 对某些 Cisco 语法解析不完整**
- `router ospf 1` 下的 `network` 行没有正确关联到 ospf 进程
- `ip route` 和 ACL 的解析比较粗

**9. knowledge/ 目录的映射文件加载逻辑脆弱**
`_load_mappings()` 遍历 JSON 文件后塞入 `self.mappings`，但 `get_interface_mapping()` 和 `get_command_mapping()` 的数据来源混乱，部分数据直接从 JSON 读取，部分硬编码。

**10. 批量翻译（`batch_tools.py`）未移植到 v2**
旧版的 `BatchTranslator` 类（正则驱动）已删除，v2 暂无批量翻译功能。

**11. 没有 CI/CD 自动化**
Harness 没有接入 Git hooks 或 CI，RegressionTest 的 baseline 需要手动积累数据。

---

## 下一步改进方向

1. **接 Embedding API** — 替换 SemanticMemory 的 hash 向量为真实向量，修复检索质量
2. **添加工具内 GSSC** — `translate_with_llm` 等工具内部也要能访问 Agent context
3. **启用 Thinking 模型** — 在 Plan 和 Reflection 阶段启用 thinking budget
4. **恢复批量翻译** — 用 ReAct 循环驱动批量任务
5. **真实 MultiTurn 测试** — 接入 WebSocket 或真实 API 测试跨轮次上下文

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
