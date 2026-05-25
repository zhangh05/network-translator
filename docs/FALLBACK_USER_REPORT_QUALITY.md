# Fallback 用户报告质量规范

> Beta 冻结期文档 — Batch I-G 产出

## 1. 三类输出字段边界

### deployable_config

| 属性 | 说明 |
|------|------|
| 面向 | 用户复制上线 |
| 内容 | 目标厂商可执行配置 + 必要 `# MANUAL_REVIEW` 注释 |
| 不包含 | 人工复核摘要、feature_summary、block_count、fallback_reason、详细复核块、内部错误原文 |
| 风险提示 | 不保证完全可直接上线，MANUAL_REVIEW 行仍需人工处理 |

### translated_config / report

| 属性 | 说明 |
|------|------|
| 面向 | 用户阅读和复核 |
| 内容 | 人工复核摘要（6 中文分类 + 风险 + 原因 + ≤3 示例）|
| 可包含 | deterministic fallback 配置块 |
| 禁止出现 | 内部错误原文（见下）|

**禁止出现的内部错误原文：**
- `第 0 项不是对象`
- `analyzer missing`
- `LLM 输出校验失败`
- `invalid JSON`
- `traceback`
- `validation failed`
- `output_analyzer`

### metadata / state

| 属性 | 说明 |
|------|------|
| 面向 | 审计和开发排查 |
| 可包含 | source_vendor、target_vendor、block_count、feature_summary、fallback_reason |
| 原始 error | 仅放 `_raw_fallback_error` 或 metadata，不直接展示给普通用户 |
| 禁止 | 直接展示给普通用户 |

---

## 2. 人工复核中文分类

### 6 类分类

| 分类 | 说明 |
|------|------|
| 管理面 | AAA、system、SNMP、NTP、logging、line-vty 等控制面配置 |
| 接口与 VLAN | interface、vlan、svi、lag、stp 等接口和二层配置 |
| ACL 与安全策略 | acl、qos、traffic-policy、service-policy、firewall-policy 等访问和安全配置 |
| 路由协议 | ospf、bgp、static-route、route-policy、route-map、vrf、nat 等路由相关配置 |
| 防火墙对象 | zone、address-set、service-set、address-object、service-object 等对象配置 |
| 未支持能力 | unknown、unsupported、raw_unknown、others 等无法归类的配置块 |

### 归并映射表

```
aaa / local-user / snmp-agent / ntp / info-center / rmon
  → 管理面

interface / vlan / port-isolate / stp / rstp / mstp / lacp / Ethernet
  → 接口与 VLAN

acl / qos / traffic-classifier / traffic-behavior / traffic-policy
  service-policy / firewall-policy / packet-filter
  → ACL 与安全策略

ospf / bgp / rip / static-route / route-policy / route-map
  vrf / ip vpn-instance / nat / dhcp relay
  → 路由协议

zone / address-set / service-set / address-object
  service-object / user / user-group / url-category
  → 防火墙对象

其他所有无法归并的特征
  → 未支持能力
```

---

## 3. 风险等级口径

**只允许使用以下三个中文等级：高 / 中 / 低**

| 等级 | 触发条件（命中任一关键词）|
|------|--------------------------|
| 高风险 | secret、cipher、password、shared-key、pre-shared-key、community、radius、tacacs、BGP neighbor password、ipsec、vpn、aaa（认证）、nat（双向）|
| 中风险 | route-policy、qos、acl、firewall-policy、ospf、bgp、vrf、pbr、traffic-policy、service-policy |
| 低风险 | vlan、interface、ntp、logging、system、stp、lacp、port-isolate |
| 默认 | 无法归类时默认 **中** |

---

## 4. 脱敏策略

### 必须脱敏的关键词（全文，包括注释、摘要、示例、metadata）

| 原始内容 | 脱敏结果 |
|----------|----------|
| `password <value>` | `password <redacted>` |
| `secret <value>` | `secret <redacted>` |
| `cipher <value>` | `cipher <redacted>` |
| `shared-key <value>` | `shared-key <redacted>` |
| `pre-shared-key <value>` | `pre-shared-key <redacted>` |
| `community <value>` | `community <redacted>` |
| `radius-server .* key` | `radius-server <redacted> key <redacted>` |
| `tacacs-server .* key` | `tacacs-server <redacted> key <redacted>` |
| `neighbor .* password` | `neighbor <addr> password <redacted>` |
| `snmp-server community <value>` | `snmp-server community <redacted>` |
| `irreversible-cipher <value>` | `irreversible-cipher <redacted>` |

### 脱敏示例

```cisco
! 原始
neighbor 10.1.1.1 password SUPER_SECRET_KEY

! 脱敏后（出现在 translated_config / report / deployable_config）
neighbor 10.1.1.1 password <redacted>
```

```cisco
! 原始
snmp-server community PUBLIC_COMM ro

! 脱敏后
snmp-server community <redacted> ro
```

---

## 5. 用户使用建议

### 复制上线优先使用 `deployable_config`

`deployable_config` 是确定性规则翻译的输出，经过脱敏处理，可以直接复制到目标设备。但必须逐行检查 `# MANUAL_REVIEW` 注释，这些行需要人工确认语义等价性。

### 看到 `MANUAL_REVIEW` 必须人工确认

任何出现在 `deployable_config` 中的 `# MANUAL_REVIEW` 行，以及 `translated_config` 中 `人工复核摘要` 章节，都要求人工复核。严禁将 `translated_config` 整段粘贴到设备。

### `translated_config` / `report` 用于理解风险

`translated_config` 是面向用户阅读的报告，包含风险分类、中文原因说明和示例行。应结合源配置理解迁移前后的语义差异，不应作为设备配置直接使用。

### Fallback 是安全兜底，不是主链路

```
主链路（正常）：Parser → IR → LLM Translate → Semantic Validate → Renderer → Validator
Fallback（兜底）：Parser → Rule-Based Translator → Safe Fallback（当 LLM 输出不可用时）
```

Fallback 在 LLM 输出无法通过校验时触发，是安全阻断机制，不等同于完整的 Parser→IR→Renderer→Validator 翻译链路。使用 Fallback 时，用户必须承担语义校验的人工责任。

---

## 6. 浏览器 UI 视角

### 翻译结果 tab 定位

**翻译结果 tab（translated）：** 始终显示 `deployable_config`，即可复制的目标厂商配置。不显示人工复核摘要、分类标签或内部 diagnostics。Fallback 时仍显示确定性规则翻译的 `deployable_config`。

**风险分析 tab（risk）：** 显示 fallback notice（当 `fallback_used=true`）和 6 中文分类风险分析（capability gaps、analyzer results、risk signals）。Fallback notice 引导用户查看人工复核摘要。

**校验结果 tab（validation）：** 显示部署状态（可部署/需人工复核/不建议上线）、错误数、警告数。

**差异对比 tab（diff）：** 显示源配置与目标配置的结构化 diff。

### deployable_config 的展示方式

`deployable_config` 在**翻译结果 tab** 直接展示（而非仅通过复制函数）：
- 翻译结果 tab 渲染 `stripFence(deployable_config || translated)`
- Fallback 时翻译结果 tab 显示确定性规则翻译的净配置

复制函数访问方式：
1. **复制全部配置**：复制 `deployable_config || translated`
2. **复制可部署配置**：复制 `deployable_config`，过滤 `# MANUAL_REVIEW` 行
3. **导出报告**：包含 `deployable_config`、`translated`、`validation`、`capability_gaps`、`analyzer_results` 等完整字段

### 刷新后结果保留机制

翻译成功后：
1. 前端调用 `GET /api/projects/<id>` 重新加载项目
2. `project.result` 包含完整的 `result_data`（含 `deployable_config`、`translated`、`validation` 等）
3. 前端 `R.result` 被刷新为 `sp.project.result`
4. 多浏览器/多窗口访问同一项目 ID 时，看到相同结果

清空结果（CL 按钮）时：
- `project.result` 被设为 `null`
- `project.request_id`、`project.version`、`project.model` 被清空
- `PROJS` 本地状态同步清空

---

## 7. 测试引用

| 测试文件 | 覆盖内容 |
|----------|----------|
| `tests/test_fallback_user_report_quality.py` | 5 厂商对 × 3 层输出分离、redaction、metadata 边界、中文分类 |
| `tests/test_realistic_fallback_report.py` | 8 个人工复核报告场景（A-H）、无内部 diagnostics 泄露 |
| `tests/test_safe_fallback_and_block_splitter.py` | block split、safe fallback deterministic、≥3 示例行、redaction |
| `tests/test_frontend_fallback_ux.py` | GraphAgent 集成、UX 端到端流程、user-facing 输出 |
| `tests/test_rule_translator_realistic_samples.py` | 规则翻译器真实样本覆盖 |
| `tests/test_rule_translator_realistic_batch_i_e.py` | Batch I-E 收敛回归 |
| `tests/test_output_redaction.py` | 统一输出脱敏（P0 修复）：16 种模式 + 递归结构 + 无假阳性 + 幂等性 + ProjectStore 集成 |

---

## 7.5. 统一输出脱敏覆盖

### 脱敏位置

脱敏在 `project_store.py` 中作为 API 层拦截器执行，位于 `translate_project()` 的三个输出路径：

| 路径 | 位置 | 说明 |
|------|------|------|
| 新翻译保存 | `translate_project()` 内 `run_translation()` 返回后 | 递归脱敏 result_data 再持久化 + 返回 |
| 复用缓存读取 | `translate_project()` 复用路径 | 从磁盘读取 project.result，脱敏后返回 |
| GET 项目 API | `get_project()` 路由 | 读取 to_full_dict() 后脱敏 result，兼容旧数据 |

### 脱敏模式（16 种）

| 模式 | 示例输入 | 脱敏后 |
|------|---------|--------|
| password | `password SECRET` | `password <redacted>` |
| secret | `secret 5 HASH` | `secret 5 <redacted>` |
| cipher | `cipher Hello@123` | `cipher <redacted>` |
| irreversible-cipher | `irreversible-cipher XyZ` | `irreversible-cipher <redacted>` |
| shared-key | `shared-key myKey` | `shared-key <redacted>` |
| pre-shared-key | `pre-shared-key secret` | `pre-shared-key <redacted>` |
| snmp-server community | `snmp-server community public` | `snmp-server community <redacted>` |
| snmp-agent community cipher | `snmp-agent community read cipher %%$abc` | `snmp-agent community read cipher <redacted>` |
| tacacs-server key | `tacacs-server key TacacsKey` | `tacacs-server key <redacted>` |
| radius-server key | `radius-server key RadiusKey` | `radius-server key <redacted>` |
| radius shared-key | `radius shared-key SharedKey` | `radius shared-key <redacted>` |
| neighbor password | `neighbor 10.0.0.1 password Pass` | `neighbor 10.0.0.1 password <redacted>` |
| set community | `set community 65000:1` | `set community <redacted>` |
| apply community | `apply community 65000:100` | `apply community <redacted>` |

### 关键设计约束

- **递归**: 自动脱敏 str/list/dict/nested 嵌套结构
- **无假阳性**: IP、ACL rule、VLAN ID、interface name、OSPF 等 6 类 safe lines 不受影响（30 条断言验证）
- **幂等性**: 对已脱敏文本再脱敏结果不变
- **无双重脱敏**: password 优先匹配，cipher/irreversible-cipher 后匹配（负向前瞻避免 password 吃掉 cipher）

### 覆盖字段

| 字段 | 类型 | 脱敏 |
|------|------|------|
| `result_data.translated` | str | ✅ |
| `result_data.deployable_config` | str | ✅ |
| `result_data.diff` | str | ✅ |
| `result_data.validation` | dict | ✅ |
| `result_data.risk_signals` | list[dict] | ✅ |
| `result_data.capability_gaps` | list[dict] | ✅ |
| `result_data.analyzer_results` | dict | ✅ |
| `result_data.node_results` | dict | ✅ |

---

## 8. Batch I-I 浏览器端到端验收结果

### LLM 配置

| 字段 | 值 |
|------|-----|
| model | Minimax M2.7 |
| base_url | https://api.minimaxi.com/anthropic |
| api_key | `***` (masked) |
| 读取状态 | 通过外部 `llm_settings.txt` 读取成功 |

### 4 样例验收汇总

| # | 样例 | 源→目标 | 翻译方式 | 状态 | 摘要 |
|---|------|---------|----------|------|------|
| 1 | Huawei VRP → Cisco | huawei→cisco | LLM | 可部署 | VLAN/ACL/OSPF/snmp/aaa 全部正确翻译 |
| 2 | Cisco → Huawei | cisco→huawei | LLM | 需人工复核 | BGP password/service-policy/aaa 需审核 |
| 3 | Topsec → Huawei USG | topsec→huawei_usg | LLM | 可部署 | Zone/address/service/policy 全翻译 |
| 4 | Hillstone → Topsec | hillstone→topsec | LLM | 需人工复核 | zone/object/service/policy 含 `// MANUAL_REVIEW` |

### 关键验收项

| 验收项 | 结果 |
|--------|------|
| 翻译结果 tab 始终优先 deployable_config | ✅ 正确 |
| 翻译结果 tab 不含人工复核摘要 | ✅ 正确 |
| 风险分析 tab 可读 (中文分类) | ✅ 正确 |
| 校验结果 tab 可读 | ✅ 正确 |
| 差异对比 tab 可读 | ✅ 正确 |
| 复制全部配置优先 deployable_config | ✅ 正确 |
| 复制可部署配置过滤 MANUAL_REVIEW | ✅ 正确 |
| 刷新后结果保留 | ✅ 正确 |
| 新窗口看到同一结果 | ✅ 正确 |
| 明文敏感值不在 fallback 输出出现 | ✅ fallback path 已脱敏 |
| 明文敏感值不在 LLM 输出出现 | ✅ 统一 `redact_sensitive_output()` 覆盖 LLM 和 fallback 所有输出路径，持久化前脱敏 |
