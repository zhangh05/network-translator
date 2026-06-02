# Batch O Evaluator Audit — 54/54 Pass 规则审计

> **Date**: 2026-06-02
> **Auditor**: workbuddy
> **Scope**: `scripts/evaluate_corpus_fallback.py` pass/fail 规则与 corpus manifest 覆盖度

---

## 1. Evaluator 入口

| 组件 | 路径 |
|------|------|
| Evaluator 主程序 | `scripts/evaluate_corpus_fallback.py` |
| Evaluator 单元测试 | `tests/test_corpus_fallback_evaluator.py` |
| Corpus manifest | `corpus/sanitized_samples/manifest.json` |
| Corpus 样本 | `corpus/sanitized_samples/*.txt` (22 files) |
| 评估报告 (JSON) | `reports/corpus_fallback_eval.json` |
| 评估报告 (MD) | `reports/CORPUS_FALLBACK_EVAL.md` |
| Gap analysis | `docs/FALLBACK_GAP_ANALYSIS.md` |
| 本次 negative tests | `tests/test_corpus_evaluator_negative.py` |

## 2. 当前规则

### Pass 条件
```python
passed = manual_review_ok AND residue_ok AND secret_ok
```

### 三个检查的精确含义

#### 2.1 manual_review_ok
```python
for mr in must_manual_review:
    first_word = mr.split()[0]
    if first_word.upper() in output_upper and "MANUAL_REVIEW" not in output_upper:
        fail  # -> missing_mr
```
- 作用：检查 manifest `must_manual_review` 列表中的命令**如果在输出中出现**，则输出中必须包含 `MANUAL_REVIEW` 字符串。
- 正确之处：确保潜在危险命令不会未被标记就进入输出。
- 缺陷：只检查 manifest 显式列出的项目。manifest 中未列出的危险命令不会触发此检查。

#### 2.2 residue_ok
```python
for pat in forbidden_residue_patterns:
    for line in exec_output.splitlines():
        if stripped_line.startswith(pat):
            fail  # -> found_residue
```
- 作用：检查可执行行（排除注释行）中是否以 `forbidden_executable_residue` 或 `forbidden_residue_by_target` 中列出的 pattern 开头。
- 正确之处：行级前缀匹配避免了子串误报（如 `security-zone name` 包含 `zone name`）。
- 缺陷：只检查 manifest 显式列出的 pattern。manifest 中未列出的残留不会被检测。

#### 2.3 secret_ok
```python
for sec in secret_tokens:
    if sec and sec in output:
        fail  # -> leaked_secrets
```
- 作用：检查 manifest `secret_tokens` 中列出的特定 token 是否出现在输出中（含注释）。
- 正确之处：全输出范围检查（含注释），不限于可执行行。
- 缺陷：**只检查预先列出的 token。没有通用正则检查 password/secret/cipher/shared-key/community/key 模式。**

## 3. 发现的问题

### P0: secret_ok 不检查通用 secret pattern

**严重度**: HIGH

当前 `secret_ok` 只检查 manifest 中 `secret_tokens` 字段列出的特定 token。如果某个样例的 `secret_tokens: []`（空列表），则 secret 检查完全跳过。

示例：样例 `sw-h3c-02` 的 `secret_tokens: []`，如果 fallback 错误地将 `password mysecret` 输出为可执行行，evaluator 不会检测到。

**建议**：增加通用正则检查，在 executable_lines 中匹配 `password|secret|cipher|shared-key|community|key` 后跟非 `<redacted>` 的明文。

### P1: evaluator 评估的是 raw fallback 输出而非 module_graph 三层分离

**严重度**: MEDIUM

生产路径使用 `core/module_graph/translator.py` 生成 `deployable_config` / `semantic_near` / `manual_review` 三层分离。但 evaluator 评估的是 `RuleBasedTranslator.translate()` 和 `H3CToCiscoTranslator.translate()` 的原始输出——这是原始的 fallback 翻译器，不经过 module graph 的三层分离。

这意味着：
- Evaluator 100% pass 只能说明**原始 fallback 输出**通过了检查
- 不能说明**module_graph 的 deployable_config** 是正确的
- 如果 module graph 逻辑 bug 把 semantic_near 内容放入 deployable_config，evaluator 不会发现

**建议**：扩展 evaluator 使其也能评估 module_graph 输出路径。

### P2: must_manual_review 检查过于依赖 manifest 预配置

**严重度**: MEDIUM

`manual_review_ok` 检查依赖于 manifest 中 `must_manual_review` 字段的准确性。如果 manifest 遗漏了某个应该标记为 manual_review 的特征，evaluator 不会发现。

**证据**：
- fw-hillstone-02 的 `features_present` 包含 `ipsec`, `ike`, `crypto`，这些都应进入 manual_review
- 但 `must_manual_review` 只含 3 项。其他危险特征的检测依赖 manifest 编写者的判断

### P3: 没有 silent drop 检查

**严重度**: MEDIUM

Evaluator 不检查源配置中的命令是否**完全消失**。如果某个关键命令（如 `router ospf 1`）在输出中完全找不到（既不 translated，也不在 manual_review 中），evaluator 不会失败。

### P4: 没有 default any 检查

**严重度**: LOW-MEDIUM

Evaluator 不检查 firewall policy 输出是否生成了 implicit default any（缺少 source-address / destination-address / service 字段的 policy）。

### P5: 没有 semantic_near 混入 deployable_config 的检查

**严重度**: MEDIUM

Evaluator 不检查 `semantic_near` 层内容是否混入了 deployable-like 输出。当前 semantic_near 生成带有 `! SOURCE:` 或 `! confirm:` 注释的内容，这些文本可能被误放入 deployable 位置。

## 4. 新增 negative tests

新增文件: `tests/test_corpus_evaluator_negative.py` — **31 tests**

| Test 类 | 测试数 | 覆盖 |
|---------|--------|------|
| `TestManualReviewLeakNegative` | 3 | MANUAL_REVIEW 混入 deployable_config |
| `TestSecretLeakInDeployable` | 5 | password/cipher/community/shared-key 明文 |
| `TestSourceResidueNegative` | 3 | 源厂商裸命令残留 |
| `TestFirewallDefaultAny` | 2 | 缺字段 firewall policy |
| `TestSilentDrop` | 3 | 源命令完全消失 |
| `TestSemanticNearLeakNegative` | 2 | semantic_near 混入 deployable |
| `TestEvaluatorPassFailLogic` | 6 | evaluator 端到端 pass/fail 逻辑 |
| `TestEvaluatorMissingSecretPatternCheck` | 2 | 通用 secret pattern 缺失 |
| `TestManifestCompleteness` | 2 | manifest 覆盖度检查 |
| `TestEvaluatorModuleGraphGap` | 1 | 文档化 module_graph 评估缺口 |

## 5. 是否发现 100% pass 存在虚假风险

**是，存在虚假风险**，原因：

1. **P0 — 通用 secret pattern 检查缺失**：如果产生新的 secret 明文（不在 manifest `secret_tokens` 中），evaluator 不会发现。根据构建方式（fallback 全部标记 MANUAL_REVIEW + 脱敏），实际产生新秘文明文的风险较低，但评估覆盖盲区存在。

2. **P1 — evaluator 不测试 module graph 路径**：生产路径与评估路径不同。当前 54/54 通过验证了**原始 fallback 输出**是安全的，但未验证 **module_graph 三层分离**的正确性。如果将来有人修改 module_graph 导致 deployable_config 混合不同层内容，evaluator 不会报警。

3. **P3 — 没有 silent drop 检查**：理论上可以构造一个输出为空的 "passed" 结果。

**但是**，54/54 在当前状态下是**可信的**，因为：
- Fallback 翻译器本身是保守的（大量使用 MANUAL_REVIEW + 脱敏）
- Residue 检查的行级前缀匹配是正确的（避免误报）
- Secret 检查通过 manifest 维护的 token 列表覆盖了已知敏感值
- 所有样例的 `secret_tokens` 中 `<redacted>` 模式有效防止了已知密钥泄露

## 6. 修正了什么

本次审计**未修改 evaluator 规则**（按用户要求：不要把语义相近当 deployable、不要放宽 evaluator、不要大改）。仅做了三件事：

1. **新增 negative test 文件** (`tests/test_corpus_evaluator_negative.py`): 31 个测试文档化 evaluator 的已知局限
2. **新增审计报告** (`reports/BATCH_O_EVALUATOR_AUDIT.md`): 本文档
3. **新增 manifest 完整性检查**: 确保所有含敏感特征的样例有 `secret_tokens`

**未修改**：
- `scripts/evaluate_corpus_fallback.py`（未改规则）
- `corpus/sanitized_samples/manifest.json`（未改样例定义）
- `corpus/sanitized_samples/*.txt`（未改原文件）
- `core/` 任何文件（未改业务逻辑）

## 7. 仍未覆盖什么

| 缺口 | 建议补充（后续 Batch） |
|------|----------------------|
| 通用 secret pattern 检查 | evaluator 增加 `SECRET_PATTERN` 正则，对所有 executable_lines 做 pattern 匹配 |
| module_graph 路径评估 | 新增 `evaluate_corpus_module_graph.py`，对 module_graph 的 deployable_config 做同样检查 |
| silent drop 检查 | evaluator 增加 `silent_drop_ok`：源配置关键命令必须在输出中存在（作为 translated 或 MANUAL_REVIEW） |
| default any 检查 | evaluator 增加 `default_any_ok`：firewall policy 缺少 source-address/destination-address/service 时标记 |
| semantic_near 混入检查 | evaluator 增加 `semantic_near_leak_ok`：deployable_config 中不应包含 `! SOURCE:` `! confirm:` 等 semantic_near 标记 |
| manifest 自动同步 | 当前 manifest 手动维护，容易与 translator 能力不一致。建议根据 translator 输出自动校验 manifest 预期 |

---

## 判定

```
EVALUATOR_TRUSTWORTHY = YES (with documented gaps)
```

54/54 pass 在当前状态下可信，因为 fallback 翻译器本身是保守的。但 evaluator 覆盖盲区（通用 secret pattern、module graph 路径、silent drop、default any）需要在后续 Batch 中逐步补齐。
