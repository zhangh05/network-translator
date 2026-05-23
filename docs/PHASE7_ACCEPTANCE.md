# Phase 7 验收记录

> 验收日期: 2026-05-23
> 验收范围: OSPF 深语义校验, 映射单一来源, Schema 契约化, 口径统一, 多域集成扩展, 验收冻结

---

## 1. 范围与目标

### 范围
- Phase 7A: OSPF 深语义校验 — _check_ospf 4 维度增强 (info sufficiency, network/area ref, area type conflict, conversion_status)
- Phase 7B: Coverage 映射单一来源 — _IR_FIELD_TO_FEATURE_KEY 集中化
- Phase 7C: Report Schema 契约化 — 21 个 schema contract test
- Phase 7D: Capability 口径统一 — 映射矩阵 + overall_verifiability_index
- Phase 7E: 多域集成扩展 — FIREWALL + ROUTER deep + ROUTER mismatch 3 条链路
- Phase 7F: 验收冻结

### 非目标
- 不涉及 parser/renderer/graph pipeline 改造
- 不删除旧兼容文件 (ir.py, cisco_output_validator.py, h3c_to_cisco.py, rule_translator.py)
- 不破坏 fallback/adapter/deprecated 策略
- OSPF 不回加 auto_verifiable registry (见 §7)
- 不做 FIREWALL 深层语义校验 (NAT 策略, zone 级行为)

---

## 2. 分阶段结果

### Phase 7A: OSPF 深语义校验 (a57f546)

**改动:**
- `core/validator/semantic_validator.py`: `_check_ospf` 新增 4 维检查 + `_make_issue` 参数扩展
- `tests/test_validator_semantic.py`: `TestSemanticValidatorOspf` (6 tests)

**检查维度:**
1. **Conversion status** (已有, 保留): non-EXACT → HIGH/rule_id=ospf:conversion_status
2. **Info sufficiency** (新增): 仅 process_id 无 networks/areas/passive → MANUAL_REVIEW MEDIUM
3. **Network area mismatch** (新增): network 引用了未定义的 area → HIGH
4. **Area type conflict** (新增): 同一 area_id 两种 type → MEDIUM

**证据字段:** rule_id + source_ref 附加到所有 OSPF issue

### Phase 7B: 映射单一来源 (a57f546)

**改动:**
- `core/validator/coverage_validator.py`: 新增 `_IR_FIELD_TO_FEATURE_KEY` + `get_feature_mapping()`
- `core/validator/__init__.py`: 引用 `coverage_validator.get_feature_mapping()` 替代私有 dict
- `tests/test_validator_coverage.py`: `TestCoverageMappingSingleSource` (3 tests)

**设计:** `_IR_FIELD_TO_FEATURE_KEY` 与 `_IR_TO_FEATURE` 同处 coverage_validator.py, 通过 `get_feature_mapping()` 暴露防御性副本。两种映射的双向漂移检测测试确保一致。

### Phase 7C: Schema 契约化 (a57f546)

**改动:**
- `tests/test_schema_contract.py`: 21 个契约测试 (新建)

**覆盖:**
- to_dict 结构稳定性 (schema_version, summary, deployable, manual_review_required, issues, metadata)
- Issue 序列化 (severity 小写, evidence 字段, 可选字段省略)
- 向后兼容模拟 (旧消费者字段存在性)
- Policy 合约 (blocking rules, severity 阈值)

### Phase 7D: 口径统一 + Bugfix (3a86872)

**改动:**
- `core/validator/capability_baseline.py`: `CLASSIFICATION_TO_ISSUE_PARAMS` 映射矩阵 + `get_classification_issue_params()`
- `core/validator/__init__.py`: `overall_verifiability_index` = coverage_rate × semantic_rate
- `core/validator/semantic_validator.py`: `_check_router` 新增 `_check_ospf` 调用 (ROUTER 域 OSPF 深校验)
- `tests/test_validator_capability_baseline.py`: 8 个新增测试

**Bugfix 说明:** _check_router 原未调用 _check_ospf (仅 _check_switch 有), 导致 ROUTER 域 OSPF 不校验。Phase 7E 测试发现并修复。

**口径矩阵:**
| 分类 | Category | Severity | 说明 |
|---|---|---|---|
| unknown_capability | MANUAL_REVIEW | HIGH | src/tgt UNKNOWN |
| unverifiable_checker_missing | MANUAL_REVIEW | MEDIUM | FULL/FULL, 无 deep checker |
| source_partial | MANUAL_REVIEW | MEDIUM | src PARTIAL |
| target_partial | MANUAL_REVIEW | MEDIUM | tgt PARTIAL |

### Phase 7E: 多域集成扩展 (3a86872 + 0b8f7b6)

**改动:**
- `tests/test_integration_phase7.py`: 21 个集成测试 + 机器可读断言表

**3 条新增链路:**
| 链路 | 源 | 目标 | 域 | 断言数 |
|------|------|------|------|--------|
| 4-FIREWALL | Huawei USG | Hillstone StoneOS | FIREWALL | 7 |
| 5-ROUTER deep OSPF | H3C Comware | Huawei VRP | ROUTER | 7 |
| 6-ROUTER OSPF mismatch | Cisco IOS-XE | H3C Comware | ROUTER | 7 |

---

## 3. 全部 commit hashes (时间顺序)

```
a57f546 Phase 7A+7B+7C: OSPF deep check + coverage single source + schema contract
37e3927 docs: audit patch for a57f546 — new/legacy code boundary
3a86872 Phase 7D+7E: Capability mapping matrix + multi-domain integration
0b8f7b6 fix: sync 7E assertion tables with actual test results
<PHASE_7F_COMMIT> Phase 7F: Acceptance package & freeze
```

---

## 4. 测试命令与结果

### 定向测试

```bash
# Phase 7A: OSPF semantic (6 tests)
PYTHONPATH=. venv/bin/python3 -m pytest tests/test_validator_semantic.py::TestSemanticValidatorOspf -v
→ 6 passed

# Phase 7B: Coverage mapping (3 tests)
PYTHONPATH=. venv/bin/python3 -m pytest tests/test_validator_coverage.py::TestCoverageMappingSingleSource -v
→ 3 passed

# Phase 7C: Schema contract (21 tests)
PYTHONPATH=. venv/bin/python3 -m pytest tests/test_schema_contract.py -v
→ 21 passed

# Phase 7D: Capability baseline (40 tests including 8 new)
PYTHONPATH=. venv/bin/python3 -m pytest tests/test_validator_capability_baseline.py -v
→ 40 passed

# Phase 7E: Integration (21 tests)
PYTHONPATH=. venv/bin/python3 -m pytest tests/test_integration_phase7.py -v
→ 21 passed

# All Phase 6+7 integration (39 tests)
PYTHONPATH=. venv/bin/python3 -m pytest tests/test_integration_phase6.py tests/test_integration_phase7.py -v
→ 39 passed

# All validator tests
PYTHONPATH=. venv/bin/python3 -m pytest tests/test_validator_*.py -v
→ 148 passed
```

### 全量回归

```bash
PYTHONPATH=. venv/bin/python3 -m pytest tests/ -v
→ 1069 passed / 13 pre-existing failures / 3 skipped
```

13 个预存失败均为外部依赖缺失 (flask/requests) 或旧 analyzer 测试, 与 Phase 7 无关。

---

## 5. 关键断言逐项列值

### 链路 1-3 (Phase 6D, 保持全通过)
参见 `docs/PHASE6_ACCEPTANCE.md` §5。18 项断言全部通过。

### 链路 4: FIREWALL Huawei USG → Hillstone StoneOS

| 断言 | 预期 | 实际 |
|------|------|------|
| residue_high_count | ≤1 | 0 |
| ir_feature_count | 4 | 4 |
| rendered_feature_count | 4 | 4 |
| coverage_verifiability_rate | 1.0 | 1.0 |
| firewall_semantic passed | 🟢 | ✅ |
| semantic_verifiability_rate ≥ 0 | ✅ | 0.25 |
| deployable | True | True |
| manual_review_required | False | False |
| schema_version | "1.0" | "1.0" |
| overall_verifiability_index | 0.0–1.0 | 0.25 |

### 链路 5: ROUTER deep OSPF H3C Comware → Huawei VRP

| 断言 | 预期 | 实际 |
|------|------|------|
| residue_hostname_detected | 1 | 1 (Huawei VRP 检测 hostname) |
| coverage_verifiability_rate | 1.0 | 1.0 |
| ospf_insufficient_info | 0 | 0 |
| ospf_network_area_mismatch | 0 | 0 |
| semantic_verifiability_rate | 0.5455 | 0.5455 |
| deployable | False (HIGH residue) | False |
| manual_review_required | False | False |
| schema_version | "1.0" | "1.0" |
| overall_verifiability_index | 0.5455 | 0.5455 |

### 链路 6: ROUTER OSPF mismatch Cisco IOS-XE → H3C Comware

| 断言 | 预期 | 实际 |
|------|------|------|
| ospf_network_area_mismatch | ≥1 | 1 |
| ospf_insufficient_info | ≥1 | 1 |
| evidence_fields (rule_id + source_ref) | present | rule_id=ospf:network_area_mismatch, source_ref=ir.ospf[1].networks |
| manual_review_required | True | True |
| deployable | False (HIGH issues) | False |
| schema_version | "1.0" | "1.0" |
| coverage_verifiability_rate | ≥0.5 | 1.0 |

---

## 6. 字段口径与映射矩阵

### deployable vs manual_review_required

| deployable | manual_review_required | 含义 |
|:---:|:---:|---|
| True | False | 无 HIGH/CRITICAL, 无 MANUAL_REVIEW |
| True | True | 无 HIGH/CRITICAL, 有 MEDIUM MANUAL_REVIEW |
| False | True | 有 HIGH/CRITICAL, 有/无 MANUAL_REVIEW |
| False | False | 有 HIGH/CRITICAL, 无 MANUAL_REVIEW |

两条独立轴线: deployable 由 severity 驱动, manual_review_required 由 category 驱动。

### 三个 verifiability_rate

| 指标 | 定义 | 范围 | 来源 |
|------|------|:---:|------|
| coverage_verifiability_rate | rendered_feature_count / ir_feature_count | 0.0–1.0 | CoverageValidator |
| semantic_verifiability_rate | baseline.verifiability_rate | 0.0–1.0 | CapabilityBaseline |
| overall_verifiability_index | coverage_rate × semantic_rate | 0.0–1.0 | CompositeValidator (新增 Phase 7D) |

### Capability → severity/category 映射矩阵

| Reason | Category | Severity | 触发条件 |
|--------|----------|:--------:|----------|
| unknown_capability | MANUAL_REVIEW | HIGH | src 或 tgt FeatureSupportStatus.UNKNOWN |
| unverifiable_checker_missing | MANUAL_REVIEW | MEDIUM | 双方 FULL 但不在 registry |
| source_partial | MANUAL_REVIEW | MEDIUM | src FeatureSupportStatus.PARTIAL |
| target_partial | MANUAL_REVIEW | MEDIUM | tgt FeatureSupportStatus.PARTIAL |

### schema_version

`REPORT_SCHEMA_VERSION = "1.0"` — 首次发布。变更策略:
- 向后兼容新增: 增加字段 (minor version bump)
- 破坏性变更: 删除/重命名/改变类型 (major version bump)
- 当前版本 1.0, 无向后兼容承诺 (首次发布)

---

## 7. OSPF Registry 最终判定

### 结论: **不回加 auto_verifiable registry**

### 论证

**7A+7E 取得的进展:**
- `_check_ospf` 具备 4 维度深校验 (info sufficiency, network/area ref, area type conflict, conversion_status)
- `_check_router` 已加入 OSPF 检查 (覆盖 ROUTER 域)
- 6 集成测试覆盖 deep pass + mismatch 场景
- 所有 issue 带 rule_id + source_ref evidence

**仍缺失的条件 (必须全部满足才能回加):**

| # | 阻塞项 | 当前状态 | 优先级 |
|---|--------|----------|:------:|
| 1 | **无跨 IR OSPF 比较** | 当前只校验 target IR 内部一致性, 不比较 src↔tgt OSPF 状态 | P0 |
| 2 | **无接口级 cost/metric 校验** | IROspf 有 reference_bandwidth 字段但 checker 未用 | P1 |
| 3 | **Network dict 键名格式未标准化** | 部分 parser 输出 "network"/"mask", 部分 "prefix"/"wildcard", checker 仅处理 "network" | P1 |

### 回加条件
上述 3 个阻塞项全部解决后, 同时:
- 所有 Phase 7A+7E OSPF 测试通过
- 新增跨 IR OSPF 比较测试
- 更新 registry 注释指向 Phase 8 的 deep OSPF checker

---

## 8. 已知限制与 Phase 8 输入

### Phase 7 已知限制

| # | 限制 | 风险 | 说明 |
|---|------|:----:|------|
| 1 | OSPF 不 在 registry | P0 | 跨 IR 比较缺失; 见 §7 |
| 2 | FIREWALL 深层校验缺失 | P1 | Phase 7E 仅框架级 firewall_semantic, 无 NAT/zone 等价校验 |
| 3 | ACL 仍无跨厂商 ACE 级等价 | P1 | 仅 order + wildcard + binding ref |
| 4 | _IR_TO_FEATURE ↔ FeatureKey 同步仍需手工 | P2 | 漂移检测测试已加, 但无自动化注册 |
| 5 | 无并行子 validator | P2 | 顺序执行, 大规模配置可能延迟 |

### Phase 8 输入 (P0→P2)

| 优先级 | 任务 | 来源 Phase |
|:------:|------|:----------:|
| P0 | 跨 IR OSPF 比较 + registry 回加 | 7A/7E |
| P0 | ACE 级 ACL 跨厂商等价验证 | Phase 6 |
| P1 | FIREWALL 深层语义 (NAT, zone policy) | 7E |
| P1 | 批量性能基线 | — |
| P2 | 并行 CompositeValidator | Phase 6 |
| P2 | 自定义报告模板 (Jinja2/HTML/PDF) | Phase 6 |

---

## 9. 冻结声明

- **parser/renderer/graph pipeline**: 本阶段 **未触及**。
- **旧兼容文件**: `ir.py`, `cisco_output_validator.py`, `h3c_to_cisco.py`, `rule_translator.py` **未删除**, fallback/adapter/deprecated 策略保持。
- **业务逻辑**: 本阶段仅修改 `core/validator/` 模块和 `tests/` 测试文件; 未改 `core/domain/`, `core/vendor/`, `core/ir_models/`, `core/parser/`, `core/renderer/`, `core/graph/`。
- **向后兼容**: `ValidationIssue.rule_id`/`source_ref`/`rendered_ref` 为 None 默认值, 所有现有调用方无需修改。CLASSIFICATION_TO_ISSUE_PARAMS 和 get_classification_issue_params() 为新增, 不破坏现有代码。
- **OSPF**: 不 在 VERIFIABLE_FEATURE_REGISTRY 中; registry 注释已更新包含回加条件和 Phase 8 指引。

---

*Phase 7 验收完毕。可进入 Phase 8 规划。*
