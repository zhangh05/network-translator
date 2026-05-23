# Phase 6 验收记录

> 验收日期: 2026-05-23
> 验收范围: Validator Capability Baseline + Capability-Aware 判定 + 审计留痕 + 多样例集成验证

---

## 1. 范围与目标

### 范围
- Phase 6A: Capability Baseline 统一模型 — VERIFIABLE_FEATURE_REGISTRY + CapabilityBaseline.derive()
- Phase 6B: Coverate/Semantic capability-aware 判定 + deployable/manual_review 规则固化 + verifiability rate 指标
- Phase 6C: 审计留痕 — evidence 字段 + schema_version + 报告输出增强 + 机器可读摘要
- Phase 6D: 多样例集成验证 — 3 条链路 (SWITCH×2 + ROUTER)
- Phase 6E: 验收包与冻结

### 非目标
- 不涉及 parser/renderer/graph pipeline 改造
- 不删除旧兼容文件 (ir.py, cisco_output_validator.py, h3c_to_cisco.py, rule_translator.py)
- 不破坏 fallback/adapter/deprecated 策略
- 不做深层语义等价校验 (留待 Phase 7 P0)
- 不添加新 VendorPlatformProfile

---

## 2. 分阶段结果

### Phase 6A: Capability Baseline (7ee84e1)

**改动文件:**
- `core/validator/capability_baseline.py` — 新增: VERIFIABLE_FEATURE_REGISTRY, CapabilityBaseline dataclass, derive() static method, to_dict()
- `core/validator/__init__.py` — CompositeValidator.validate() 接入 baseline, metadata 新增 capability_metrics/capability_gaps/capability_manual_review_items
- `tests/test_validator_capability_baseline.py` — 32 tests

**分类口径:**

| src status | tgt status | in registry | 分类 |
|---|---|---|---|
| FULL | FULL | YES | auto_verifiable_semantics |
| FULL | FULL | NO | manual_review (unverifiable_checker_missing) |
| FULL | PARTIAL | * | manual_review (target_partial) |
| FULL/PARTIAL | UNSUPPORTED/absent | * | unsupported_semantics |
| PARTIAL | * | * | manual_review (source_partial) |
| UNKNOWN | * | * | manual_review (unknown_capability) |
| UNSUPPORTED/absent | * | * | irrelevant (不纳入统计) |

### Phase 6B: Capability-Aware 判定 (2116e99 + 9961eaf)

**前置收敛 (2116e99):** OSPF 从 registry 移除 — 当前 checker 仅查 conversion_status, 无 area/cost/NSSA 校验, 标记 auto_verifiable 有误导性。采用 Option A (临时降级)。

**主任务 (9961eaf):**
- CoverageValidator capability-aware: `_adjust_coverage_against_baseline()` 后处理, manual_review 特性降级为 MANUAL_REVIEW/MEDIUM, unsupported 加标注
- SemanticValidator: 保持 failed/warning/info 分桶, LOW/INFO 不进 failed
- 新指标: `coverage_verifiability_rate` + `semantic_verifiability_rate`
- deployable/manual_review 规则固化: 3 种组合全部测试覆盖

### Phase 6C+6D: 审计留痕 + 多样例集成 (92739bc)

**审计增强:**
- `ValidationIssue` 新增 `rule_id`/`source_ref`/`rendered_ref` (None 默认值, 向后兼容)
- `report_markdown.py` 重写: Capability Boundary 章节, Manual Review Checklist 表格
- `schema_version=1.0` 写入 `to_dict()`
- `docs/phase6_summary.json` — 机器可读验收摘要
- 修复 Python 3.9 Enum TypeError in `_record_check`

**多样例集成:**
- 链路 1: H3C Comware → Cisco IOS-XE SWITCH (6 断言)
- 链路 2: Cisco IOS-XE → Huawei VRP ROUTER (6 断言)
- 链路 3: Huawei VRP → Cisco IOS-XE SWITCH (6 断言)

### Phase 6E: 验收包与冻结 (当前 commit)

---

## 3. 全部 commit hashes (时间顺序)

```
7ee84e1 Phase 6A: Capability Baseline complete implementation
2116e99 Phase 6B pre-convergence: Remove OSPF from verifiable registry (Option A)
9961eaf Phase 6B: Validator capability-aware + deployable/manual_review rules + metrics
92739bc Phase 6C+6D: Audit evidence + report stabilization + multi-sample integration
412f217 docs: fill actual commit hash in phase6_summary.json
<PHASE_6E_COMMIT> Phase 6E: Acceptance package & freeze
```

---

## 4. 测试命令与结果

### 定向测试

```bash
# Phase 6A: Capability Baseline (32 tests)
PYTHONPATH=. venv/bin/python3 -m pytest tests/test_validator_capability_baseline.py -v
→ 32 passed

# Phase 6B: 全部 validator (85 + 32 = 117)
PYTHONPATH=. venv/bin/python3 -m pytest tests/test_validator_*.py -v
→ 117 passed

# Phase 6C+6D: 集成验证 (18 tests)
PYTHONPATH=. venv/bin/python3 -m pytest tests/test_integration_phase6.py -v
→ 18 passed
```

### 全量回归

```bash
PYTHONPATH=. venv/bin/python3 -m pytest tests/ -v
→ 1010 passed / 13 pre-existing failures / 3 skipped
```

13 个预存失败均为外部依赖缺失 (flask, requests) 或旧 analyzer 测试, 与 Phase 6 无关。

---

## 5. 关键断言逐项列值

### 链路 1: H3C Comware → Cisco IOS-XE SWITCH

| 断言 | 预期 | 实际 |
|------|------|------|
| residue 计数 | 0 | 0 |
| ir_feature_count | 4 | 4 |
| rendered_feature_count | 4 | 4 |
| coverage_verifiability_rate | 1.0 | 1.0 |
| semantic passed_checks 包含 vlan_names/svi_ips/static_routes | ✅ | ✅ |
| semantic info_checks 包含 acl_entries | ✅ | ✅ |
| semantic_verifiability_rate > 0 | ✅ | ✅ |
| capability total_features_considered ≥ 10 | 10+ | ✅ |
| capability auto_verifiable ≥ 5 | 5+ | ✅ |
| capability verifiability_rate > 0 | ✅ | ✅ |
| deployable | True | True |
| manual_review_required | False | False |
| schema_version | "1.0" | "1.0" |

### 链路 2: Cisco IOS-XE → Huawei VRP ROUTER

| 断言 | 预期 | 实际 |
|------|------|------|
| residue 检出 hostname | ≥1 | ✅ |
| coverage gap 检测 (BGP/VRF 未渲染) | coverage 或 manual_review issue 存在 | ✅ |
| capability total_features_considered ≥ 3 | 3+ | ✅ |
| capability verifiability_rate 存在 | ✅ | ✅ |
| semantic_verifiability_rate ≥ 0 | ≥0 | ✅ |
| schema_version | "1.0" | "1.0" |
| issue field 可追溯 | 至少 1 个 issue 有 field | ✅ |

### 链路 3: Huawei VRP → Cisco IOS-XE SWITCH

| 断言 | 预期 | 实际 |
|------|------|------|
| residue 计数 | 0 | 0 |
| coverage_verifiability_rate | 1.0 | 1.0 |
| semantic checked > 0 | ✅ | ✅ |
| semantic_verifiability_rate 存在 | ✅ | ✅ |
| capability total_features_considered ≥ 5 | 5+ | ✅ |
| deployable | True | True |
| manual_review_required | False | False |
| to_dict() JSON 可序列化 | ✅ | ✅ |
| schema_version | "1.0" | "1.0" |

---

## 6. 报告字段一致性说明

### 字段体系

```
ValidationReport
├── schema_version: str = "1.0"                     # JSON schema 版本
├── summary: dict[IRRiskLevel, int]                  # 按 severity 计数 (仅非零)
├── total_issues: int                                # len(issues)
├── deployable: bool                                 # policy 或无 policy 下的 CRITICAL/HIGH 检查
├── manual_review_required: bool                     # issues 中是否有 MANUAL_REVIEW category
├── issues: list[ValidationIssue]                    # 所有检查结果
│   └── evidence: rule_id / source_ref / rendered_ref (可选)
└── metadata: dict
    ├── coverage_metrics: dict
    │   ├── ir_feature_count: int
    │   ├── rendered_feature_count: int
    │   └── coverage_verifiability_rate: float       # rendered / ir (仅当 ir > 0)
    ├── semantic_metrics: dict
    │   ├── checked: list[str]
    │   ├── passed_checks: list[str]
    │   ├── failed_checks: list[str]
    │   ├── warning_checks: list[str]
    │   ├── info_checks: list[str]
    │   └── semantic_verifiability_rate: float       # baseline.verifiability_rate
    ├── capability_metrics: dict
    │   ├── total_features_considered: int
    │   ├── auto_verifiable: int
    │   ├── manual_review: int
    │   ├── unsupported: int
    │   └── verifiability_rate: float                # auto / total
    ├── capability_gaps: list[str]                   # unsupported FeatureKey values
    └── capability_manual_review_items: dict[str, list[str]]  # reason → FeatureKey values
```

### 关键关系

- **deployable** 与 **manual_review_required** 独立: MANUAL_REVIEW 类别 issue 不影响 deployable 判定, 除非其 severity 为 HIGH/CRITICAL。MEDIUM MANUAL_REVIEW → deployable=True + manual_review_required=True。
- **verifiability_rate** (capability) vs **coverage_verifiability_rate** (coverage) vs **semantic_verifiability_rate** (semantic): 三者含义不同但共享同一个 baseline 来源。
  - `capability_metrics.verifiability_rate` = auto_verifiable / total_features_considered
  - `coverage_metrics.coverage_verifiability_rate` = rendered_feature_count / ir_feature_count (渲染覆盖率)
  - `semantic_metrics.semantic_verifiability_rate` = same as capability_metrics.verifiability_rate
- **schema_version** 从 `REPORT_SCHEMA_VERSION = "1.0"` 常量读取；变更时需同步升级。

---

## 7. 已知限制与风险分级

| # | 限制 | 风险级 | 说明 |
|---|------|--------|------|
| 1 | OSPF 已从 registry 移除 | P0 | 当前仅 conversion_status 浅层检查, 需深层 checker 后回加 |
| 2 | ACL 语义校验有限 | P0 | 仅 sequence order + permit ip any any + binding ref; 无 ACE 级跨厂商等价验证 |
| 3 | FIREWALL registry 条目最少 | P1 | 仅框架级 SemanticValidator 存在, 深层 checker 需补充 |
| 4 | _COVERAGE_FIELD_TO_FEATURE_KEY 手工维护 | P1 | 需与 _IR_TO_FEATURE 自动同步, 否则 coverage 后处理可能漏匹配 |
| 5 | Coverage 能力感知是后处理 | P2 | 未内建到 CoverageValidator 自身, 导致耦合于 CompositeValidator |
| 6 | 子 validator 无并行执行 | P2 | 顺序执行, 大规模配置时可能延迟 |
| 7 | markdown 报告无自定义模板 | P2 | 当前纯手写字符串拼接, 无 Jinja2/HTML 支持 |
| 8 | 13 个预存测试失败 | 外部 | 依赖 flask/requests 未安装, 与 Phase 6 无关 |

---

## 8. Phase 7 建议

### P0 (建议优先)
1. **深层 OSPF checker**: area/interface cost/NSSA/network type 跨厂商语义验证。完成后再将 OSPF 移回 registry。
2. **ACE 级 ACL 等价验证**: H3C advanced ACL ↔ Cisco extended ACL 逐条等价性检查 (src/dst/proto/port 完全匹配, wildcard 语义等价)。

### P1
3. **SNMP/NTP/LLDP 语义验证** — 扩展 ROUTER/SWITCH 通用管理协议检查。
4. **_COVERAGE_FIELD_TO_FEATURE_KEY 自动同步** — 基于 _IR_TO_FEATURE 和 IRConfig 字段的反射生成。
5. **FIREWALL 深层 checker** — zone policy / security policy 规则级等价验证。

### P2
6. **并行 CompositeValidator** — concurrent.futures 并行子 validator。
7. **自定义报告模板** — Jinja2 HTML/PDF 报告支持。
8. **report_to_dict 版本兼容检查** — 基于 schema_version 做向后兼容断言。

---

## 9. 冻结声明

- **parser/renderer/graph pipeline**: 本阶段 **未触及**。
- **旧兼容文件**: `ir.py`, `cisco_output_validator.py`, `h3c_to_cisco.py`, `rule_translator.py` **未删除**, fallback/adapter/deprecated 策略保持。
- **业务逻辑**: 本阶段仅修改 `core/validator/` 模块和 `tests/` 测试文件; 未改 `core/domain/`, `core/vendor/`, `core/ir_models/`, `core/parser/`, `core/renderer/`, `core/graph/`。
- **向后兼容**: `ValidationIssue.rule_id`/`source_ref`/`rendered_ref` 为 None 默认值, 所有现有调用方无需修改。
- **schema 版本**: `REPORT_SCHEMA_VERSION = "1.0"` 首次发布, 后续变更必须递增。

---

*Phase 6 验收完毕。可进入 Phase 7 规划。*
