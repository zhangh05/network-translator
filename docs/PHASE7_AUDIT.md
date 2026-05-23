# Phase 7 Batch 1 (7A+7B+7C) — 审计说明

> 针对 commit a57f546，说明首次纳管文件中的已有代码与新增代码的分界。

---

## coverage_validator.py (140 行)

| 类型 | 行号 | 内容 | 说明 |
|------|------|------|------|
| 已有 | 1–9 | 模块导入 | 前置开发阶段已有，本批未改 |
| 已有 | 12–32 | `_IR_TO_FEATURE` | 前置开发阶段已有，本批未改 |
| **新增** | **34–61** | **`_IR_FIELD_TO_FEATURE_KEY` + `get_feature_mapping()`** | **Phase 7B 新增** |
| 已有 | 64–74 | `_ir_feature_presence()` | 前置开发阶段已有，本批未改 |
| 已有 | 77–140 | `CoverageValidator` 类 | 前置开发阶段已有，本批未改 |

**结论：** `_IR_FIELD_TO_FEATURE_KEY` 和 `get_feature_mapping()` 为 Phase 7B 新增。其余代码为历史存量，纳管时未改动。

---

## test_validator_coverage.py (174 行)

| 类型 | 行号 | 内容 | 说明 |
|------|------|------|------|
| 已有(改) | 1–14 | 模块导入 | 原有 import 中新增 `get_feature_mapping`, `_IR_TO_FEATURE` |
| 已有 | 17–35 | `_make_ir()`, `_span()` | 前置开发阶段已有，本批未改 |
| 已有 | 38–146 | `TestCoverageValidator` (7 tests) | 前置开发阶段已有，本批未改 |
| **新增** | **149–174** | **`TestCoverageMappingSingleSource` (3 tests)** | **Phase 7B 新增** |

**结论：** 导入行新增了两个符号引用；`TestCoverageMappingSingleSource` 为 Phase 7B 新增。其余测试为历史存量，纳管时未改动。

---

## 其他文件（非首次纳管）

| 文件 | 操作 | 说明 |
|------|------|------|
| `core/validator/semantic_validator.py` | 修改 | Phase 7A 增强 `_check_ospf` + `_make_issue` 参数扩展 |
| `core/validator/__init__.py` | 修改 | Phase 7B 映射来源改为 `coverage_validator.get_feature_mapping()` |
| `tests/test_validator_semantic.py` | 修改 | Phase 7A 新增 `TestSemanticValidatorOspf` (6 tests) |
| `tests/test_schema_contract.py` | **新增** | Phase 7C 全新 (21 tests) |
