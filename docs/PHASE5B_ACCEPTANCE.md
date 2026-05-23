# Phase 5B 验收记录

> 验收日期: 2026-05-23
> 验收范围: Validator 基础设施 + CoverageValidator + SemanticValidator + 收敛修正

---

## 1. 变更清单

### 架构基础设施 (Phase 0–Phase 5A)

| Commit | 说明 |
|--------|------|
| `2f32278` | IR 类型枚举 (IRType) |
| `79ce6fa` | SourceSpan, IRModelBase, IRConfigMeta, IRConfig |
| `66bb084` | common/switch/router/firewall/unsupported 数据模型 |
| `15ae0cd` | DeviceDomain, FeatureKey, DomainProfile, DomainDetector |
| `85cc428` | 8 个 VendorPlatformProfile + 注册表 |
| `879bf22` | Parser 基础设施 + 8 个 skeleton 解析器 |
| `273d942` | H3C Comware SWITCH 全量解析器 (99.75% coverage) |
| `f3f4d70` | Renderer 基础设施 + 8 个 skeleton 渲染器 |
| `57738c0` | Cisco IOS-XE SWITCH 全量渲染器 |

### Phase 5B: Validator (当前验收)

| Commit | 说明 |
|--------|------|
| `7abf537` | Phase 5B 收敛修正: IR-level acl_binding, 4-bucket metrics, manual_review_required |

`7abf537` 包含:
- `core/validator/base.py` — ValidationCategory, ValidationIssue, ValidationReport, ValidationPolicy
- `core/validator/residue_validator.py` — 跨厂商残留检测
- `core/validator/conversion_validator.py` — IR 转换状态检查
- `core/validator/capability_gap_validator.py` — 能力差距比较
- `core/validator/syntax_validator.py` — 基础语法校验
- `core/validator/coverage_validator.py` — 渲染覆盖率检查
- `core/validator/semantic_validator.py` — 语义一致性检查 (SWITCH + ROUTER + FIREWALL)
- `core/validator/__init__.py` — CompositeValidator 组合验证器
- `core/validator/report_json.py` / `core/validator/report_markdown.py` — 报告输出
- `tests/test_validator_base.py` (21+4 新测试)
- `tests/test_validator_semantic.py` (15 测试)
- `tests/test_validator_composite.py` (9 测试)
- `tests/test_validator_coverage.py` (8 测试)
- `tests/test_validator_residue.py` (12 测试)
- `tests/test_validator_conversion.py` (8 测试)
- `tests/test_validator_capability_gap.py` (4 测试)

---

## 2. ValidationReport 字段口径

### 核心字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `issues` | `list[ValidationIssue]` | 所有检查结果 |
| `metadata` | `dict` | 额外信息 (profiles, coverage_metrics, semantic_metrics) |
| `total_issues` | `int` | `len(issues)` |
| `deployable` | `bool` | 是否允许部署 (受 ValidationPolicy 控制) |
| `manual_review_required` | `bool` | 是否有 MANUAL_REVIEW 类别问题 |
| `summary` | `dict[IRRiskLevel, int]` | 按严重级别计数 (只含非零) |
| `by_category()` | `dict[str, list]` | 按类别分组的 issues |
| `by_severity()` | `dict[str, list]` | 按严重级别分组的 issues |
| `to_dict()` | `dict` | JSON 可序列化字典 |

### deployable

`deployable` 计算规则:
- 无 policy 时: 不允许 CRITICAL 或 HIGH 严重级别的问题
- 有 policy 时: `policy.allows_deploy(report)` — 可配置 `max_high` 阈值、`categories_to_block`、`forbid_unsupported`、`allow_deploy_on_warnings` 等

```python
def deployable(self) -> bool:
    if self.policy:
        return self.policy.allows_deploy(self)
    return all(
        issue.severity not in (IRRiskLevel.CRITICAL, IRRiskLevel.HIGH)
        for issue in self.issues
    )
```

### manual_review_required

`manual_review_required` 与 `deployable` 独立:
- 任何 `ValidationCategory.MANUAL_REVIEW` 类别的问题 => `manual_review_required = True`
- MANUAL_REVIEW 问题不影响 deployable 判定, 除非其 severity 为 HIGH/CRITICAL
- 常见触发场景: `features_skipped`、`ir is None` (结构化 IR 不可用)

```python
@property
def manual_review_required(self) -> bool:
    return any(
        issue.category == ValidationCategory.MANUAL_REVIEW
        for issue in self.issues
    )
```

### coverage_metrics

存储在 `report.metadata["coverage_metrics"]`, 类型 `dict[str, int]`:

| 字段 | 说明 |
|------|------|
| `ir_feature_count` | IR 中非零出现的特性数 |
| `rendered_feature_count` | `render_result.features_rendered` 长度 |

### semantic_metrics

存储在 `report.metadata["semantic_metrics"]`, 类型 `dict[str, list[str]]`:

| 字段 | 说明 |
|------|------|
| `checked` | 所有已执行的检查名称 |
| `passed_checks` | 无任何 issue 的检查 |
| `failed_checks` | 包含 HIGH 或 CRITICAL issue 的检查 |
| `warning_checks` | 包含 MEDIUM issue 的检查 |
| `info_checks` | 包含 LOW issue 的检查 |

分类规则 (代码 `_record_check`):
- 无 issue → `passed_checks`
- 最高 severity 为 LOW → `info_checks`
- 最高 severity 为 MEDIUM → `warning_checks`
- 最高 severity 为 HIGH 或 CRITICAL → `failed_checks`

---

## 3. test_config 链路验证结果

### 场景: H3C Comware → Cisco IOS-XE 干净回环

**输入 IR 特性**: vlans(1), svis(1), acls(1), static_routes(1)
**渲染结果**: 4/4 特性完全渲染

| 断言 | 预期 | 实际 | 状态 |
|------|------|------|------|
| 总 issue 数 | 1 (LOW 语义) | 1 | ✅ |
| deployable | True | True | ✅ |
| manual_review_required | False | False | ✅ |
| LOW 语义 issue 内容 | ACL 2000 permit ip any any | ✅ | ✅ |
| residue 残留 | 0 | 0 | ✅ |
| conversion 问题 | 0 | 0 | ✅ |
| coverage 问题 | 0 | 0 | ✅ |
| semantic 问题 | 1 (LOW) | 1 | ✅ |
| ir_feature_count | 4 | 4 | ✅ |
| rendered_feature_count | 4 | 4 | ✅ |
| acl_entries 在 info_checks | ✅ | ✅ | ✅ |
| 无 failed_checks | ✅ | ✅ | ✅ |

### 验证命令

```bash
PYTHONPATH=. venv/bin/python3 /var/folders/yg/.../verify_phase5b.py
```

---

## 4. 定向测试结果

| 测试文件 | 测试数 | 通过 | 命令 |
|----------|--------|------|------|
| coverage validator | 8 | 8 | `pytest tests/test_validator_coverage.py -v` |
| semantic validator | 15 | 15 | `pytest tests/test_validator_semantic.py -v` |
| composite validator | 9 | 9 | `pytest tests/test_validator_composite.py -v` |
| 全部 validator | 64+ | 64+ | `pytest tests/test_validator_*.py -v` |
| 全量回归 | 970 | 954 通过 / 13 预存失败 / 3 跳过 | `pytest tests/ -v` |
| test_config 集成 | 9 断言 | 9/9 | `python3 verify_phase5b.py` |

13 个预存失败均为外部依赖缺失 (flask, requests) 或旧 analyzer 测试, 与本阶段无关。

---

## 5. 已知限制

### SemanticValidator (SWITCH)
1. **ACL 语义深度校验有限**: 仅检查 sequence 顺序、permit ip any any 检测、ACL binding 引用存在性。未做 ACE 级交叉厂商语义等价 (如 H3C advanced ACL → Cisco extended ACL 逐条等价验证)
2. **FHRP 语义**: 仅标记 conversion_status, 未验证 VRRP/HSRP 参数等价性 (preempt delay, priority, authentication)
3. **OSPF 语义**: 仅检查 conversion_status, 未验证 area/interface/NSSA 配置语义
4. **LAG 成员**: 仅检查 conversion_status, 未验证成员端口名映射等价性
5. **Static route**: 仅检查 conversion_status, 未验证 VRF route leaking 语义

### CoverageValidator
6. **特性映射硬编码**: `_IR_TO_FEATURE` 字典包含 ~20 个预定义映射项, 未覆盖所有可能的 IR 字段
7. **lacp → lags 多键映射**: 仅做 `any(e in rendered_feature_names for e in expected)` 简单匹配, 未处理部分渲染场景

### CompositeValidator (通用)
8. **无并行校验**: 所有子 validator 顺序执行, 无并行化
9. **报告格式**: JSON/Markdown 输出基础, 无自定义模板
10. **无缓存**: 每次 `validate()` 重新执行所有子校验

---

## 6. Phase 6 建议

### P0 (建议优先)
1. **ACE 级 ACL 语义验证**: 实现 H3C basic/advanced ACL ↔ Cisco standard/extended ACL 条目级等价性检查
2. **FHRP 参数验证**: 添加 VRRP/HSRP 关键参数 (priority, preempt, auth) 的跨厂商语义等价检查
3. **OSPF 语义深入**: 验证 area 配置、interface cost、network type 的等价性
4. **Coverage 映射扩展**: 基于 IR 数据模型的反射自动生成 `_IR_TO_FEATURE` 映射, 消除硬编码遗漏

### P1
5. **SNMP / NTP / LLDP 语义验证**: 扩展 ROUTER/SWITCH 通用管理协议检查
6. **VLAN name 语义验证**: 验证 VLAN name 长度限制和特殊字符跨厂商兼容性
7. **Performance 基准**: 对 10000+ 行配置做 validator 延迟测试

### P2
8. **并行 CompositeValidator**: 使用 `concurrent.futures` 并行化子 validator
9. **可定制报告模板**: 支持 Jinja2 模板定制 HTML/PDF 报告
10. **缓存层**: 对重复校验结果做 LRU 缓存 (需考虑 IR 不变性判断)

---

## 7. 结论

Phase 5B 通过验收。全部 64+ 定向测试通过, 970 全量回归无回归, test_config 集成链路 9/9 断言通过。CompositeValidator 可在旧翻译管线中部署作为 VALIDATION 阶段加强。

已知限制已记录, 不影响本轮部署。建议 Phase 6 按 P0→P1→P2 优先级推进语义深度校验。
