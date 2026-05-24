# Fallback Review Summary — User-Readable & Redacted (2026-05-24)

## Status

Draft → User must approve before implementation.

## Problem Statement

The current `FallbackNode._manual_review_fallback()` in `core/graph/nodes.py` generates a manual review summary that:
1. Uses raw feature codes (`aaa`, `acl`, `qos`, `snmp`, `vlan`) as user-visible labels
2. Shows unredacted sensitive values (passwords, community strings, keys) in example lines
3. Exposes internal diagnostics ("第 0 项不是对象", "LLM 输出校验失败") to users
4. Has no risk level per category
5. Has no review reason per category
6. Does not group firewall objects (address-set, service-set, security-policy) correctly

## Design: User-Readable Category Structure

### 6 User-Facing Categories

| Internal feature | User label |
|-----------------|-----------|
| `aaa`, `system` (user/logger) | **管理面** |
| `interface`, `vlan`, `二层` | **接口与 VLAN** |
| `acl`, `firewall-object`, `security-policy` | **ACL 与安全策略** |
| `ospf`, `bgp`, `static-route`, `route-policy`, `route` | **路由协议** |
| `address-set`, `service-set`, `address-object`, `service-object` | **防火墙对象** |
| (everything else) | **未支持能力** |

### Per-Category Fields

Each category section must include:
- Count: `N 个配置块`
- Risk level: `⚠ 高风险` / `△ 中风险` / `○ 低风险`
- Review reason: one sentence explaining why human review is needed
- Example lines: max 3 lines, source lines (with sensitive values redacted)

### Risk Level Assignment

| Condition | Level |
|-----------|-------|
| Contains password/cipher/irreversible-cipher or shared-key or secret | **高** |
| Contains ACL rules or firewall object definitions | **中** |
| Contains routing protocols (OSPF/BGP) or interface with IP | **中** |
| Contains VLAN without IP | **低** |
| Unknown feature (no mapping) | **低** |

### Review Reason Templates

| Category | Reason template |
|----------|----------------|
| 管理面 | 涉及认证/授权/日志等关键控制面配置，语义可能因厂商而异 |
| 接口与 VLAN | 二层/三层接口和 VLAN 配置在目标平台可能语义不同 |
| ACL 与安全策略 | 访问控制列表和安全策略需人工确认对应关系 |
| 路由协议 | 路由协议配置（OSPF/BGP 等）需确认目标平台 AS/进程号 |
| 防火墙对象 | 防火墙对象（地址集/服务集/安全策略）需人工确认映射 |
| 未支持能力 | 目标平台未确认支持此功能，建议人工确认是否需要迁移 |

## Design: Sensitive Value Redaction

### Redaction Patterns

Before populating example lines, sanitize each source line with:

```python
def _redact_sensitive_values(line: str) -> str:
    patterns = [
        (r'(password\s+)irreversible-cipher\s+\S+', r'\1irreversible-cipher <redacted>'),
        (r'(password\s+)cipher\s+\S+', r'\1cipher <redacted>'),
        (r'(password\s+)\S+', r'\1<redacted>'),
        (r'(shared-key\s+)cipher\s+\S+', r'\1cipher <redacted>'),
        (r'(shared-key\s+)\S+', r'\1<redacted>'),
        (r'(secret\s+)cipher\s+\S+', r'\1cipher <redacted>'),
        (r'(secret\s+)\S+', r'\1<redacted>'),
        (r'(community\s+)read\s+cipher\s+\S+', r'\1read cipher <redacted>'),
        (r'(community\s+)write\s+cipher\s+\S+', r'\1write cipher <redacted>'),
        (r'(community\s+)\S+', r'\1<redacted>'),
        (r'(key\s+)cipher\s+\S+', r'\1cipher <redacted>'),
    ]
    result = line
    for pattern, replacement in patterns:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    return result
```

## Design: Internal Diagnostics Isolation

The `fallback_reason` field goes into internal metadata only:
- `fallback_reason=...` (metadata line, fine as internal)
- NOT shown in user-visible summary section

The user-visible summary should show a friendly reason:
- "自动翻译未生成可验证结果" (not the raw error)

## Design: Deterministic Fallback Block

Unchanged — must continue to output:
```
BEGIN_DETERMINISTIC_FALLBACK
...deterministically translated config...
END_DETERMINISTIC_FALLBACK
```

The `MANUAL_REVIEW` prefix marks lines that need human review in the comment block.

## Design: Frontend Fallback Notice

Current `index.html` already has the notice at lines 860-861:
```html
fallbackNotice="<div class='rs risk--review'><div class='rs__hd'>⚠ 规则兜底 — 已启用</div>...
```

This notice already covers all requirements. The frontend tests should verify it is present and correct when `fallback_used=true`.

## Files to Change

1. `core/graph/nodes.py` — rewrite `FEATURE_LABELS`, `_manual_review_fallback()`, add `_redact_sensitive_values()`, add `_CATEGORY_GROUPS`, add `_RISK_LEVELS`, add `_REVIEW_REASONS`
2. `tests/test_realistic_fallback_report.py` — full rewrite with strict assertions
3. `tests/test_frontend_fallback_ux.py` — new file
4. `frontend/index.html` — no changes expected, but check line 860 matches requirements

## Testing Requirements

### test_realistic_fallback_report.py

**A. Friendly categories present** — assert these exact Chinese labels appear in summary:
- 管理面
- 接口与 VLAN
- ACL 与安全策略
- 路由协议
- 防火墙对象
- 未支持能力

**B. No raw feature codes as only label** — assert raw codes `aaa`, `acl`, `qos`, `snmp` do NOT appear as the sole label (they may appear in metadata or comment-prefixed internal sections, but NOT in the user summary line itself as the category name).

**C. Per-group fields** — for each category present:
- count (数字 + 个配置块)
- risk level (高/中/低)
- review reason (at least one Chinese sentence)
- example lines ≤ 3

**D. Sensitive redaction** — input contains `SECRET_PASS` / `PUBLIC_COMM` / `RADIUS_KEY`; assert these exact strings do NOT appear anywhere in output; assert `<redacted>` (or equivalent) appears.

**E. Internal diagnostics hidden** — input error contains "LLM 输出校验失败: 第 0 项不是对象"; assert these exact strings do NOT appear in user-visible output.

**F. Source residue zero** — executable lines (non-comment) contain no source vendor residue:
- `traffic classifier`
- `local-user`
- `interface Vlanif`
- `vlan batch`
- `security-policy rule`
- `ip address-set`

**G. Firewall object classification** — Huawei USG config with `address-set`, `service-set`, `security-policy`; assert "防火墙对象" or "ACL 与安全策略" appears in summary, NOT "未支持能力" only.

**H. Routing protocol classification** — OSPF/BGP config; assert "路由协议" appears in summary, NOT "未支持能力" only.

### test_frontend_fallback_ux.py

Assert that when `fallback_used=true`:
1. The page shows "规则兜底已启用" (or similar)
2. The page shows "可执行配置只包含系统能确定的转换"
3. The page shows "其余内容已进入人工复核"
4. The page shows "请查看人工复核摘要" (or similar)
5. MANUAL_REVIEW lines are styled with the `.mr` CSS class

---

*Approve to proceed to implementation, or ask for changes.*