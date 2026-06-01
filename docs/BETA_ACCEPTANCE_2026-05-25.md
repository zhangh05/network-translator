# Beta Acceptance — 2026-05-25

> Batch J-A: 已知 tolerated failures 清零
> Base commit: `2eeb2de`

---

## 1. 项目定位

本项目不是"AI 配置翻译网页"，而是**可审计、可验证、可复核的多设备域、多厂商网络配置迁移与审计系统**。

核心承诺：结构化解析 → 语义迁移 → 覆盖率校验 → 残留检测 → 风险/人工复核报告。

---

## 2. 当前 Beta 能力边界

### SWITCH

| 能力 | 状态 | 说明 |
|------|------|------|
| H3C Comware → Cisco IOS XE | ✅ 最强验证链路 | VLAN / SVI / trunk/access / ACL binding / OSPF 基础 / 管理面部分转换 |
| Cisco → H3C | ✅ 基础 fallback | 基础 VLAN 转换，hostname 残留已知 |
| Huawei VRP → Cisco | ✅ 基础 fallback | 类似 H3C 覆盖范围 |
| Ruijie RGOS → Cisco/Huawei | ✅ 基础 fallback | 基础接口/VLAN 转换 |
| **不能做** | ❌ | 不覆盖：三层接口子接口、stackwise、MLAG、MSTP 实例。本系统不提供全量交换配置迁移。 |

### ROUTER

| 能力 | 状态 | 说明 |
|------|------|------|
| Static route | ✅ 自动转换 | Cisco/Huawei/H3C/Ruijie 四向 |
| OSPF 基础 | ✅ 自动转换 | 基础 area/network/passive-interface |
| OSPF 深语义 | ⚠️ 人工复核 | NSSA/virtual-link/redistribute/import-route 必须人工复核 |
| BGP skeleton | ⚠️ 人工复核 | peer/network 骨架，route-policy 必须人工复核 |
| VRF skeleton | ⚠️ 人工复核 | RT import/export 骨架，复杂 VRF 必须人工复核 |
| Route-policy | ⚠️ 部分骨架 + 人工复核 | match/set 基础子句，community/continue/extcommunity 必须人工复核 |
| **不能做** | ❌ | 本系统不提供全量路由协议迁移。中级以上 OSPF/BGP/VRF 安全边界需人工复核。 |

### FIREWALL

| 能力 | 状态 | 说明 |
|------|------|------|
| Zone 基础转换 | ✅ 部分自动 | Huawei USG → Hillstone / Topsec 部分 zone 映射 |
| Address object | ✅ 小范围 | 地址对象自动转换（IP/subnet/range） |
| Service object | ✅ 小范围 | TCP/UDP/ICMP 端口自动转换 |
| Complete policy | ✅ 小范围 | 简单策略全链路自动（zone/address/service/action） |
| NAT | ❌ 人工复核 | 无自动 NAT 转换，全部标记 MANUAL_REVIEW |
| IPsec | ❌ 人工复核 | 无自动 IPsec 转换 |
| URL/AV/time-range | ❌ 人工复核 | 高级安全策略未覆盖 |
| **不能做** | ❌ | 本系统不提供全量防火墙迁移。复杂策略、NAT、IPsec、URL/AV 必须人工复核。 |

---

## 3. 主链路状态

- **Parser → IR → Renderer → Validator 主链路已存在**（新架构建设中）
- 当前**最强验证链路**仍是 H3C Comware SWITCH → Cisco IOS XE SWITCH
- 多厂商 fallback（`RuleBasedTranslator` + `H3CToCiscoFallback`）是 Beta 能力补充，**不等同于完整 IR 语义迁移**
- 不要把 fallback 描述成主架构完成
- Validator pipeline（residue/coverage/semantic/syntax/capability-gap）已独立运行
- LLM 驱动翻译路径作为兼容旧路径保留，输出经过 validator + redaction + manual review 三重检查

---

## 4. UI/用户体验状态

| 功能 | 状态 |
|------|------|
| 翻译结果 tab 显示 deployable_config | ✅ 优先 deployable_config，fallback 用 translated |
| 风险/校验/差异 tab | ✅ 风险分析（中文分类）、校验结果、差异对比 |
| 项目结果跨刷新持久化 | ✅ 刷新后结果保留 |
| 项目结果多窗口可见 | ✅ 新窗口看到同一结果 |
| 项目窗口可命名 | ✅ 侧边栏重命名 |
| 复制全部配置 | ✅ 优先 deployable_config |
| 复制可部署配置 | ✅ 过滤 MANUAL_REVIEW 行 |
| 复制风险报告 | ✅ 结构化文本报告 |
| 服务地址 0.0.0.0:5008 | ✅ 内网可访问 |

---

## 5. 输出脱敏状态

| 维度 | 状态 |
|------|------|
| 统一脱敏函数 | ✅ `redact_sensitive_output()` 实现于 `project_store.py` |
| 覆盖路径 | ✅ 新翻译、复用、GET list、GET detail、PUT/store.update_project |
| 覆盖字段 | ✅ `translated` / `deployable_config` / `diff` / `validation` / `risk_signals` / `capability_gaps` / `analyzer_results` / `node_results` |
| 脱敏模式 | 14 种：password/secret/cipher/irreversible-cipher/shared-key/pre-shared-key/snmp-community/snmp-agent-community-cipher/tacacs-key/radius-key/neighbor-password/set-community/apply-community |
| LLM 成功路径 | ✅ 覆盖 |
| Fallback 路径 | ✅ 覆盖 |
| 持久化文件 | ✅ 磁盘 JSON 不含明文 |
| **残余风险** | ⚠️ 未知厂商自定义密钥格式可能需要继续补模式 |

---

## 6. 测试状态

| 测试范围 | 口径 |
|----------|------|
| `tests/test_output_redaction.py` | **47 passed** — 16 种模式匹配 + 无假阳性 + 幂等性 + 递归结构 + cipher 上下文 + ProjectStore 集成 |
| `tests/test_project_store.py` + `test_translation_reuse.py` + `test_frontend_fallback_ux.py` + `test_fallback_user_report_quality.py` | **124 passed** |
| fallback 相关套件* | **多文件覆盖** — rule_translator + realistic fallback + switch/router/firewall 多厂商 |
| CI gate (--full) | **2345 passed / 0 known tolerated / 30 skipped** |
| 全量测试 (`pytest tests/`) | **2346 passed / 0 failed / 29 skipped** |

> *fallback 套件包含：test_fallback_user_report_quality.py、test_realistic_fallback_report.py、test_safe_fallback_and_block_splitter.py、test_rule_translator_*.py 等

### Known tolerated failures

**已全部清零（Batch J-A）** — 此前 13 个已知 tolerated failures + 1 个 packaging 临时 tolerated 已全部修复。当前 CI gate 全绿，无 tolerated failure。

| 问题类别 | 数量 | 修复方式 |
|----------|------|----------|
| analyzer object registry (yaml 缺失) | 7 | 安装 PyYAML + `/readyz` runtime checks |
| Flask contract/readyz (Flask 缺失) | 4 | 安装 Flask + `/readyz` `checks` 字段 |
| requests retry (requests 缺失) | 2 | 安装 requests |
| packaging port 校准 | 1 | 测试已通过，不再 tolerated |

---

## 7. 已知限制

1. **GitHub Actions runner 未实测** — 当前所有 CI 跑在本地，未在 GitHub Actions 远端运行
2. **Known tolerated failures 已清零** — 13 个依赖/缺失 + packaging 端口校准已全部修复（Batch J-A），当前 0 tolerated
3. **OSPF 深语义未完全自动验证** — NSSA/virtual-link/redistribute 需人工复核
4. **NAT/IPsec/URL/AV/time-range 不自动转换** — 全部标记 MANUAL_REVIEW
5. **AAA/QoS/route-policy 只支持小范围或骨架** — 复杂语义必须人工复核
6. **Fallback 不是完整语义迁移** — 确定性规则翻译不等同于 IR 语义等价
7. **LLM 输出仍可能语义不准确** — 必须经过 validator → report → manual review 三重检查
8. **未知 secret 格式可能需要补脱敏规则** — 新增厂商/格式需扩展 `_REDACT_PATTERNS`
9. **生产上线仍需真实设备/仿真环境验证** — 本系统输出不能跳过设备级测试
10. **ProjectStore 使用文件锁** — SQLite WAL 模式可替代高并发场景
11. **Web 使用 Flask dev server 运行** — 生产应用 gunicorn（scripts/start.sh 自动检测）
12. **SemanticMemory 使用词法匹配** — embedding 匹配是后续增强

---

## 8. Beta Ready 判定

```
BETA_READY = YES (conditional)
```

### 通过条件

| 条件 | 状态 |
|------|------|
| 本地 CI gate pass | ✅ 2345 passed, 0 regressions |
| 浏览器本地验收 pass | ✅ 4 样例跨 6 厂商对，Batch I-I |
| 输出脱敏 P0 已修 | ✅ 统一 redact_sensitive_output() |
| 内网访问 pass | ✅ 0.0.0.0:5008 |
| GitHub Actions runner 实测 | ❌ **唯一/主要 blocking** |
| 人工复核边界明确 | ✅ 本文档第 2 节、第 7 节完整列出 |

### 验收签署

| 核查项 | 状态 | 日期 |
|--------|------|------|
| LLM 配置收敛 | ✅ PASS | 2026-05-25 |
| 6-chain 域覆盖 | ✅ PASS | 2026-05-25 |
| CI 质量门禁 | ✅ PASS | 2026-05-25 |
| 安全脱敏（全路径） | ✅ PASS | 2026-05-25 |
| 审计追溯 | ✅ PASS | 2026-05-25 |
| Fallback 报告 | ✅ PASS | 2026-05-25 |
| UI/UX 验收 | ✅ PASS | 2026-05-25 |
| 输出脱敏 | ✅ PASS | 2026-05-25 |
| 文档完整 | ✅ PASS | 2026-05-25 |

---

## 9. 下一阶段建议

不再以 Phase 编号继续膨胀。建议 Roadmap 如下：

### P0（Beta 收口必要条件）
- [ ] GitHub Actions runner 实测
- [x] ~~清理 13 known tolerated failures~~ ✅ **已清零（Batch J-A）**
- [ ] 建立真实设备/仿真样例回放

### P1（能力增强）
- [ ] OSPF 深语义校验（NSSA/virtual-link/redistribute）
- [ ] BGP route-policy 更细粒度 IR
- [ ] Firewall NAT/IPsec IR

### P2（生产就绪）
- [ ] UI 报告导出 PDF/HTML
- [ ] 批量项目审计
- [ ] 更多真实厂商样例库

---

*本文档与 `docs/beta_acceptance_2026_05_25.json` 保持数字一致。*
