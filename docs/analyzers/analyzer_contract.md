# Analyzer Contract

## Overview

Each analyzer implements `FeatureAnalyzer` (ABC in `core/analyzers/base.py`) and produces a `FeatureAnalysis` dataclass.

## Interface

```python
class FeatureAnalyzer(ABC):
    @abstractmethod
    def analyze(self, config_text: str, vendor: str, domain: str, platform: str) -> FeatureAnalysis:
        pass

    @property
    @abstractmethod
    def feature_name(self) -> str:
        pass
```

## FeatureAnalysis Output

```python
@dataclass
class FeatureAnalysis:
    feature: str                    # Feature name, e.g. "nat"
    status: str = "skipped"        # "analyzed" | "skipped" | "error"
    risk_level: str = "info"       # "info" | "warning" | "fatal"
    manual_review_required: bool = False
    rules: list = []                # Structured rule entries
    references: dict = {}           # Referenced objects (ACLs, pools, prefix-lists...)
    missing_context: list = []      # Missing context items (strings)
    source_lines: list = []         # Matched source config lines
    notes: list = []                # Human-readable notes
    metadata: dict = {}             # Extra metadata
```

## Consumer: CapabilityGapNode

`CapabilityGapNode` (in `core/graph/nodes.py`) runs `registry.analyze_all()` in `_get_analyzer_results()`,
merges results into structured `capability_gaps` and passes `analyzer_context` to `TranslateNode`.

## Consumer: ValidateNode

`ValidateNode` uses analyzer results in its Layer 3 (Domain) and Layer 4 (Feature) validation:
- `risk_level='fatal'` → `deployable=False`
- `risk_level='warning'` → validation errors added
- `missing_context` items → specific validation errors

## Consumer: TranslateNode Prompt

Analyzer context is injected as a structured `analyzer_context` JSON param in the LLM prompt.
Fields used: `missing_context`, `manual_review_required`, `risk_level`, `rules`.

## Analyzer-Specific Contracts

### BfdAnalyzer (bfd)

- **Priority**: p2
- **Risk**: medium
- **Domains**: routing
- **Reason**: 参数简单但关联 OSPF/BGP/static

**Input Patterns**:
  - `bfd interval (Cisco)`
  - `bfd session bind peer-ip (Huawei)`
  - `bfd multi-hop (H3C)`

**Extracted Fields**:
  - `min_tx`
  - `min_rx`
  - `multiplier`
  - `peer_ip`
  - `local_discriminator`
  - `remote_discriminator`

**Risk Rules**:
  - 被 OSPF/BGP/static 引用但未定义 → fatal
  - 对等体 IP 缺失 → fatal

**Validation Impact**: BFD 关联路由协议验证
**Test Cases Planned**: 2

**Linked Bench Cases**:
  - `h3c-routing-ospf-bfd-to-cisco`

### DhcpAnalyzer (dhcp)

- **Priority**: p1
- **Risk**: low
- **Domains**: routing, switching
- **Reason**: 常见，参数映射简单

**Input Patterns**:
  - `ip dhcp pool / ip dhcp excluded-address (Cisco)`
  - `dhcp server / dhcp server ip-pool (Huawei)`
  - `dhcp server ip-pool (H3C)`

**Extracted Fields**:
  - `pool_name`
  - `network`
  - `gateway`
  - `dns_servers`
  - `lease_time`
  - `excluded_addresses`

**Risk Rules**:
  - network 缺失 → fatal
  - gateway 缺失 → warning

**Validation Impact**: DHCP 服务配置检查
**Test Cases Planned**: 2

**Linked Bench Cases**:
  - `cisco-routing-dhcp-to-h3c`

### IpsecAnalyzer (ipsec)

- **Priority**: p0
- **Risk**: high
- **Domains**: routing, firewall
- **Reason**: 参数依赖强，缺 proposal/ike/peer/acl 导致不可用

**Input Patterns**:
  - `Crypto ike/ipsec config (Cisco)`
  - `IPsec proposal/policy (Huawei)`
  - `IPsec policy/profile (H3C)`
  - `IKEv1/v2 config (all)`

**Extracted Fields**:
  - `ike_version`
  - `encryption_alg`
  - `integrity_alg`
  - `dh_group`
  - `lifetime`
  - `peer_ip`
  - `local_ip`
  - `transform_set`
  - `acl_ref`
  - `interface_binding`

**Risk Rules**:
  - IKE proposal 缺失 → fatal
  - 缺少 peer IP → fatal
  - transform set 不完整 → warning
  - ACL 引用缺失 → warning
  - 接口绑定缺失 → warning

**Validation Impact**: IPsec 隧道配置可用性检查
**Test Cases Planned**: 4

**Linked Bench Cases**:
  - `cisco-firewall-ipsec-to-huawei`

### LacpAnalyzer (lacp)

- **Priority**: p2
- **Risk**: low
- **Domains**: switching
- **Reason**: 结构简单，risk 低

**Input Patterns**:
  - `channel-group (Cisco)`
  - `eth-trunk (Huawei)`
  - `Bridge-Aggregation (H3C)`

**Extracted Fields**:
  - `group_id`
  - `mode`
  - `member_interfaces`
  - `lacp_rate`
  - `max_active`

**Risk Rules**:
  - 成员接口不足 → warning
  - member interface 引用未定义 → warning

**Validation Impact**: LACP/链路聚合配置检查
**Test Cases Planned**: 2

**Linked Bench Cases**:
  - `h3c-switching-lacp-to-cisco`

### ObjectAnalyzer (object)

- **Priority**: p1
- **Risk**: low
- **Domains**: firewall
- **Reason**: 防火墙对象支撑 NAT/security_policy

**Input Patterns**:
  - `object network / object-group network/service (Cisco ASA)`
  - `address-set / service-set (Huawei)`
  - `object network / object service (H3C)`

**Extracted Fields**:
  - `object_name`
  - `object_type`
  - `ip_addresses`
  - `subnets`
  - `tcp_ports`
  - `udp_ports`
  - `protocols`

**Risk Rules**:
  - 被 NAT/security_policy 引用但未定义 → fatal
  - address-set 引用未定义 → fatal
  - 端口不完整 → warning

**Validation Impact**: 防火墙对象引用完整性检查
**Test Cases Planned**: 3

**Linked Bench Cases**:
  - `cisco-firewall-security-policy-to-h3c`
  - `h3c-firewall-nat-server-to-huawei`
  - `h3c-firewall-service-object-to-huawei`
  - `huawei-firewall-security-policy-deny-to-h3c`
  - `huawei-firewall-zone-address-to-cisco`

### QosAnalyzer (qos)

- **Priority**: p0
- **Risk**: medium
- **Domains**: routing, switching
- **Reason**: 厂商差异大，class/behavior/policy/service-policy 关系易丢

**Input Patterns**:
  - `traffic classifier/behavior/policy (Huawei/H3C)`
  - `class-map/policy-map/service-policy (Cisco)`

**Extracted Fields**:
  - `classifier_name`
  - `behavior_name`
  - `policy_name`
  - `match_criteria`
  - `action`
  - `bandwidth_params`
  - `interface_binding`

**Risk Rules**:
  - classifier 引用未定义 → fatal
  - behavior 被 policy 引用但不存在 → fatal
  - policy 未被应用 → warning
  - DSCP/cos 映射不完整 → warning

**Validation Impact**: QoS 策略完整性检查
**Test Cases Planned**: 4

**Linked Bench Cases**:
  - `huawei-routing-qos-to-cisco`
  - `huawei-switching-qos-to-h3c`

### RoutePolicyAnalyzer (route_policy)

- **Priority**: p0
- **Risk**: medium
- **Domains**: routing
- **Reason**: 与 BGP/OSPF import/export 强相关，误翻影响路由传播

**Input Patterns**:
  - `Huawei route-policy / ip-prefix`
  - `H3C route-policy / ip-prefix`
  - `Cisco route-map / prefix-list`

**Extracted Fields**:
  - `policy_name`
  - `node_sequence`
  - `permit_deny`
  - `match_clauses`
  - `apply_set_clauses`
  - `referenced_prefix_list`
  - `route_protocol_references`

**Risk Rules**:
  - 引用 prefix-list 缺失 → warning
  - match/apply 无法映射 → warning/fatal
  - 顺序变化 → warning
  - route-policy 被 BGP/OSPF 引用但未定义 → fatal/manual_review

**Validation Impact**: 影响 BGP/OSPF/static 翻译质量
**Test Cases Planned**: 6

**Linked Bench Cases**:
  - `huawei-routing-bgp-route-policy-to-cisco`

### StpAnalyzer (stp)

- **Priority**: p2
- **Risk**: medium
- **Domains**: switching
- **Reason**: MSTP 多实例关系需要验证

**Input Patterns**:
  - `spanning-tree (Cisco)`
  - `stp region-configuration (Huawei)`
  - `stp region-configuration (H3C)`

**Extracted Fields**:
  - `mode`
  - `region_name`
  - `revision`
  - `instance_vlan_map`
  - `priority_per_instance`

**Risk Rules**:
  - MST region 名称冲突 → warning
  - instance-vlan 映射重复 → warning
  - 配置未生效 (active) → warning

**Validation Impact**: STP 区域配置一致性检查
**Test Cases Planned**: 2

**Linked Bench Cases**:
  - `huawei-switching-stp-to-cisco`

### TunnelAnalyzer (tunnel)

- **Priority**: p2
- **Risk**: medium
- **Domains**: routing
- **Reason**: GRE/IPIP 结构简单，IPsec over tunnel 需单独处理

**Input Patterns**:
  - `interface Tunnel (Cisco)`
  - `interface Tunnel (Huawei)`
  - `interface Tunnel (H3C)`

**Extracted Fields**:
  - `tunnel_id`
  - `mode`
  - `source`
  - `destination`
  - `key`
  - `mtu`
  - `tcp_mss_adjust`

**Risk Rules**:
  - source 缺失 → fatal
  - destination 缺失 → fatal
  - mode 不明确 → warning

**Validation Impact**: 隧道配置完整性检查
**Test Cases Planned**: 2

**Linked Bench Cases**:
  - `cisco-routing-tunnel-to-huawei`

### VrfAnalyzer (vrf)

- **Priority**: p2
- **Risk**: medium
- **Domains**: routing
- **Reason**: 结构稳定，风险中等

**Input Patterns**:
  - `ip vrf (Cisco)`
  - `ip vpn-instance (Huawei)`
  - `ip vpn-instance (H3C)`

**Extracted Fields**:
  - `vrf_name`
  - `rd_value`
  - `rt_export`
  - `rt_import`
  - `interface_binding`

**Risk Rules**:
  - RD 缺失 → warning
  - 被 BGP 引用但未定义 → fatal
  - interface binding 缺失 → warning

**Validation Impact**: VRF 一致性检查
**Test Cases Planned**: 2

**Linked Bench Cases**:
  - `cisco-routing-vrf-static-to-huawei`

### VrrpAnalyzer (vrrp)

- **Priority**: p1
- **Risk**: low
- **Domains**: routing, switching
- **Reason**: 常见但结构相对简单

**Input Patterns**:
  - `vrrp vrid (Huawei)`
  - `vrrp vrid (H3C)`
  - `standby (Cisco)`

**Extracted Fields**:
  - `vrid`
  - `virtual_ip`
  - `priority`
  - `preempt`
  - `track_interface`
  - `authentication`

**Risk Rules**:
  - virtual-ip 缺失 → fatal
  - VRID 冲突 → warning
  - priority 超出范围 → warning

**Validation Impact**: HA 配置完整性检查
**Test Cases Planned**: 2

**Linked Bench Cases**:
  - `huawei-routing-vrrp-to-cisco`

