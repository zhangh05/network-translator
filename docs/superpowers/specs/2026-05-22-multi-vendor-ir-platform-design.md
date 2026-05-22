# Multi-Vendor IR-Driven Network Configuration Migration & Audit Platform

**设计文档 v1.0 — 2026-05-22**

---

## 1. 项目初衷

本项目不是"配置翻译器"。它是一个**多设备域、多厂商平台的网络配置迁移与审计系统**。

核心承诺：
- **结构化解析** — 任意厂商配置 → 统一中间语义模型（IR）
- **语义迁移** — IR → 目标厂商配置，尽力保持语义等价
- **覆盖率校验** — 解析/渲染覆盖率可量化、可报告
- **残留检测** — 目标输出不含源厂商或其他厂商语法残留
- **风险/人工复核报告** — 不可等价转换、语义不确定项显式输出
- **批量与审计留痕** — 每次迁移生成可追溯的结构化记录

不是：完美自动翻译器。是：把"不知道能不能翻译"变成"知道哪里不能翻译"。

---

## 2. DeviceDomain — 设备大类（第一层抽象）

### 2.1 DeviceDomain 枚举

```python
class DeviceDomain(Enum):
    SWITCH = "switch"       # 交换机: L2/L3 switching, VLAN/Trunk/STP/LACP/SVI
    ROUTER = "router"       # 路由器: routing, WAN, BGP/OSPF/VRF/PBR/NAT
    FIREWALL = "firewall"   # 防火墙: zone, security policy, object NAT
    # 后续可扩展:
    # WLAN = "wlan"         # AC/AP
    # LB = "load_balancer"  # 负载均衡
    # IPS = "ips"           # 入侵防御
```

DeviceDomain 是"本次配置迁移任务的语义域"，不是设备物理分类。同一硬件不同配置可能映射到不同 domain（如三层交换机配置以 VLAN/SVI 为主 → SWITCH 域；同一设备大量 BGP/VRF → ROUTER 域）。

### 2.2 DomainProfile

```python
@dataclass
class DomainProfile:
    domain: DeviceDomain
    description: str
    required_ir_types: list[IRType]          # 必须覆盖的核心 IR 类型
    optional_ir_types: list[IRType]          # 可选 IR 类型
    feature_keys: list[FeatureKey]           # 该域关注的功能
    critical_validators: list[str]           # 必检类别
    coverage_thresholds: dict[str, float]    # 关键特性覆盖率下限
    notes: list[str] = field(default_factory=list)
```

#### SWITCH DomainProfile

```python
DomainProfile(
    domain=DeviceDomain.SWITCH,
    description="二层/三层交换机配置迁移",
    required_ir_types=[
        IRType.VLAN, IRType.SVI, IRType.INTERFACE,
        IRType.LAG, IRType.STP, IRType.ACL,
        IRType.STATIC_ROUTE, IRType.FHRP, IRType.MANAGEMENT,
    ],
    optional_ir_types=[IRType.OSPF, IRType.BGP, IRType.AAA, IRType.NAT],
    feature_keys=[
        FeatureKey.VLAN, FeatureKey.SVI, FeatureKey.TRUNK,
        FeatureKey.STP, FeatureKey.LACP, FeatureKey.FHRP,
        FeatureKey.ACL, FeatureKey.STATIC_ROUTE, FeatureKey.LLDP,
        FeatureKey.CDP, FeatureKey.DHCP_SNOOPING,
    ],
    critical_validators=["residue", "coverage", "semantic"],
    coverage_thresholds={
        "vlans": 1.0, "svis": 1.0, "interfaces": 1.0,
        "acls": 1.0, "routes": 1.0, "lag_members": 1.0,
    },
    notes=[
        "SVI 的 FHRP (VRRP/HSRP) 是 approximated 转换，非 exact",
        "Packet-filter 必须全部转为 access-group",
        "ACL 顺序必须保留，不允许重新排序",
    ],
)
```

#### ROUTER DomainProfile

```python
DomainProfile(
    domain=DeviceDomain.ROUTER,
    description="路由器/路由协议配置迁移",
    required_ir_types=[
        IRType.INTERFACE, IRType.STATIC_ROUTE, IRType.OSPF,
        IRType.BGP, IRType.ACL, IRType.NAT, IRType.MANAGEMENT,
    ],
    optional_ir_types=[
        IRType.VRF, IRType.PBR, IRType.IPSEC_VPN,
        IRType.VLAN, IRType.AAA, IRType.FHRP,
    ],
    feature_keys=[
        FeatureKey.STATIC_ROUTE, FeatureKey.OSPF, FeatureKey.BGP,
        FeatureKey.VRF, FeatureKey.PBR, FeatureKey.NAT,
        FeatureKey.ACL, FeatureKey.IPSEC_VPN, FeatureKey.INTERFACE,
        FeatureKey.MANAGEMENT, FeatureKey.AAA,
    ],
    critical_validators=["residue", "coverage", "semantic"],
    coverage_thresholds={
        "interfaces": 1.0, "static_routes": 1.0,
        "ospf_networks": 1.0, "bgp_peers": 1.0,
        "acls": 1.0, "nat_rules": 1.0,
    },
    notes=[
        "OSPF area 格式跨厂商可能差异（decimal vs dotted）",
        "NAT 语义差异大，建议 always review",
        "VRF 跨厂商转换需要 routing table isolation 等价性确认",
    ],
)
```

#### FIREWALL DomainProfile

```python
DomainProfile(
    domain=DeviceDomain.FIREWALL,
    description="防火墙/安全网关策略迁移",
    required_ir_types=[
        IRType.INTERFACE, IRType.ZONE, IRType.ADDRESS_OBJECT,
        IRType.SERVICE_OBJECT, IRType.SECURITY_POLICY,
        IRType.NAT_RULE, IRType.STATIC_ROUTE, IRType.MANAGEMENT,
    ],
    optional_ir_types=[
        IRType.VLAN, IRType.SVI, IRType.OSPF, IRType.BGP,
        IRType.IPSEC_VPN, IRType.AAA, IRType.FHRP,
    ],
    feature_keys=[
        FeatureKey.ZONE, FeatureKey.ADDRESS_OBJECT,
        FeatureKey.SERVICE_OBJECT, FeatureKey.SECURITY_POLICY,
        FeatureKey.NAT_POLICY, FeatureKey.IPSEC_VPN,
        FeatureKey.HA, FeatureKey.USER_AUTH, FeatureKey.LOGGING,
        FeatureKey.MANAGEMENT_ACCESS, FeatureKey.INTERFACE,
    ],
    critical_validators=["residue", "coverage", "semantic", "zone_integrity"],
    coverage_thresholds={
        "security_policies": 1.0, "address_objects": 1.0,
        "service_objects": 1.0, "zones": 1.0,
        "nat_rules": 1.0, "interfaces": 1.0,
    },
    notes=[
        "SecurityPolicy ≠ ACL: 域间策略与包过滤语义不同",
        "AddressObject/ServiceObject 跨厂商映射需人工确认",
        "Zone 架构差异大，部分厂商无 zone 概念",
        "NAT: Router NAT（interface/pool）≠ Firewall NAT（zone/object）",
    ],
)
```

### 2.3 DomainDetector

```python
@dataclass
class DomainDetectionResult:
    primary_domain: DeviceDomain
    confidence: float
    evidence: dict[str, float]           # domain -> score
    detected_features: list[FeatureKey]
    secondary_features: list[FeatureKey] # primary 之外检测到的 feature

class DomainDetector:
    def detect(self, config_text: str, vendor_hint: str | None = None) -> DomainDetectionResult:
        """
        基于签名检测配置的语义域。

        检测策略:
        - SWITCH 信号: switchport, vlan batch, port trunk, port access,
                        vlan database, spanning-tree, interface Vlan-interface
        - ROUTER 信号: router ospf, router bgp, ip route, vrf definition,
                       route-map, ip prefix-list, neighbor
        - FIREWALL 信号: security-zone, zone-pair security, policy interzone,
                         address-group, service-group, security-policy, nat server

        每类信号计分，得分最高且超过阈值者为主 domain。
        同时检测到的其他信号进入 secondary_features。
        """
        ...
```

DomainDetector 结果存入 `IRConfigMeta.detected_domains`。用户可通过 `IRConfigMeta.manual_domain_override` 覆盖。

---

## 3. VendorPlatform — 厂商平台（第二层抽象）

### 3.1 支持平台

| 平台 Key | 厂商 | 平台 | 设备域 | device_family |
|----------|------|------|--------|---------------|
| `cisco_ios_xe` | cisco | ios-xe | SWITCH, ROUTER | unified |
| `h3c_comware` | h3c | comware | SWITCH, ROUTER | unified |
| `huawei_vrp` | huawei | vrp | SWITCH, ROUTER | unified |
| `huawei_usg` | huawei | usg | FIREWALL | firewall |
| `ruijie_rgos` | ruijie | rgos | SWITCH, ROUTER | unified |
| `hillstone_stoneos` | hillstone | stoneos | FIREWALL | firewall |
| `topsec_tos` | topsec | tos | FIREWALL | firewall |
| `dptech_fw` | dptech | dp-firewall | FIREWALL | firewall |

说明：
- `huawei_vrp` 覆盖华为交换/路由器（VRP 系统），`huawei_usg` 覆盖华为防火墙（USG 系统）。同一厂商不同系统分别建模。
- DPtech 明确为防火墙平台 `dptech_fw`。后续如需支持 DPtech 交换机则另起 `dptech_switch`。

### 3.2 VendorPlatformProfile

```python
@dataclass
class VendorPlatformProfile:
    key: str                                              # "cisco_ios_xe"
    vendor: str                                           # "cisco"
    platform: str                                         # "ios-xe"
    display_name: str                                     # "Cisco IOS-XE"
    device_family: str                                    # "unified" / "switch" / "router" / "firewall"

    supported_domains: list[DeviceDomain]
    default_domain: DeviceDomain | None

    interface_naming: InterfaceNaming
    signatures: list[VendorSignature]
    forbidden_patterns: list[ForbiddenPattern]
    comment_char: str                                     # "!" / "#" / ";"

    capabilities: dict[DeviceDomain, dict[FeatureKey, FeatureSupport]]
    limitations: list[VendorLimitation]
```

### 3.3 Capability Matrix 示例

```python
# Cisco IOS-XE for SWITCH domain
capabilities[DeviceDomain.SWITCH] = {
    FeatureKey.VLAN:               FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.SVI:                FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.TRUNK:              FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.STP:                FeatureSupport(FeatureSupportStatus.FULL, modes=["mstp", "rstp", "pvst", "rapid-pvst"]),
    FeatureKey.LACP:               FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.FHRP:               FeatureSupport(FeatureSupportStatus.FULL, modes=["vrrp", "hsrp", "glbp"]),
    FeatureKey.ACL:                FeatureSupport(FeatureSupportStatus.FULL, sub_types=["standard", "extended"]),
    FeatureKey.STATIC_ROUTE:       FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.OSPF:               FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.BGP:                FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.NAT:                FeatureSupport(FeatureSupportStatus.PARTIAL, notes="Router-style NAT only"),
}

# Hillstone StoneOS for FIREWALL domain
capabilities[DeviceDomain.FIREWALL] = {
    FeatureKey.ZONE:               FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.ADDRESS_OBJECT:     FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.SERVICE_OBJECT:     FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.SECURITY_POLICY:    FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.NAT_POLICY:         FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.IPSEC_VPN:          FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.HA:                 FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.INTERFACE:          FeatureSupport(FeatureSupportStatus.FULL),
    FeatureKey.VLAN:               FeatureSupport(FeatureSupportStatus.UNSUPPORTED, notes="Hillstone 不处理 L2 VLAN"),
    FeatureKey.SVI:                FeatureSupport(FeatureSupportStatus.UNSUPPORTED),
}
```

### 3.4 ForbiddenPattern & VendorSignature

```python
class ForbiddenPatternCategory(Enum):
    RESIDUAL_SYNTAX = "residual_syntax"         # 目标平台残留源语法
    DANGEROUS_COMMAND = "dangerous_command"     # 输出包含危险命令
    UNSUPPORTED_FEATURE = "unsupported_feature"  # 输出包含不支持特性
    STYLE_WARNING = "style_warning"             # 风格不推荐

@dataclass
class ForbiddenPattern:
    pattern: str                   # 正则
    severity: IRRiskLevel
    category: ForbiddenPatternCategory
    message: str
    target_context: str | None = None    # config / interface / acl / routing / management
    suggested_action: str | None = None

@dataclass
class VendorSignature:
    pattern: str
    weight: int = 5                        # 权重，检测厂商时优先高权重
    domain: DeviceDomain | None = None     # 可选：仅在特定 domain 生效
    context: str | None = None             # 正则的前后文限制
```

### 3.5 InterfaceNaming

```python
@dataclass
class InterfaceNaming:
    pattern: str                              # 接口名总匹配正则
    svi_prefix: str                           # Vlan / Vlan-interface / Vlanif
    loopback_prefix: str                      # Loopback
    port_channel_prefix: str                  # Port-channel / Bridge-Aggregation / Eth-Trunk
    tunnel_prefix: str                        # Tunnel
    management_prefix: str                    # M-GE / M-Eth / MEth
    subinterface_separator: str               # . 或 /
    physical_patterns: list[str]              # 物理口名模式列表

    def normalize(self, name: str) -> str:
        """厂商接口名 -> canonical IR 名

        H3C Vlan-interface100     -> Vlan100
        Huawei Vlanif100          -> Vlan100
        Cisco Vlan100             -> Vlan100
        H3C Bridge-Aggregation1   -> PortChannel1
        """
        ...

    def render(self, canonical: str, target_profile: "VendorPlatformProfile") -> str:
        """canonical IR 名 -> 目标厂商接口名"""
        ...
```

---

## 4. IR 分层数据模型

### 4.1 核心建模

```python
@dataclass(frozen=True)
class SourceSpan:
    start_line: int                # 原始文件行号（1-indexed）
    end_line: int
    source_text: list[str] = field(default_factory=list)  # 可选，仅报告使用

class IRType(Enum):
    VLAN = "vlan"; SVI = "svi"; INTERFACE = "interface"; LAG = "lag"
    STATIC_ROUTE = "static_route"; OSPF = "ospf"; BGP = "bgp"
    ACL = "acl"; NAT = "nat"; FHRP = "fhrp"; STP = "stp"
    AAA = "aaa"; MANAGEMENT = "management"
    ZONE = "zone"; ADDRESS_OBJECT = "address_object"
    SERVICE_OBJECT = "service_object"; SECURITY_POLICY = "security_policy"
    NAT_RULE = "nat_rule"; VRF = "vrf"; PBR = "pbr"
    IPSEC_VPN = "ipsec_vpn"
    UNSUPPORTED = "unsupported"; UNKNOWN = "unknown"

class IRFhrpProtocol(Enum):
    VRRP = "vrrp"; HSRP = "hsrp"; UNKNOWN = "unknown"

class IRInterfaceType(Enum):
    PHYSICAL = "physical"; SVI = "svi"; LOOPBACK = "loopback"
    PORT_CHANNEL = "port_channel"; MANAGEMENT = "management"
    TUNNEL = "tunnel"; SUBINTERFACE = "subinterface"; NULL = "null"

class IRRiskLevel(Enum):
    LOW = "low"; MEDIUM = "medium"; HIGH = "high"; CRITICAL = "critical"

class ConversionStatus(Enum):
    EXACT = "exact"                 # 完全等价
    APPROXIMATED = "approximated"   # 近似等价（如 VRRP→HSRP）
    UNSUPPORTED = "unsupported"     # 目标不支持
    NEEDS_REVIEW = "needs_review"   # 语义不确定，需复核

class FeatureKey(Enum):
    VLAN = "vlan"; SVI = "svi"; TRUNK = "trunk"
    STP = "stp"; LACP = "lacp"; FHRP = "fhrp"
    LLDP = "lldp"; CDP = "cdp"; DHCP_SNOOPING = "dhcp_snooping"
    STATIC_ROUTE = "static_route"; OSPF = "ospf"; BGP = "bgp"
    VRF = "vrf"; PBR = "pbr"; ACL = "acl"
    NAT = "nat"; NAT_POLICY = "nat_policy"
    INTERFACE = "interface"; MANAGEMENT = "management"
    AAA = "aaa"; IPSEC_VPN = "ipsec_vpn"
    ZONE = "zone"; ADDRESS_OBJECT = "address_object"
    SERVICE_OBJECT = "service_object"; SECURITY_POLICY = "security_policy"
    HA = "ha"; USER_AUTH = "user_auth"
    LOGGING = "logging"; MANAGEMENT_ACCESS = "management_access"

class FeatureSupportStatus(Enum):
    FULL = "full"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"

@dataclass
class FeatureSupport:
    status: FeatureSupportStatus
    notes: str | None = None
    modes: list[str] = field(default_factory=list)
    sub_types: list[str] = field(default_factory=list)
```

### 4.2 IRModel 基类

```python
@dataclass
class IRModelBase:
    type: IRType
    source_span: SourceSpan
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
```

### 4.3 Common IR（跨 domain 共享）

```python
@dataclass
class IRInterface(IRModelBase):
    iftype: IRInterfaceType
    name: str                           # canonical name
    description: str | None = None
    ip: str | None = None
    mask: str | None = None
    untagged_vlan: int | None = None
    trunk_allowed: list[int] | None = None  # None=not trunk, []=no vlan, [1,..]=expanded
    trunk_allowed_all: bool = False
    lag_group: int | None = None
    speed: str | None = None
    duplex: str | None = None
    shutdown: bool = False
    # 映射依赖: lag_group 引用 IRLag，SVI 引用 IRVlan

@dataclass
class IRStaticRoute(IRModelBase):
    prefix: str
    mask: str
    nexthop: str
    metric: int | None = None
    vrf: str | None = None
    tag: int | None = None
    description: str | None = None
    distance: int | None = None

@dataclass
class IRAclEntry:
    sequence: int | None = None
    action: str                            # permit / deny
    protocol: str | None = None            # ip / tcp / udp / icmp / esp / ah / ...
    src: str | None = None
    src_wildcard: str | None = None
    src_port: str | None = None
    dst: str | None = None
    dst_wildcard: str | None = None
    dst_port: str | None = None
    remark: str | None = None
    established: bool = False
    logging: bool = False

@dataclass
class IRAcl(IRModelBase):
    acl_type: str                         # standard / extended
    number: int | None = None
    name: str | None = None
    entries: list[IRAclEntry] = field(default_factory=list)
    applied_to: list[dict] = field(default_factory=list)  # [{interface, direction}]

@dataclass
class IRAaa(IRModelBase):
    auth_method: str | None = None
    accounting: str | None = None
    servers: list[dict] = field(default_factory=list)     # → 后续拆 IRAaaServer

@dataclass
class IRManagement(IRModelBase):
    snmp: list[dict] = field(default_factory=list)        # → 后续拆 IRSnmpCommunity
    ntp: list[dict] = field(default_factory=list)         # → 后续拆 IRNtpServer
    syslog: list[dict] = field(default_factory=list)      # → 后续拆 IRSyslogServer
    ssh: dict | None = None
    dns: dict | None = None
    # TODO: 上述 list[dict] 下一步拆为强类型子 dataclass
```

### 4.4 Switch IR

```python
@dataclass
class IRVlan(IRModelBase):
    vid: int
    name: str | None = None

@dataclass
class IRFhrp(IRModelBase):
    protocol: IRFhrpProtocol
    group_id: int
    virtual_ip: str
    priority: int = 100
    preempt: bool = False
    track: list[dict] = field(default_factory=list)  # [{interface, decrement}]
    authentication: str | None = None

@dataclass
class IRSvi(IRModelBase):
    vid: int
    ip: str | None = None
    mask: str | None = None
    fhrp: list[IRFhrp] = field(default_factory=list)
    acl_in: str | None = None
    acl_out: str | None = None
    description: str | None = None
    shutdown: bool = False

@dataclass
class IRLag(IRModelBase):
    lag_id: int
    member_ports: list[str] = field(default_factory=list)    # canonical interface names
    mode: str = "static"                                      # static / lacp
    lacp_mode: str = "active"                                 # active / passive

@dataclass
class IRStp(IRModelBase):
    mode: str | None = None                    # mstp / rstp / stp / pvst / rapid-pvst
    region: str | None = None
    revision: int | None = None
    instances: list[dict] = field(default_factory=list)  # [{id, vlans, priority, bridges}]
    priority: dict = field(default_factory=dict)
```

### 4.5 Router IR

```python
@dataclass
class IROspf(IRModelBase):
    process_id: int
    router_id: str | None = None
    networks: list[dict] = field(default_factory=list)        # → 后续拆 IROspfNetwork
    areas: list[dict] = field(default_factory=list)           # [{area_id, type}]
    redistributes: list[dict] = field(default_factory=list)   # → 后续拆 IROspfRedistribute
    passive_interfaces: list[str] = field(default_factory=list)
    reference_bandwidth: int | None = None
    # TODO: networks/redistributes 下一步拆为强类型子 dataclass

@dataclass
class IRBgp(IRModelBase):
    asn: int
    router_id: str | None = None
    peers: list[dict] = field(default_factory=list)           # → 后续拆 IRBgpPeer
    networks: list[str] = field(default_factory=list)
    redistribute: list[str] = field(default_factory=list)

@dataclass
class IRVrf(IRModelBase):
    name: str
    rd: str | None = None
    import_rt: list[str] = field(default_factory=list)
    export_rt: list[str] = field(default_factory=list)

@dataclass
class IRPbr(IRModelBase):
    name: str
    rules: list[dict] = field(default_factory=list)

@dataclass
class IRNat(IRModelBase):
    """Router-style NAT (interface/pool-based)"""
    rules: list[dict] = field(default_factory=list)           # → 后续拆 IRNatRule（路由型）

@dataclass
class IRIpsecVpn(IRModelBase):
    connections: list[dict] = field(default_factory=list)
```

### 4.6 Firewall IR

```python
@dataclass
class IRZone(IRModelBase):
    name: str
    members: list[str] = field(default_factory=list)  # interface canonical names

@dataclass
class IRAddressObject(IRModelBase):
    name: str
    ip: str | None = None
    network: str | None = None
    range: str | None = None
    fqdn: str | None = None

@dataclass
class IRServiceObject(IRModelBase):
    name: str
    protocol: str | None = None
    port: str | None = None
    port_range: str | None = None

@dataclass
class IRSecurityPolicy(IRModelBase):
    name: str | None = None
    from_zone: str | None = None
    to_zone: str | None = None
    src_addresses: list[str] = field(default_factory=list)      # address object names
    dst_addresses: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)           # service object names
    action: str = "permit"
    logging: bool = False
    session_stateful: bool = True
    description: str | None = None

@dataclass
class IRNatRule(IRModelBase):
    """Firewall-style NAT (zone/object-based)"""
    name: str | None = None
    original_ip: str | None = None
    translated_ip: str | None = None
    pool: str | None = None
    interface: str | None = None
    from_zone: str | None = None
    to_zone: str | None = None
    src_address: str | None = None     # address object name
    dst_address: str | None = None
    service: str | None = None
    nat_type: str = "source"           # source / destination / static
```

### 4.7 IRConfigMeta 与 IRConfig

```python
@dataclass
class IRConfigMeta:
    source_vendor: str
    target_vendor: str
    source_domain: DeviceDomain
    target_domain: DeviceDomain
    source_platform: str
    target_platform: str
    hostname: str | None = None
    detected_domains: list[DeviceDomain] = field(default_factory=list)
    domain_confidence: float = 0.0
    domain_evidence: dict[str, float] = field(default_factory=dict)
    manual_domain_override: DeviceDomain | None = None
    platform: str | None = None
    version: str | None = None
    parser_version: str | None = None
    created_at: str = ""
    warnings: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)

@dataclass
class IRConfig:
    meta: IRConfigMeta

    # Common
    interfaces: list[IRInterface] = field(default_factory=list)
    static_routes: list[IRStaticRoute] = field(default_factory=list)
    acls: list[IRAcl] = field(default_factory=list)
    nat: list[IRNat] = field(default_factory=list)
    aaa: IRAaa | None = None
    management: IRManagement | None = None

    # Switch
    vlans: list[IRVlan] = field(default_factory=list)
    svis: list[IRSvi] = field(default_factory=list)
    lags: list[IRLag] = field(default_factory=list)
    stp: IRStp | None = None

    # Router
    ospf: list[IROspf] = field(default_factory=list)
    bgp: list[IRBgp] = field(default_factory=list)
    vrfs: list[IRVrf] = field(default_factory=list)
    pbrs: list[IRPbr] = field(default_factory=list)
    ipsec_vpns: list[IRIpsecVpn] = field(default_factory=list)

    # Firewall
    zones: list[IRZone] = field(default_factory=list)
    address_objects: list[IRAddressObject] = field(default_factory=list)
    service_objects: list[IRServiceObject] = field(default_factory=list)
    security_policies: list[IRSecurityPolicy] = field(default_factory=list)
    nat_rules: list[IRNatRule] = field(default_factory=list)

    # Non-translatable / unknown
    unsupported: list[IRUnsupported] = field(default_factory=list)
    unknown_blocks: list[IRUnknownBlock] = field(default_factory=list)

    # 原始顺序保留（供校验、报告用，Renderer 不依赖 blocks）
    blocks: list[IRModelBase] = field(default_factory=list)
```

---

## 5. Parser 解析器体系

### 5.1 ParserContext

```python
@dataclass
class RawLine:
    line_no: int
    raw: str
    normalized: str

@dataclass
class ParserContext:
    lines: list[RawLine]                      # 所有原始行，保留行号
    profile: VendorPlatformProfile | None = None
    consumed: set[int] = field(default_factory=set)
    errors: list[ParseError] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

@dataclass
class ParseSectionResult[T]:
    items: list[T]
    consumed: set[int]
    warnings: list[str] = field(default_factory=list)
    errors: list[ParseError] = field(default_factory=list)

@dataclass
class ParseResult:
    ir: IRConfig
    parsed_line_count: int
    total_line_count: int
    unknown_line_count: int = 0
    coverage_ratio: float = 0.0
    feature_counts: dict[str, int] = field(default_factory=dict)
    errors: list[ParseError] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
```

### 5.2 BaseParser

```python
class BaseParser(ABC):
    vendor = ""                     # class attribute, "h3c_comware"
    domain = None                   # class attribute, DeviceDomain.SWITCH

    def parse(self, config_text: str, **kwargs) -> ParseResult:
        """preprocess → create_ctx → parse_* → build_ir"""
        ...

    def preprocess(self, text: str) -> str:
        """清理注释/空行/大小写, 保留行号映射"""
        ...

    def parse_system(self, ctx: ParserContext) -> IRConfigMeta: ...
    def parse_vlans(self, ctx: ParserContext) -> list[IRVlan]: ...
    def parse_interfaces(self, ctx: ParserContext) -> tuple[list[IRInterface], list[IRSvi]]: ...
    def parse_lags(self, ctx: ParserContext) -> list[IRLag]: ...
    def parse_static_routes(self, ctx: ParserContext) -> list[IRStaticRoute]: ...
    def parse_ospf(self, ctx: ParserContext) -> list[IROspf]: ...
    def parse_bgp(self, ctx: ParserContext) -> list[IRBgp]: ...
    def parse_acls(self, ctx: ParserContext) -> list[IRAcl]: ...
    def parse_nat(self, ctx: ParserContext) -> list[IRNat]: ...
    def parse_stp(self, ctx: ParserContext) -> IRStp | None: ...
    def parse_aaa(self, ctx: ParserContext) -> IRAaa | None: ...
    def parse_management(self, ctx: ParserContext) -> IRManagement | None: ...
    def parse_firewall(self, ctx: ParserContext) -> tuple[list, list, list, list, list]: ...
    def parse_vrfs(self, ctx: ParserContext) -> list[IRVrf]: ...
    def parse_pbrs(self, ctx: ParserContext) -> list[IRPbr]: ...
    def parse_ipsec(self, ctx: ParserContext) -> list[IRIpsecVpn]: ...
    def collect_unknown(self, ctx: ParserContext) -> list[IRUnknownBlock]: ...
```

非核心 parse_* 方法默认返回 `[]` 或 `None`，不强制覆盖。

### 5.3 注册

```python
class DomainPlatformKey:
    domain: DeviceDomain
    platform: str

_parsers: dict[DomainPlatformKey, type[BaseParser]] = {}

def register_parser(domain: DeviceDomain, platform: str, parser_cls: type[BaseParser]):
    _parsers[DomainPlatformKey(domain, platform)] = parser_cls

def get_parser(domain: DeviceDomain, platform: str) -> BaseParser | None:
    cls = _parsers.get(DomainPlatformKey(domain, platform))
    return cls() if cls else None
```

Parser 自发现：`discover_parsers()` 扫描 `core/parser/` 目录，导入所有 `parser_*.py`。

### 5.4 共享工具（core/parser/shared.py）

```python
def parse_vlan_range(text: str) -> list[int]:
def render_vlan_range(vlans: list[int]) -> str:
def cidr_to_mask(bits: int) -> str:
def mask_to_cidr(mask: str) -> int:
def wildcard_to_prefix(wildcard: str) -> str:
def normalize_interface_name(name: str, profile: InterfaceNaming) -> str:
def split_config_blocks(lines: list[str], header_pattern: str) -> list[tuple[str, list[str]]]:
```

### 5.5 Parser 文件结构

```
core/parser/
├── __init__.py              # discover_parsers(), register_parser(), get_parser()
├── base.py                  # BaseParser, ParserContext, ParseResult, ParseSectionResult, RawLine
├── shared.py                # 通用网络工具函数
├── parser_h3c_comware.py    # 多 domain (SWITCH, ROUTER), H3C Comware → IR（完整）
├── parser_huawei_vrp.py     # SWITCH/ROUTER domain: Huawei VRP → IR（骨架）
├── parser_cisco_ios.py      # SWITCH/ROUTER domain: Cisco IOS-XE → IR（骨架）
├── parser_ruijie_rgos.py    # SWITCH/ROUTER domain: Ruijie RGOS → IR（骨架）
├── parser_huawei_usg.py     # FIREWALL domain: Huawei USG → IR（骨架）
├── parser_hillstone.py      # FIREWALL domain: Hillstone → IR（骨架）
├── parser_topsec.py         # FIREWALL domain: Topsec → IR（骨架）
└── parser_dptech.py         # FIREWALL domain: DPtech → IR（骨架）
```

骨架 Parser 最小行为：
- 注册成功，get_parser 返回有效实例
- 识别并设置 vendor/platform/domain
- 返回配置为 IRUnknownBlock
- ParseResult.coverage_ratio 可能较低但不崩溃

---

## 6. Renderer 渲染器体系

### 6.1 RenderContext

```python
@dataclass
class RenderContext:
    target_profile: VendorPlatformProfile
    policy: ConversionPolicy
    target_domain: DeviceDomain
    warnings: list[str] = field(default_factory=list)
    errors: list[RenderError] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
```

### 6.2 RenderResult

```python
@dataclass
class RenderResult:
    config_text: str
    ir: IRConfig
    warnings: list[str] = field(default_factory=list)
    errors: list[RenderError] = field(default_factory=list)
    rendered_features: dict[str, int] = field(default_factory=dict)  # {"vlans": 26, "acls": 2, ...}
    skipped_features: list[RenderError] = field(default_factory=list)
    manual_review_items: list[ReviewItem] = field(default_factory=list)

@dataclass
class ReviewItem:
    ir_type: IRType
    span: SourceSpan
    message: str
    risk_level: IRRiskLevel
    recommendation: str | None = None

@dataclass
class RenderError:
    ir_type: IRType
    span: SourceSpan
    message: str
    severity: IRRiskLevel
```

### 6.3 BaseRenderer

```python
class BaseRenderer(ABC):
    vendor = ""                     # "cisco_ios_xe"
    domain = None                   # DeviceDomain.SWITCH

    def render(self, ir: IRConfig, ctx: RenderContext | None = None, **kwargs) -> RenderResult:
        """render_header → render_* → render_unsupported → format"""
        ...

    def render_header(self, ir: IRConfig) -> list[str]:
        """只放注释型元信息, 不干扰可上线配置"""
        ...

    def render_system(self, ir: IRConfig) -> list[str]: ...
    def render_vlans(self, vlans: list[IRVlan], ctx: RenderContext) -> list[str]: ...
    def render_svis(self, svis: list[IRSvi], ctx: RenderContext) -> list[str]: ...
    def render_interfaces(self, interfaces: list[IRInterface], ctx: RenderContext) -> list[str]: ...
    def render_lags(self, lags: list[IRLag], ctx: RenderContext) -> list[str]: ...
    def render_static_routes(self, routes: list[IRStaticRoute]) -> list[str]: ...
    def render_ospf(self, ospf_list: list[IROspf]) -> list[str]: ...
    def render_bgp(self, bgp_list: list[IRBgp]) -> list[str]: ...
    def render_acls(self, acls: list[IRAcl]) -> list[str]: ...
    def render_nat(self, nat_list: list[IRNat]) -> list[str]: ...
    def render_stp(self, stp: IRStp | None) -> list[str]: ...
    def render_aaa(self, aaa: IRAaa | None) -> list[str]: ...
    def render_management(self, mgmt: IRManagement | None) -> list[str]: ...
    def render_firewall(self, zones, addrs, services, policies, nat_rules, ctx) -> list[str]: ...
    def render_vrfs(self, vrfs: list[IRVrf]) -> list[str]: ...
    def render_pbrs(self, pbrs: list[IRPbr]) -> list[str]: ...
    def render_ipsec(self, vpns: list[IRIpsecVpn]) -> list[str]: ...

    def render_unsupported(self, items: list[IRUnsupported], ctx: RenderContext) -> list[str]:
        """注释输出不可等价转换块, 使用 ctx.target_profile.comment_char"""
        ...

    def render_unknown(self, items: list[IRUnknownBlock], ctx: RenderContext) -> list[str]:
        """注释输出未知块, 不允许裸命令出到可执行配置"""
        ...

    def format_output(self, sections: list[list[str]], ctx: RenderContext) -> str:
        """section 排序、去多余空行、文件尾换行"""
        ...
```

### 6.4 渲染顺序策略

Cisco IOS-XE 推荐顺序（各 Renderer 可覆盖）：
```
1. header (注释)
2. system (hostname, global)
3. vlans
4. acls (ACL 先于接口绑定)
5. port-channel (LAG 先于成员接口)
6. physical interfaces
7. svis (含 FHRP)
8. routing (static → ospf → bgp)
9. management/aaa
10. unsupported/unknown comment blocks
11. footer
```

每个 Renderer 可在 `format_output` 中定义自己的顺序。

### 6.5 Renderer 不可为 LLM 内部调用

Renderer 是确定性的。复杂/未知块的 IR 构建可以在 pipeline 层调用 LLM 辅助，但 Renderer 本身不调 LLM。LLM 辅助的结果必须先回到 IR 或 ReviewItem，再由 Renderer 渲染。

### 6.6 关键渲染规则

- FHRP 源 VRRP → 目标 HSRP：必须标记 APPROXIMATED，warnings 记录
- unknown 块只能注释输出，不能裸命令
- unsupported 块输出目标注解符（comment_char）
- ACL 先定义再引用
- LAG 先定义 port-channel 再在成员口绑定 channel-group
- sections 之间统一分隔符

### 6.7 文件结构

```
core/renderer/
├── __init__.py              # discover_renderers(), register_renderer(), get_renderer()
├── base.py                  # BaseRenderer, RenderContext, RenderResult, RenderError, ReviewItem
├── shared.py                # 通用渲染工具
├── renderer_cisco_ios.py    # 完整, registrations for SWITCH & ROUTER domains
├── renderer_h3c_comware.py  # 骨架, registrations for SWITCH & ROUTER domains
├── renderer_huawei_vrp.py   # 骨架, registrations for SWITCH & ROUTER domains
├── renderer_ruijie_rgos.py  # 骨架, registrations for SWITCH & ROUTER domains
├── renderer_huawei_usg.py   # 骨架, registration for FIREWALL domain
├── renderer_hillstone.py    # 骨架, registration for FIREWALL domain
├── renderer_topsec.py       # 骨架, registration for FIREWALL domain
└── renderer_dptech.py       # 骨架, registration for FIREWALL domain
```

---

## 7. Validator 体系

### 7.1 ValidationIssue & ValidationReport

```python
class ValidationCategory(Enum):
    RESIDUE = "residue"               # 残留语法
    COVERAGE = "coverage"             # 覆盖完整性
    CONVERSION = "conversion"         # 转换质量
    SYNTAX = "syntax"                 # 基础语法
    CAPABILITY = "capability"         # 能力差距
    SECURITY = "security"             # 安全合规
    SEMANTIC = "semantic"             # 语义一致性

@dataclass
class ValidationIssue:
    category: ValidationCategory
    severity: IRRiskLevel
    ir_type: IRType | None = None
    source_span: SourceSpan | None = None    # 源配置行号
    target_span: SourceSpan | None = None    # 目标配置行号
    message: str = ""
    recommendation: str | None = None
    code: str | None = None                  # 唯一标识码

@dataclass
class ValidationReport:
    deployable: bool
    manual_review_required: bool
    total_issues: int
    issue_counts_by_severity: dict[str, int]
    issue_counts_by_category: dict[str, int]
    coverage_metrics: dict[str, float | int] = field(default_factory=dict)
    semantic_metrics: dict[str, bool | str] = field(default_factory=dict)
    issues: list[ValidationIssue] = field(default_factory=list)
```

### 7.2 子 Validator

#### ResidueValidator

```python
class ResidueValidator:
    def validate(self, config_text: str, profile: VendorPlatformProfile) -> list[ValidationIssue]:
        """
        只扫描可执行配置行（跳过注释行）。
        可选扫描注释并降级为 INFO。
        target_span 指向目标配置行号。
        """
        ...
```

- 跳过以 `comment_char` 开头的行
- 裸命令 `interface Vlan-interface30` → HIGH residue
- 注释行 `! [原文] interface Vlan-interface30` → 跳过或降级 INFO

#### CoverageValidator

```python
class CoverageValidator:
    def validate(self, ir: IRConfig, result: RenderResult,
                 domain_profile: DomainProfile | None = None) -> list[ValidationIssue]:
        """
        比较 IR 与 RenderResult 的关键对象数量：
        - VLAN count / SVI count / physical interface count
        - LAG count / member count
        - static route count / OSPF network count
        - ACL count / entry count / interface binding count
        - FHRP group count
        - zone count / security policy count / NAT rule count
        """
        ...
```

#### ConversionValidator

```python
class ConversionValidator:
    def validate(self, ir: IRConfig) -> list[ValidationIssue]:
        """DFS 遍历 IR 中所有对象的 conversion_status"""
        ...
```

#### SyntaxValidator (BasicSyntaxValidator)

```python
class BasicSyntaxValidator:
    def validate(self, config_text: str, profile: VendorPlatformProfile) -> list[ValidationIssue]:
        """IP/mask 合法性、VLAN 范围、接口名基本匹配、明显非法命令"""
        ...
```

#### CapabilityGapValidator

```python
class CapabilityGapValidator:
    def validate(self, ir: IRConfig,
                 src_profile: VendorPlatformProfile,
                 tgt_profile: VendorPlatformProfile,
                 tgt_domain: DeviceDomain) -> list[ValidationIssue]:
        """
        target capability 为 PARTIAL → MEDIUM issue
        target capability 为 UNSUPPORTED → HIGH/CRITICAL issue
        """
        ...
```

#### SemanticValidator

```python
class SemanticValidator:
    def validate(self, ir: IRConfig, result: RenderResult, domain: DeviceDomain) -> list[ValidationIssue]:
        """
        语义一致性检查，按 domain 决定重点：
        SWITCH: SVI IP 匹配、VLAN ID 一致、packet-filter 全迁移
        ROUTER: 路由表一致、OSPF/BGP neighbor 数一致
        FIREWALL: Zone 绑定完整、Policy action 一致
        """
        ...
```

### 7.3 CompositeValidator

```python
class CompositeValidator:
    """
    验证流程由 target domain + target platform + conversion policy 共同决定。
    先加载 target domain profile 确定 validator 列表，
    再加载 target platform profile 运行残留检测和能力差距。
    """

    def validate(
        self,
        target_config: str,
        ir: IRConfig,
        render_result: RenderResult,
        src_profile: VendorPlatformProfile | None,
        tgt_profile: VendorPlatformProfile,
        tgt_domain: DeviceDomain,
        policy: ConversionPolicy | None = None,
    ) -> ValidationReport:
        ...
```

### 7.4 文件结构

```
core/validator/
├── __init__.py
├── base.py
├── residue_validator.py
├── coverage_validator.py
├── conversion_validator.py
├── syntax_validator.py
├── capability_gap_validator.py
├── semantic_validator.py
├── report_markdown.py
└── report_json.py
```

---

## 8. ConversionPolicy & Fallback 注册表

### 8.1 ConversionPolicy

```python
@dataclass
class ConversionPolicy:
    source_domain: DeviceDomain
    source_platform: str
    target_domain: DeviceDomain
    target_platform: str

    fhrp_mode: str = "vrrp"              # vrrp / hsrp / passthrough
    ospf_area_format: str = "decimal"    # decimal / dotted
    lacp_mode: str = "active"            # active / passive / on
    acl_format: str = "named"            # named / numbered
    zone_mapping: str = "name"           # name / id / passthrough
    interface_naming: str = "canonical"  # canonical / raw
```

未找到注册策略时，创建默认策略并加入 assumption：
```
"No explicit conversion policy for h3c_comware:SWITCH → cisco_ios_xe:SWITCH, using defaults"
```

### 8.2 Fallback 注册表

```python
@dataclass
class FallbackEntry:
    translator_cls: type[BaseTranslator]
    priority: int = 0                    # 越大越优先

_fallbacks: dict[DomainPlatformKey, dict[DomainPlatformKey, FallbackEntry]] = {}
# ⇑ source                ⇑ target

def register_fallback(
    source_domain: DeviceDomain, source_platform: str,
    target_domain: DeviceDomain, target_platform: str,
    translator_cls: type[BaseTranslator],
):
    ...

def get_fallback(
    source_domain: DeviceDomain, source_platform: str,
    target_domain: DeviceDomain, target_platform: str,
) -> type[BaseTranslator] | None:
    """匹配优先级: exact → source,target 通配 → 全域通配"""
    ...
```

### 8.3 TranslationCandidate

```python
@dataclass
class TranslationCandidate:
    path: str                           # "parser_renderer" / "llm_direct" / "fallback_rule"
    config_text: str
    ir: IRConfig | None
    parse_result: ParseResult | None
    render_result: RenderResult | None
    validation_report: ValidationReport | None
    translation_path: str = ""
    fallback_used: bool = False
    fallback_name: str | None = None
    score: float | None = None
    manual_review_required: bool = False
    structured_coverage_unavailable: bool = False
```

---

## 9. 双路径 Pipeline 集成

### 9.1 调度流程

```
TranslateNode
  │
  ├─ DomainDetector.detect(config_text) → primary_domain, detected_features
  │
  ├─ 有 parser(source_domain, source_platform)?
  │     AND 有 renderer(target_domain, target_platform)?
  │   → YES: Parser → IR → Renderer 路径
  │      TranslationCandidate.path = "parser_renderer"
  │
  ├─ 只有 parser(source_domain, source_platform)?
  │   → Parser → IR → LLM 翻译（IR 作为 LLM 上下文）
  │      TranslationCandidate.path = "llm_with_ir"
  │
  └─ 无 parser?
      → LLM 直译（现有逻辑）
         TranslationCandidate.path = "llm_direct"

ValidateNode（统一入口）
  └─ CompositeValidator.validate() 对所有 candidate
     ├─ ResidueValidator
     ├─ CoverageValidator
     ├─ ConversionValidator
     ├─ CapabilityGapValidator
     ├─ BasicSyntaxValidator
     └─ SemanticValidator

RouteNode
  └─ ValidationReport.deployable?
     ├─ True  → success → SemanticValidatorNode / DiffNode / MemoryNode
     └─ False → fallback 或 manual_review_required

FallbackNode
  ├─ 如果有 fallback(source_domain, source_platform, target_domain, target_platform)
  │   → FallbackEntry.translator_cls().translate()
  │   → 输出也走 Validator
  ├─ 如果 parser_renderer 路径已有结果
  │   → 比较多个候选，选择 deployable 更高/issue 更少的
  └─ 无 fallback → manual_review_required
```

### 9.2 Pipeline 集成原则

- **LLM direct 路径无 IR** → deployable=false, manual_review_required=true
- **llm_with_ir 路径** → IR 有限但可用于 Coverage/SemanticValidator
- **parser_renderer 路径** → 完整验证
- **Validator 是统一出口**，不重复运行
- **Fallback 结果必须标记 provenance**
- **旧 ir.py / cisco_output_validator.py** → 标记 deprecated 但保留兼容层

### 9.3 State 扩展

```python
state.ir: IRConfig | None
state.parse_result: ParseResult | None
state.render_result: RenderResult | None
state.validation_report: ValidationReport | None
state.translation_path: str
state.translation_candidates: list[TranslationCandidate]
state.primary_result: TranslationCandidate | None
state.fallback_result: TranslationCandidate | None
state.manual_review_required: bool
state.deployable: bool
state.structured_coverage_unavailable: bool
```

---

## 10. 验收链路与后续扩展

### 10.1 本轮验收链路

| 验收项 | 要求 |
|--------|------|
| **Domain Profile** | SWITCH / ROUTER / FIREWALL 完整定义，含 required_ir_types、feature_keys、coverage_thresholds、critical_validators |
| **Vendor Platform Profile** | 8 个完整（cisco_ios_xe / h3c_comware / huawei_vrp / huawei_usg / ruijie_rgos / hillstone_stoneos / topsec_tos / dptech_fw），capabilities 按 domain 组织。含 DPtech 防火墙线 `dptech_fw`，含华为 USG 防火墙 `huawei_usg` |
| **DomainDetector** | 可从配置文本自动检测 primary_domain，输出 confidence + evidence |
| **Parser: H3C Comware → IR** | SWITCH 域完整覆盖：system/vlan/svi+fhrp/interface/lag/ospf/static_route/acl/stp/mgmt |
| **Renderer: IR → Cisco IOS-XE** | SWITCH 域完整覆盖：同 Parser 覆盖集，输出纯 Cisco IOS-XE |
| **CompositeValidator** | 6 子 validator 全部实现，按 domain+platform 分派 |
| **残留检测** | ResidueValidator 对 7 平台有效，不误报注释行 |
| **语义验证** | VLAN/SVI/ACL/路由/OSPF 数量一致，packet-filter 全迁移 |
| **全链路测试** | test_config.txt H3C→Cisco 完整转换，零残留 |
| **其他厂商骨架** | 注册成功、返回 IRUnknownBlock、Validator 标记 manual_review、deployable=false |

### 10.2 后续扩展无阻塞

| 方向 | 添加步骤 |
|------|----------|
| Huawei VRP → Cisco IOS-XE (SWITCH) | 完善 parser_huawei_vrp.py parse_* 方法 |
| Cisco IOS-XE → Huawei VRP (SWITCH) | 完善 renderer_huawei_vrp.py render_* 方法 |
| Hillstone → Topsec (FIREWALL) | 完善 parser_hillstone.py + renderer_topsec.py 的 firewall IR 处理 |
| 新增第 8 厂商 | 新增 profile + parser + renderer，注册即可，主流程 0 改动 |
| 新增 WLAN domain | 新增 DeviceDomain.WLAN、DomainProfile、各厂商 WLAN parser/renderer |

### 10.3 风险清单

| 风险 | 级别 | 缓解措施 |
|------|------|----------|
| IR 字段设计不完整，实际 H3C 样例遇到未覆盖字段 | MEDIUM | 迭代补充，测试先行 |
| 强类型 IR 序列化/反序列化边缘用例 | LOW | 加 round-trip 测试 |
| 旧测试依赖已废弃的 ir.py / cisco_output_validator.py | LOW | 保留兼容层，逐步迁移 |
| LLM direct 路径跳过 Validator | MEDIUM | Validator 对 LLM 输出同样强制运行 |
| DPtech 平台差异大，单一 profile 不够 | LOW | 先覆盖通用 firwall 场景，后续可按型号细分 |

---

## 附录 A：旧文件迁移策略

### A.1 原则

1. 旧文件先保留，不一次性删除
2. 新架构以新增目录为主，旧文件通过 adapter 接入新体系
3. 旧文件按三种策略归类
4. 用户样例文件（`/Users/zhangh01/Desktop/test_config.txt` 等）只读，不删除、不覆盖、不移动

### A.2 旧文件迁移分类

| 策略 | 说明 | 文件 |
|------|------|------|
| **兼容保留** | 仍被旧流程调用，暂时保留，标记 deprecated | `ir.py`, `graph/nodes.py` 中现有节点逻辑 |
| **包装为 fallback** | 旧规则翻译器包装进新 fallback registry | `h3c_to_cisco.py` → `H3CToCiscoFallback` |
| | | `rule_translator.py` → `RuleBasedFallback` |
| **逐步迁移后删除** | 等新 Validator/Renderer 测试通过后删除 | `cisco_output_validator.py`, 旧 vendor 硬编码校验函数, 散落规则函数 |

### A.3 旧 → 新 映射表

| 旧文件 | 当前用途 | 新归属 | 当前处理方式 | 删除条件 |
|--------|----------|--------|-------------|----------|
| `ir.py` | 旧 IR/LLM 输出结构 | `core/ir_models/` | deprecated, 保留兼容层 | 新 IR 全覆盖后 + 全量测试通过 |
| `h3c_to_cisco.py` | 旧 H3C→Cisco 规则翻译 | `core/fallback/` | 包装为 fallback wrapper | 新 parser/renderer 稳定后可保留或删除 |
| `cisco_output_validator.py` | Cisco 输出校验 | `core/validator/` | 迁移规则到新 validator | 新 validator 测试覆盖后 + 对比测试通过 |
| `rule_translator.py` | 通用规则兜底 | `core/fallback/` | 包装为 fallback wrapper | fallback 新实现后 |

### A.4 删除条件（所有条件必须满足）

1. 没有任何 import 引用（`rg "module_name|class_name|function_name"` 确认）
2. 新模块完全覆盖其功能
3. 新旧结果对比测试通过（同一输入，新旧输出等价）
4. 全量测试通过
5. test_config.txt 样例链路通过
6. 删除后回归风险可控

### A.5 用户只读文件

以下文件不删除、不覆盖、不移动：
- `/Users/zhangh01/Desktop/test_config.txt`
- `/Users/zhangh01/Desktop/trans.txt`
- `/Users/zhangh01/Desktop/cisco_translated_config.txt`

### A.6 目录结构变更

```
core/
├── domain/                          # NEW: DeviceDomain, DomainProfile, DomainDetector
│   ├── __init__.py
│   ├── base.py
│   └── detector.py
│
├── vendor/                          # NEW: VendorPlatformProfile 注册表
│   ├── __init__.py
│   ├── base.py                      # VendorPlatformProfile, InterfaceNaming, ForbiddenPattern, VendorSignature
│   ├── enums.py                     # FeatureKey, FeatureSupportStatus, ForbiddenPatternCategory
│   ├── profile_cisco_ios.py         # 完整
│   ├── profile_h3c_comware.py       # 完整
│   ├── profile_huawei_vrp.py       # SWITCH, ROUTER
├── profile_huawei_usg.py       # FIREWALL        # 完整
│   ├── profile_ruijie_rgos.py       # 完整
│   ├── profile_hillstone.py         # 完整
│   ├── profile_topsec.py            # 完整
│   └── profile_dptech.py            # 完整
│
├── ir_models/                       # NEW: IR 数据模型
│   ├── __init__.py                  # IRConfig, 全量导出
│   ├── base.py                      # IRModelBase, SourceSpan, ConversionStatus
│   ├── enums.py                     # IRType, IRFhrpProtocol, IRInterfaceType, IRRiskLevel
│   ├── common.py                    # IRInterface, IRStaticRoute, IRAcl, IRAclEntry, IRAaa, IRManagement
│   ├── switch.py                    # IRVlan, IRSvi, IRFhrp, IRLag, IRStp
│   ├── router.py                    # IROspf, IRBgp, IRVrf, IRPbr, IRNat, IRIpsecVpn
│   ├── firewall.py                  # IRZone, IRAddressObject, IRServiceObject, IRSecurityPolicy, IRNatRule
│   ├── unsupported.py               # IRUnsupported, IRUnknownBlock
│   └── ir_config.py                 # IRConfig, IRConfigMeta
│
├── parser/
│   ├── __init__.py                  # discover_parsers(), register_parser(), get_parser()
│   ├── base.py                      # BaseParser, ParserContext, ParseResult, ParseSectionResult, RawLine
│   ├── shared.py                    # parse_vlan_range(), normalize_interface_name(), ...
│   ├── parser_h3c_comware.py        # 多 domain, 注册 DomainPlatformKey(SWITCH,comware) 等
│   ├── parser_huawei_vrp.py         # 骨架, registrations for SWITCH & ROUTER
│   ├── parser_cisco_ios.py          # 骨架, registrations for SWITCH & ROUTER
│   ├── parser_ruijie_rgos.py        # 骨架, registrations for SWITCH & ROUTER
│   ├── parser_huawei_usg.py         # 骨架, registration for FIREWALL domain
│   ├── parser_hillstone.py          # 骨架, registration for FIREWALL domain
│   ├── parser_topsec.py             # 骨架, registration for FIREWALL domain
│   └── parser_dptech.py             # 骨架, registration for FIREWALL domain
│
├── renderer/
│   ├── __init__.py                  # discover_renderers(), register_renderer(), get_renderer()
│   ├── base.py                      # BaseRenderer, RenderContext, RenderResult, RenderError, ReviewItem
│   ├── shared.py                    # 通用渲染工具
│   ├── renderer_cisco_ios.py        # 完整, registrations for SWITCH & ROUTER domain
│   ├── renderer_h3c_comware.py      # 骨架, registrations for SWITCH & ROUTER
│   ├── renderer_huawei_vrp.py       # 骨架, registrations for SWITCH & ROUTER
│   ├── renderer_ruijie_rgos.py      # 骨架, registrations for SWITCH & ROUTER
│   ├── renderer_huawei_usg.py       # 骨架, registration for FIREWALL domain
│   ├── renderer_hillstone.py        # 骨架, registration for FIREWALL domain
│   ├── renderer_topsec.py           # 骨架, registration for FIREWALL domain
│   └── renderer_dptech.py           # 骨架, registration for FIREWALL domain
│
├── validator/
│   ├── __init__.py                  # CompositeValidator
│   ├── base.py                      # ValidationIssue, ValidationReport
│   ├── residue_validator.py         # 对 7 平台有效
│   ├── coverage_validator.py
│   ├── conversion_validator.py
│   ├── syntax_validator.py
│   ├── capability_gap_validator.py
│   ├── semantic_validator.py
│   ├── report_markdown.py
│   └── report_json.py
│
├── fallback/
│   ├── __init__.py                  # register_fallback(), get_fallback()
│   └── base.py                      # BaseTranslator, FallbackEntry
│
├── policy/
│   ├── __init__.py                  # register_policy(), get_conversion_policy()
│   └── base.py                      # ConversionPolicy
│
├── graph/
│   └── nodes.py                     # MODIFIED: TranslateNode, RouteNode, FallbackNode, ValidateNode
│
├── ir.py                            # DEPRECATED (兼容保留)
├── cisco_output_validator.py        # DEPRECATED (迁移 validator 规则后删除)
├── h3c_to_cisco.py                  # RETAINED (包装为 fallback)
└── rule_translator.py               # RETAINED (包装为 fallback)
```

### A.7 core/domain.py 命名冲突处理

当前存在 `core/domain.py`（旧单文件），与计划新增的 `core/domain/` 目录包名冲突。

处理方案：
1. 第一步（实施时）：将旧 `core/domain.py` 重命名为 `core/domain_legacy.py`，文件内加 `import warnings; warnings.warn("use core.domain package instead")`，保留兼容导入
2. 第二步：创建 `core/domain/__init__.py` 作为新包，导出新 `DeviceDomain` / `DomainProfile` / `DomainDetector`
3. 第三步：检查所有 import `core.domain` 的地方，逐一迁移到新包
4. 第四步：所有导入迁移完成后，删除 `core/domain_legacy.py`

过渡期内，旧 `core/domain.py` 不删除、不改内容，仅重命名以避免命名空间冲突。

### A.8 旧 knowledge_data 兼容加载策略

当前知识库：
- `knowledge_data/{cisco,huawei,h3c}/{feature}.md` — vendor-first 组织
- `knowledge_data/capability_map.yaml`
- `knowledge_data/features/registry.yaml`

处理策略：
1. **旧结构保留**：所有 `knowledge_data/{vendor}/` 文件继续可读，`KnowledgeRetriever.get_all_mapping_info()` 维持原逻辑
2. **新结构可选新增**：新增 `knowledge_data/domains/{domain}/{vendor}/{feature}.md` 是可选的 domain-first 组织，不强制迁移
3. **双路径加载**：`KnowledgeNode` 尝试新路径，找不到时 fallback 旧路径。或两者都加载并去重
4. **不删除旧文件**：旧知识文件在旧 KnowledgeNode 中仍有直接引用，删除前需要：
   - 新 KnowledgeNode 已完全上线
   - 全量测试通过
   - 对比测试证明新知识覆盖 >= 旧知识
5. **capability_map.yaml**：后续迁移到 `core/vendor/enums.py` 中的 FeatureSupport 枚举

旧 KnowledgeNode 在新架构中保留兼容运行，不要求立即重构。
新 Parser/Renderer 不依赖 knowledge_data markdown，而是依赖注册的 VendorPlatformProfile.capabilities。
