# Multi-Vendor IR-Driven Platform Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the complete domain-first, multi-vendor IR-driven architecture defined in the design spec. This covers DeviceDomain/VendorPlatformProfile/IR models/Parser/Renderer/Validator/Policy/Fallback/Pipeline integration with full TDD across all phases.

**Architecture:** Domain-first: SWITCH / ROUTER / FIREWALL -> Parser -> IR -> Renderer deterministic translation path, with CompositeValidator at the exit. LLM path retained as fallback when parser/renderer are unavailable.

**Tech Stack:** Python 3.12, dataclasses, enum, abc, re, pytest, existing test infrastructure.

**Design Source:** `docs/superpowers/specs/2026-05-22-multi-vendor-ir-platform-design.md`

---

## File Structure to Create

```
core/
|- domain/                          # NEW
|   |- __init__.py
|   |- base.py                      # DeviceDomain, DomainProfile
|   |- detector.py                  # DomainDetector, DomainDetectionResult
|- vendor/                          # NEW
|   |- __init__.py                  # registry
|   |- base.py                      # VendorPlatformProfile, InterfaceNaming, etc.
|   |- enums.py                     # FeatureKey, FeatureSupportStatus, etc.
|   |- profile_cisco_ios_xe.py ...
|- ir_models/                       # NEW
|   |- __init__.py
|   |- enums/base/common/switch/router/firewall/unsupported/ir_config.py
|- parser/                          # NEW
|   |- __init__.py, base.py, shared.py
|   |- parser_h3c_comware.py (FULL)
|   |- parser_huawei_vrp.py ... (SKELETONS)
|- renderer/                        # NEW
|   |- __init__.py, base.py, shared.py
|   |- renderer_cisco_ios.py (FULL)
|   |- renderer_h3c_comware.py ... (SKELETONS)
|- validator/                       # NEW
|   |- __init__.py, base.py
|   |- residue/coverage/conversion/syntax/capability_gap/semantic validator
|- fallback/                        # NEW
|   |- __init__.py, base.py
|- policy/                          # NEW
|   |- __init__.py, base.py
- graph/nodes.py (MODIFIED)
```

## Phase 0: Enums & Base Types

### Task 0.1: IR Enums

- [ ] **Step 1: Write the failing test**

```python
# tests/test_ir_enums.py
import pytest
from core.ir_models import (
    IRType, IRFhrpProtocol, IRInterfaceType,
    IRRiskLevel, ConversionStatus,
)

class TestIRType:
    def test_has_vlan(self): assert IRType.VLAN.value == 'vlan'
    def test_has_svi(self): assert IRType.SVI.value == 'svi'
    def test_has_interface(self): assert IRType.INTERFACE.value == 'interface'
    def test_has_lag(self): assert IRType.LAG.value == 'lag'
    def test_has_static_route(self): assert IRType.STATIC_ROUTE.value == 'static_route'
    def test_has_ospf(self): assert IRType.OSPF.value == 'ospf'
    def test_has_bgp(self): assert IRType.BGP.value == 'bgp'
    def test_has_acl(self): assert IRType.ACL.value == 'acl'
    def test_has_nat(self): assert IRType.NAT.value == 'nat'
    def test_has_fhrp(self): assert IRType.FHRP.value == 'fhrp'
    def test_has_stp(self): assert IRType.STP.value == 'stp'
    def test_has_aaa(self): assert IRType.AAA.value == 'aaa'
    def test_has_management(self): assert IRType.MANAGEMENT.value == 'management'
    def test_has_zone(self): assert IRType.ZONE.value == 'zone'
    def test_has_address_object(self): assert IRType.ADDRESS_OBJECT.value == 'address_object'
    def test_has_service_object(self): assert IRType.SERVICE_OBJECT.value == 'service_object'
    def test_has_security_policy(self): assert IRType.SECURITY_POLICY.value == 'security_policy'
    def test_has_nat_rule(self): assert IRType.NAT_RULE.value == 'nat_rule'
    def test_has_vrf(self): assert IRType.VRF.value == 'vrf'
    def test_has_pbr(self): assert IRType.PBR.value == 'pbr'
    def test_has_ipsec_vpn(self): assert IRType.IPSEC_VPN.value == 'ipsec_vpn'
    def test_has_unsupported(self): assert IRType.UNSUPPORTED.value == 'unsupported'
    def test_has_unknown(self): assert IRType.UNKNOWN.value == 'unknown'
    def test_total_members(self): assert len(IRType) == 23

class TestIRFhrpProtocol:
    def test_vrrp(self): assert IRFhrpProtocol.VRRP.value == 'vrrp'
    def test_hsrp(self): assert IRFhrpProtocol.HSRP.value == 'hsrp'
    def test_unknown(self): assert IRFhrpProtocol.UNKNOWN.value == 'unknown'

class TestIRInterfaceType:
    def test_physical(self): assert IRInterfaceType.PHYSICAL.value == 'physical'
    def test_svi(self): assert IRInterfaceType.SVI.value == 'svi'
    def test_loopback(self): assert IRInterfaceType.LOOPBACK.value == 'loopback'
    def test_port_channel(self): assert IRInterfaceType.PORT_CHANNEL.value == 'port_channel'
    def test_management(self): assert IRInterfaceType.MANAGEMENT.value == 'management'
    def test_tunnel(self): assert IRInterfaceType.TUNNEL.value == 'tunnel'
    def test_subinterface(self): assert IRInterfaceType.SUBINTERFACE.value == 'subinterface'
    def test_null(self): assert IRInterfaceType.NULL.value == 'null'

class TestIRRiskLevel:
    def test_low(self): assert IRRiskLevel.LOW.value == 'low'
    def test_medium(self): assert IRRiskLevel.MEDIUM.value == 'medium'
    def test_high(self): assert IRRiskLevel.HIGH.value == 'high'
    def test_critical(self): assert IRRiskLevel.CRITICAL.value == 'critical'

class TestConversionStatus:
    def test_exact(self): assert ConversionStatus.EXACT.value == 'exact'
    def test_approximated(self): assert ConversionStatus.APPROXIMATED.value == 'approximated'
    def test_unsupported(self): assert ConversionStatus.UNSUPPORTED.value == 'unsupported'
    def test_needs_review(self): assert ConversionStatus.NEEDS_REVIEW.value == 'needs_review'
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=. venv/bin/python3 -m pytest tests/test_ir_enums.py -v`

Expected: FAIL with `ModuleNotFoundError: No module named 'core.ir_models'`

- [ ] **Step 3: Write the implementation**

```python
# core/ir_models/__init__.py
from core.ir_models.enums import (
    IRType, IRFhrpProtocol, IRInterfaceType,
    IRRiskLevel, ConversionStatus,
)
from core.ir_models.base import IRModelBase, SourceSpan
from core.ir_models.common import (
    IRInterface, IRStaticRoute, IRAcl, IRAclEntry, IRAaa, IRManagement,
)
from core.ir_models.switch import IRVlan, IRSvi, IRFhrp, IRLag, IRStp
from core.ir_models.router import (
    IROspf, IRBgp, IRVrf, IRPbr, IRNat, IRIpsecVpn,
)
from core.ir_models.firewall import (
    IRZone, IRAddressObject, IRServiceObject,
    IRSecurityPolicy, IRNatRule,
)
from core.ir_models.unsupported import IRUnsupported, IRUnknownBlock
from core.ir_models.ir_config import IRConfig, IRConfigMeta

__all__ = [
    'IRType', 'IRFhrpProtocol', 'IRInterfaceType', 'IRRiskLevel', 'ConversionStatus',
    'SourceSpan', 'IRModelBase',
    'IRInterface', 'IRStaticRoute', 'IRAcl', 'IRAclEntry', 'IRAaa', 'IRManagement',
    'IRVlan', 'IRSvi', 'IRFhrp', 'IRLag', 'IRStp',
    'IROspf', 'IRBgp', 'IRVrf', 'IRPbr', 'IRNat', 'IRIpsecVpn',
    'IRZone', 'IRAddressObject', 'IRServiceObject', 'IRSecurityPolicy', 'IRNatRule',
    'IRUnsupported', 'IRUnknownBlock',
    'IRConfig', 'IRConfigMeta',
]
```

```python
# core/ir_models/enums.py
from __future__ import annotations
from enum import Enum

class IRType(Enum):
    VLAN='vlan'; SVI='svi'; INTERFACE='interface'; LAG='lag'
    STATIC_ROUTE='static_route'; OSPF='ospf'; BGP='bgp'
    ACL='acl'; NAT='nat'; FHRP='fhrp'; STP='stp'
    AAA='aaa'; MANAGEMENT='management'
    ZONE='zone'; ADDRESS_OBJECT='address_object'
    SERVICE_OBJECT='service_object'; SECURITY_POLICY='security_policy'
    NAT_RULE='nat_rule'; VRF='vrf'; PBR='pbr'
    IPSEC_VPN='ipsec_vpn'
    UNSUPPORTED='unsupported'; UNKNOWN='unknown'

class IRFhrpProtocol(Enum):
    VRRP='vrrp'; HSRP='hsrp'; UNKNOWN='unknown'

class IRInterfaceType(Enum):
    PHYSICAL='physical'; SVI='svi'; LOOPBACK='loopback'
    PORT_CHANNEL='port_channel'; MANAGEMENT='management'
    TUNNEL='tunnel'; SUBINTERFACE='subinterface'; NULL='null'

class IRRiskLevel(Enum):
    LOW='low'; MEDIUM='medium'; HIGH='high'; CRITICAL='critical'

class ConversionStatus(Enum):
    EXACT='exact'; APPROXIMATED='approximated'
    UNSUPPORTED='unsupported'; NEEDS_REVIEW='needs_review'
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=. venv/bin/python3 -m pytest tests/test_ir_enums.py -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add core/ir_models/__init__.py core/ir_models/enums.py tests/test_ir_enums.py
git commit -m "feat(ir_models): add IR enums"
```

### Task 0.2: IR Base Dataclasses (SourceSpan, IRModelBase)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_ir_base.py
import pytest
from core.ir_models import IRModelBase, SourceSpan, IRType, ConversionStatus, IRRiskLevel

class TestSourceSpan:
    def test_minimal(self):
        span = SourceSpan(start_line=1, end_line=5)
        assert span.start_line == 1
        assert span.end_line == 5
        assert span.source_text == []
    def test_with_source_text(self):
        span = SourceSpan(start_line=1, end_line=1, source_text=['vlan 10'])
        assert span.source_text == ['vlan 10']
    def test_frozen(self):
        span = SourceSpan(start_line=1, end_line=1)
        with pytest.raises(AttributeError):
            span.start_line = 99

class TestIRModelBase:
    def test_minimal(self):
        span = SourceSpan(start_line=1, end_line=1)
        m = IRModelBase(type=IRType.VLAN, source_span=span)
        assert m.type == IRType.VLAN
        assert m.conversion_status == ConversionStatus.EXACT
    def test_with_all_fields(self):
        span = SourceSpan(start_line=1, end_line=1)
        m = IRModelBase(type=IRType.BGP, source_span=span,
            conversion_status=ConversionStatus.APPROXIMATED,
            reason='different AS format',
            risk_level=IRRiskLevel.MEDIUM,
            review_notes='verify AS number')
        assert m.conversion_status == ConversionStatus.APPROXIMATED
        assert m.reason == 'different AS format'
    def test_default_fields(self):
        span = SourceSpan(start_line=1, end_line=1)
        m = IRModelBase(type=IRType.ACL, source_span=span)
        assert m.reason is None
        assert m.risk_level is None
```

- [ ] **Step 2: Run test**

Run: `PYTHONPATH=. venv/bin/python3 -m pytest tests/test_ir_base.py -v`

Expected: FAIL

- [ ] **Step 3: Write implementation**

```python
# core/ir_models/base.py
from __future__ import annotations
from dataclasses import dataclass, field
from core.ir_models.enums import IRType, ConversionStatus, IRRiskLevel

@dataclass(frozen=True)
class SourceSpan:
    start_line: int
    end_line: int
    source_text: list[str] = field(default_factory=list)

@dataclass
class IRModelBase:
    type: IRType
    source_span: SourceSpan
    conversion_status: ConversionStatus = ConversionStatus.EXACT
    reason: str | None = None
    risk_level: IRRiskLevel | None = None
    review_notes: str | None = None
```

- [ ] **Step 4: Run test**

Run: `PYTHONPATH=. venv/bin/python3 -m pytest tests/test_ir_base.py -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add core/ir_models/base.py tests/test_ir_base.py
git commit -m "feat(ir_models): add SourceSpan and IRModelBase"
```

## Phase 1: Domain Module

### Task 1.1: DeviceDomain Enum + DomainProfile

- [ ] **Step 1: Write the failing test**

```python
# tests/test_domain_base.py
import pytest
from core.domain.base import DeviceDomain, DomainProfile, FeatureKey, IRType

class TestDeviceDomain:
    def test_switch(self): assert DeviceDomain.SWITCH.value == 'switch'
    def test_router(self): assert DeviceDomain.ROUTER.value == 'router'
    def test_firewall(self): assert DeviceDomain.FIREWALL.value == 'firewall'

class TestDomainProfile:
    def test_switch_profile(self):
        profile = DomainProfile(domain=DeviceDomain.SWITCH,
            required_ir_types=[IRType.VLAN, IRType.INTERFACE],
            optional_ir_types=[IRType.OSPF], feature_keys=[FeatureKey.VLAN],
            critical_validators=['residue','coverage'],
            coverage_thresholds={'vlans': 1.0}, description='test')
        assert profile.domain == DeviceDomain.SWITCH
    def test_notes_default(self):
        profile = DomainProfile(domain=DeviceDomain.SWITCH, description='test',
            required_ir_types=[], optional_ir_types=[], feature_keys=[],
            critical_validators=[], coverage_thresholds={})
        assert profile.notes == []
```

- [ ] **Step 2: Run test**

Run: `PYTHONPATH=. venv/bin/python3 -m pytest tests/test_domain_base.py -v`

Expected: FAIL (ModuleNotFoundError)

- [ ] **Step 3: Write implementation**

```python
# core/domain/__init__.py
from core.domain.base import DeviceDomain, DomainProfile
from core.domain.detector import DomainDetector, DomainDetectionResult
from core.vendor.enums import FeatureKey, FeatureSupportStatus
```

```python
# core/domain/base.py
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from core.ir_models.enums import IRType
from core.vendor.enums import FeatureKey

class DeviceDomain(Enum):
    SWITCH='switch'; ROUTER='router'; FIREWALL='firewall'

@dataclass
class DomainProfile:
    domain: DeviceDomain
    description: str
    required_ir_types: list[IRType]
    optional_ir_types: list[IRType]
    feature_keys: list[FeatureKey]
    critical_validators: list[str]
    coverage_thresholds: dict[str, float]
    notes: list[str] = field(default_factory=list)
```

- [ ] **Step 4: Run test**

Run: `PYTHONPATH=. venv/bin/python3 -m pytest tests/test_domain_base.py -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add core/domain/__init__.py core/domain/base.py tests/test_domain_base.py
git commit -m "feat(domain): add DeviceDomain enum and DomainProfile"
```

### Task 1.2: DomainDetector

- [ ] **Step 1: Write the failing test**

```python
# tests/test_domain_detector.py
import pytest
from core.domain import DomainDetector, DeviceDomain

class TestDomainDetector:
    def test_detect_switch_from_switchport(self):
        detector = DomainDetector()
        config = 'vlan 10\n switchport mode trunk\n spanning-tree mode rstp'
        result = detector.detect(config)
        assert result.primary_domain == DeviceDomain.SWITCH
        assert result.confidence > 0.5
    def test_detect_router_from_ospf(self):
        detector = DomainDetector()
        config = 'router ospf 1\n network 10.0.0.0 0.255.255.255 area 0'
        result = detector.detect(config)
        assert result.primary_domain == DeviceDomain.ROUTER
    def test_detect_firewall_from_security_zone(self):
        detector = DomainDetector()
        config = 'security-zone name trust\n import interface GigabitEthernet0/1'
        result = detector.detect(config)
        assert result.primary_domain == DeviceDomain.FIREWALL
    def test_empty_config_returns_switch_default(self):
        detector = DomainDetector()
        result = detector.detect('! empty config')
        assert result.primary_domain == DeviceDomain.SWITCH
    def test_returns_evidence_dict(self):
        detector = DomainDetector()
        result = detector.detect('interface Vlan-interface10')
        assert isinstance(result.evidence, dict)
```

- [ ] **Step 2: Run test**

Run: `PYTHONPATH=. venv/bin/python3 -m pytest tests/test_domain_detector.py -v`

Expected: FAIL

- [ ] **Step 3: Write implementation**

```python
# core/domain/detector.py
from __future__ import annotations
import re
from dataclasses import dataclass, field
from core.domain.base import DeviceDomain

@dataclass
class DomainDetectionResult:
    primary_domain: DeviceDomain
    confidence: float
    evidence: dict[str, float]
    detected_features: list[str]
    secondary_features: list[str] = field(default_factory=list)

class DomainDetector:
    SWITCH_SIG = [
        (r'switchport',3.0), (r'vlan batch',3.0),
        (r'port trunk',2.0), (r'port access',2.0),
        (r'spanning-tree',3.0), (r'interface Vlan-?interface',3.0),
        (r'stp mode',2.0),
    ]
    ROUTER_SIG = [
        (r'router ospf',4.0), (r'router bgp',4.0),
        (r'ip route ',2.0), (r'vrf definition',3.0),
        (r'route-map',2.0), (r'neighbor \d+\.\d+\.\d+\.\d+',3.0),
    ]
    FIREWALL_SIG = [
        (r'security-zone',4.0), (r'zone-pair security',4.0),
        (r'policy interzone',3.0), (r'security-policy',3.0),
        (r'nat server',2.0),
    ]

    def __init__(self):
        self.signatures = {
            DeviceDomain.SWITCH: self.SWITCH_SIG,
            DeviceDomain.ROUTER: self.ROUTER_SIG,
            DeviceDomain.FIREWALL: self.FIREWALL_SIG,
        }

    def detect(self, config_text: str, vendor_hint: str | None = None) -> DomainDetectionResult:
        scores = {}
        detected = []
        for domain, sigs in self.signatures.items():
            total = 0.0
            for pattern, weight in sigs:
                if re.search(pattern, config_text, re.IGNORECASE | re.MULTILINE):
                    total += weight
                    detected.append(pattern)
            if total > 0: scores[domain] = total
        evidence = {d.value: s for d, s in scores.items()}
        if scores:
            primary = max(scores, key=scores.get)
            total = sum(scores.values())
            conf = scores[primary] / total if total > 0 else 0.0
        else:
            primary = DeviceDomain.SWITCH; conf = 0.0
        return DomainDetectionResult(primary_domain=primary, confidence=round(conf,4),
            evidence=evidence, detected_features=list(set(detected)))
```

- [ ] **Step 4: Run test**

Run: `PYTHONPATH=. venv/bin/python3 -m pytest tests/test_domain_detector.py -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add core/domain/detector.py tests/test_domain_detector.py
git commit -m "feat(domain): add DomainDetector"
```

## Phase 2: Vendor Module

### Task 2.1: Vendor Enums

- [ ] **Step 1: Write tests/test_vendor_enums.py**

```python
import pytest
from core.vendor.enums import FeatureKey, FeatureSupportStatus, ForbiddenPatternCategory
class TestFeatureKey:
    def test_vlan(self): assert FeatureKey.VLAN.value == 'vlan'
    def test_svi(self): assert FeatureKey.SVI.value == 'svi'
    def test_trunk(self): assert FeatureKey.TRUNK.value == 'trunk'
    def test_stp(self): assert FeatureKey.STP.value == 'stp'
    def test_lacp(self): assert FeatureKey.LACP.value == 'lacp'
class TestFeatureSupportStatus:
    def test_full(self): assert FeatureSupportStatus.FULL.value == 'full'
    def test_partial(self): assert FeatureSupportStatus.PARTIAL.value == 'partial'
    def test_unsupported(self): assert FeatureSupportStatus.UNSUPPORTED.value == 'unsupported'
    def test_unknown(self): assert FeatureSupportStatus.UNKNOWN.value == 'unknown'
class TestForbiddenPatternCategory:
    def test_residual(self): assert ForbiddenPatternCategory.RESIDUAL_SYNTAX.value == 'residual_syntax'
    def test_dangerous(self): assert ForbiddenPatternCategory.DANGEROUS_COMMAND.value == 'dangerous_command'
```

- [ ] **Step 2-5: Run FAIL, write core/vendor/__init__.py + core/vendor/enums.py, run PASS, commit**

```python
# core/vendor/enums.py
from enum import Enum
class FeatureKey(Enum):
    VLAN='vlan'; SVI='svi'; TRUNK='trunk'; STP='stp'; LACP='lacp'
    FHRP='fhrp'; LLDP='lldp'; CDP='cdp'; DHCP_SNOOPING='dhcp_snooping'
    STATIC_ROUTE='static_route'; OSPF='ospf'; BGP='bgp'; VRF='vrf'
    PBR='pbr'; ACL='acl'; NAT='nat'; NAT_POLICY='nat_policy'
    INTERFACE='interface'; MANAGEMENT='management'; AAA='aaa'
    IPSEC_VPN='ipsec_vpn'; ZONE='zone'
    ADDRESS_OBJECT='address_object'; SERVICE_OBJECT='service_object'
    SECURITY_POLICY='security_policy'; HA='ha'; USER_AUTH='user_auth'
    LOGGING='logging'; MANAGEMENT_ACCESS='management_access'
class FeatureSupportStatus(Enum):
    FULL='full'; PARTIAL='partial'; UNSUPPORTED='unsupported'; UNKNOWN='unknown'
class ForbiddenPatternCategory(Enum):
    RESIDUAL_SYNTAX='residual_syntax'; DANGEROUS_COMMAND='dangerous_command'
    UNSUPPORTED_FEATURE='unsupported_feature'; STYLE_WARNING='style_warning'
```

### Task 2.2: Vendor Base Types + Registry

- [ ] **Write tests/test_vendor_base.py with InterfaceNaming/VendorPlatformProfile/Registry tests**
- [ ] **Run FAIL, implement core/vendor/base.py, run PASS, commit**

core/vendor/base.py contains: InterfaceNaming, VendorSignature, ForbiddenPattern, FeatureSupport, VendorLimitation, VendorPlatformProfile, registry (_profiles dict, register_profile, get_profile, list_profiles)

### Task 2.3: All 8 VendorPlatformProfiles

- [ ] **Write tests/test_vendor_profiles.py with tests for all 8 profiles**
- [ ] **Run FAIL, create 8 profile files, run PASS, commit**

Each profile file follows the pattern: profile_cisco_ios_xe.py, profile_h3c_comware.py, profile_huawei_vrp.py, profile_huawei_usg.py, profile_ruijie_rgos.py, profile_hillstone_stoneos.py, profile_topsec_tos.py, profile_dptech_fw.py

## Phase 3: IR Data Models

### Task 3.1: All Remaining IR Types

- [ ] **Write tests: test_ir_common.py, test_ir_switch.py, test_ir_router.py, test_ir_firewall.py, test_ir_unsupported.py, test_ir_config.py**
- [ ] **Run FAIL, write all 7 implementation files**
core/ir_models/common.py: IRInterface, IRStaticRoute, IRAclEntry, IRAcl, IRAaa, IRManagement
core/ir_models/switch.py: IRVlan, IRFhrp, IRSvi, IRLag, IRStp
core/ir_models/router.py: IROspf, IRBgp, IRVrf, IRPbr, IRNat, IRIpsecVpn
core/ir_models/firewall.py: IRZone, IRAddressObject, IRServiceObject, IRSecurityPolicy, IRNatRule
core/ir_models/unsupported.py: IRUnsupported, IRUnknownBlock
core/ir_models/ir_config.py: IRConfigMeta, IRConfig
- [ ] **Run PASS, commit**

## Phase 4: Parser

### Task 4.1: BaseParser / ParserContext / Shared Utils

```python
# tests/test_parser_base.py
import pytest
from core.parser.base import BaseParser, ParserContext, ParseResult, ParseSectionResult, RawLine
class TestRawLine:
    def test_create(self):
        rl = RawLine(line_no=1, raw='  vlan 10  ', normalized='vlan 10')
        assert rl.line_no == 1
class TestParseResult:
    def test_coverage_ratio(self):
        from core.ir_models import IRConfig, IRConfigMeta; from core.domain.base import DeviceDomain
        meta = IRConfigMeta(source_vendor='h3c',target_vendor='cisco',source_domain=DeviceDomain.SWITCH,target_domain=DeviceDomain.SWITCH,source_platform='c',target_platform='c')
        r = ParseResult(ir=IRConfig(meta=meta), parsed_line_count=10, total_line_count=20)
        assert r.coverage_ratio == 0.5
class TestBaseParser:
    def test_abstract(self):
        with pytest.raises(TypeError): BaseParser()
```

core/parser/__init__.py: register_parser, get_parser, discover_parsers
core/parser/base.py: RawLine, ParserContext, ParseSectionResult, ParseResult, BaseParser
core/parser/shared.py: parse_vlan_range, render_vlan_range, cidr_to_mask, mask_to_cidr, normalize_interface_name, split_config_blocks

### Task 4.2: H3C Comware Full Parser (SWITCH Domain)

```python
# tests/test_parser_h3c.py -- tests for vlan/interface/svi/route/acl/stp/lag parsing
class TestH3CParser:
    def test_registered(self):
        import core.parser.parser_h3c_comware
        p = get_parser('switch', 'comware')
        assert p is not None
    def test_parse_vlans(self):
        import core.parser.parser_h3c_comware
        r = get_parser('switch','comware').parse('vlan 10\ndescription MGMT\nvlan 20')
        assert len(r.ir.vlans) == 2
    # + tests for interfaces, svis, static_routes, acls, stp, lags, ospf, management
```

core/parser/parser_h3c_comware.py: H3CComwareParser extends BaseParser, implements all parse_* methods
Registers for ('switch','comware') and ('router','comware')

## Phase 5: Renderer

### Task 5.1: BaseRenderer / RenderContext / Shared Utils

core/renderer/__init__.py: register_renderer, get_renderer, discover_renderers
core/renderer/base.py: RenderContext, RenderResult, RenderError, ReviewItem, BaseRenderer
core/renderer/shared.py: format_output

### Task 5.2: Cisco IOS-XE Full Renderer (SWITCH Domain)

core/renderer/renderer_cisco_ios.py: CiscoIOSXERenderer extends BaseRenderer
Renders: header, vlans, svis, interfaces, lags, static_routes, ospf, bgp, acls, management, unsupported/unknown
Registers for ('switch','ios-xe') and ('router','ios-xe')

## Phase 6: Validator

### Task 6.1: Base Validation Types
core/validator/base.py: ValidationCategory, ValidationIssue, ValidationReport
### Task 6.2: ResidueValidator
Scans target config for forbidden patterns from VendorPlatformProfile
### Task 6.3: CoverageValidator + ConversionValidator + SyntaxValidator + CapabilityGapValidator + SemanticValidator
### Task 6.4: CompositeValidator
Orchestrates all sub-validators, produces ValidationReport with deployable flag

## Phase 7: Policy & Fallback

### Task 7.1: ConversionPolicy
core/policy/base.py + __init__.py: ConversionPolicy dataclass + registry
### Task 7.2: Fallback Registry
core/fallback/base.py + __init__.py: BaseTranslator, FallbackEntry, register_fallback, get_fallback

## Phase 8: Pipeline Integration

### Task 8.1: TranslationCandidate + State Modifications
TranslationCandidate dataclass in pipeline models
State additions: ir, parse_result, render_result, validation_report, translation_path, translation_candidates

### Task 8.2: TranslateNode Dual-Path
Modify TranslateNode to try Parser->IR->Renderer path first, fall back to LLM

### Task 8.3: ValidateNode Unified
Modify ValidateNode to use CompositeValidator for all candidates

### Task 8.4: RouteNode Deployable
Use ValidationReport.deployable to determine output path

## Phase 9: Legacy Adapter + Skeleton Parsers/Renderers

### Task 9.1: Rename core/domain.py -> core/domain_legacy.py
### Task 9.2: Skeleton Parser Files (huawei_vrp, cisco_ios, ruijie_rgos, huawei_usg, hillstone, topsec, dptech)
Each skeleton: registers via register_parser, parse() returns empty IR with all config as IRUnknownBlock
### Task 9.3: Skeleton Renderer Files (h3c_comware, huawei_vrp, ruijie_rgos, huawei_usg, hillstone, topsec, dptech)
Each skeleton: registers via register_renderer, render() outputs commented-out unknown blocks

---

## Implementation Notes

1. Each task follows TDD: write test, run to verify FAIL, write impl, run to verify PASS, commit
2. All tests run with: `PYTHONPATH=. venv/bin/python3 -m pytest tests/test_*.py -v`
3. Flat test structure: all test files in tests/ directory
4. Each task step should take 2-5 minutes
5. Always commit after each task with descriptive message
6. Use `git status` and `git diff` before committing to verify changes
7. For skeleton parsers/renderers: minimum viable registration that doesn't crash
