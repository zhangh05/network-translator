# [SUPERSEDED] Domain / Vendor / Platform / Feature Refactor

> ⚠️ **此计划已被取代。** 最新设计以 `docs/superpowers/specs/2026-05-22-multi-vendor-ir-platform-design.md` 为准。
>
> **Superseded by**: `docs/superpowers/specs/2026-05-22-multi-vendor-ir-platform-design.md`
> **Superseded at**: 2026-05-22
> **原因**: 旧计划为 vendor-first 架构，新设计变更为 domain-first 架构 (DeviceDomain: SWITCH/ROUTER/FIREWALL)，核心假设、数据模型、目录结构均有重大差异，不可直接复用。
>
> 此文件保留仅用于历史参考，**不要**以它作为实施计划的输入。

# Domain / Vendor / Platform / Feature Refactor

## Objective

Upgrade the config translator from `vendor → vendor` to `domain → vendor → platform → feature` architecture. This enables meaningful translation between devices with the same domain (routing/switching/firewall) but different vendors, and prevents dangerous cross-domain translations (e.g., firewall NAT → router ACL).

## Anti-Patterns to Avoid

- **Big Bang**: Don't merge a single 2000-line PR. Each step must keep the system functional.
- **Dead Code Syndrome**: Don't leave old `from_vendor/to_vendor` code paths dead in the tree. Keep them working as fallback until migration is complete.
- **Premature Analyzer Abstraction**: Don't build `FeatureAnalyzer` base class until at least 2 real analyzers exist.
- **Untested Cache Invalidation**: Cache key changes WILL invalidate all existing caches. Document this explicitly.
- **Vendor Dir Mask**: Old `knowledge_data/{vendor}/*.md` must still work until migration step. Don't break the live system.

## Design

### Dependency Graph

```
Phase 1 ───────────────────────────────────────────────────────────────────────
Step 1: State + types (no deps)
  ├── Step 2: ParseNode domain/platform detection (depends: Step 1)
  ├── Step 3: registry.yaml, profile.yaml, capability_map upgrade (no code deps)
  └── Step 5: Frontend domain/platform selectors (no backend deps)

Step 4: Cache key upgrade (depends: Step 1, Step 3)
Step 6: web_app API domain/platform params (depends: Step 1, Step 2, Step 5)

Phase 2 ───────────────────────────────────────────────────────────────────────
Step 7a: knowledge_data/features/ structure (P0 features)
Step 7b: knowledge_data/domains/ structure + profile.yaml per vendor
Step 8: KnowledgeNode dual-path loading (depends: Step 7a, Step 7b)
Step 9: Migrate old knowledge_data/{vendor}/ → domains/ (depends: Step 7a, Step 7b, Step 8)

Phase 3 ───────────────────────────────────────────────────────────────────────
Step 10: core/analyzers/ base + registry (depends: Step 3)
Step 11: NatAnalyzer (depends: Step 10)
Step 12: SecurityPolicyAnalyzer (depends: Step 10)
Step 13: AclAnalyzer (depends: Step 10)
Step 14: FeatureAnalyzerNode in graph (depends: Step 11, Step 12, Step 13)

Phase 4 ───────────────────────────────────────────────────────────────────────
Step 15: ValidateNode split into generic/domain/platform/feature (depends: Step 2)
Step 16: Prompt upgrade with full context (depends: Step 6, Step 9, Step 14)
Step 17: Test + benchmark update (depends: Step 16)
```

### Parallelism

```
Parallel within Phase 1: Steps 2, 3, 5
Phase 2: Steps 7a→7b→8→9 serial (each depends on prior)
Parallel within Phase 3: Steps 11, 12, 13
```

### Serial Order Within Phases

```
Phase 1: Step 1 → (Step 2, Step 3, Step 5 parallel) → Step 4 → Step 6
Phase 2: Step 7a → Step 7b → Step 8 → Step 9
Phase 3: Step 10 → (Step 11, Step 12, Step 13 parallel) → Step 14
Phase 4: Step 15 → Step 16 → Step 17
```

### Model Tier

- Phase 1 (Steps 1-6): Default model — mechanical refactoring, well-defined patterns
- Phase 2 (Steps 7a-9): Default model — file ops, dual-load logic
- Phase 3 (Steps 10-14): Strongest model — analyzer architecture requires careful design
- Phase 4 (Steps 15-17): Strongest model — validation split and prompt design is high-risk

## Plan

---

### Step 1: State + Type Extensions

**Context**: State currently only carries `from_vendor`/`to_vendor`. We need `source_domain`, `source_platform`, `target_domain`, `target_platform`, and `features` as first-class fields that every node can read/write.

**Files to modify**:
- `core/graph/__init__.py` — State dataclass: add type hints, domain/platform constants
- `core/domain.py` (NEW) — Domain enum, Platform enum, DomainVendor mapping
- `core/graph/nodes.py` — Import new types

**Task**:
1. Create `core/domain.py`:
   ```python
   from enum import Enum, auto

   class Domain(Enum):
       ROUTING = "routing"
       SWITCHING = "switching"
       FIREWALL = "firewall"
       UNKNOWN = "unknown"

   # Platform mapping per vendor
   VENDOR_PLATFORMS = {
       "huawei": ["vrp", "usg", "unknown"],
       "h3c": ["comware", "secpath", "unknown"],
       "cisco": ["ios", "ios-xe", "nx-os", "asa", "ftd", "unknown"],
       "ruijie": ["rg-os", "unknown"],
       "hillstone": ["stoneos", "unknown"],
       "topsec": ["topsec-os", "unknown"],
       "dbappsecurity": ["unknown"],
       "dptech": ["unknown"],
   }

   DOMAIN_VENDOR_MAP = {
       "routing": ["huawei", "h3c", "cisco", "ruijie"],
       "switching": ["huawei", "h3c", "cisco", "ruijie"],
       "firewall": ["huawei", "h3c", "cisco", "hillstone", "topsec", "dbappsecurity", "dptech"],
   }

   def detect_domain_from_vendor(vendor: str) -> Domain:
       # heuristic: routing if unknown
       ...

   def detect_platform_from_config(config_text: str, domain: Domain, vendor: str) -> str:
       # regex-based detection per vendor
       ...
   ```

2. Extend `State` in `core/graph/__init__.py`:
   ```python
   @dataclass
   class State:
       session_id: str = field(...)
       data: Dict[str, Any] = field(default_factory=dict)

       # convenience accessors
       def get_source_domain(self) -> str:
           return self.get("source_domain", "unknown")
       def get_target_domain(self) -> str:
           return self.get("target_domain", "unknown")
       # ... similar for platform, features
   ```

3. Add `_DEFAULT_DOMAIN` fallback constant in nodes.py.

**Verification**:
- `PYTHONPATH=. python3 -c "from core.domain import Domain, DOMAIN_VENDOR_MAP; print(Domain.ROUTING.value)"` outputs `routing`
- `PYTHONPATH=. ./venv/bin/pytest tests/ -q` passes 59 tests

**Rollback**: Revert `core/domain.py`, restore `__init__.py`.

---

### Step 2: ParseNode Domain/Platform Detection

**Context**: ParseNode currently outputs `parsed_config` (vendor, hostname, interfaces, vlans). We need it to also detect domain and platform with confidence scores.

**Files to modify**:
- `core/graph/nodes.py` — ParseNode.execute()
- `tools/__init__.py` — ConfigParser.parse() + detect_vendor()
- `core/domain.py` — detect_platform_from_config() implementation

**Task**:
1. Implement `detect_platform_from_config()` in `core/domain.py`:
   - `huawei`: detect `sysname` + `interface Vlanif` → VRP; `security-zone` → USG
   - `cisco`: detect `interface` + `router ospf` → IOS; `security-level` → ASA; `switchport` + `vlan` → NX-OS
   - `h3c`: `comware` → Comware; `secpath` → SecPath
   - Regex-based, vendor-signature style

2. Extend ParseNode output:
   ```python
   state.set("source_domain", detected_domain)
   state.set("source_platform", detected_platform)
   state.set("target_domain", state.get("target_domain") or detected_domain)
   state.set("target_platform", state.get("target_platform") or "")
   state.set("features", detected_features)
   ```

3. Add confidence scoring (`vendor: 0.95`, `domain: 0.9`, `platform: 0.75`, etc.)

4. Keep old `from_vendor`/`to_vendor` keys functional for backward compat.

**Verification**:
- Test with Cisco IOS config → domain=routing, platform=ios
- Test with Huawei USG config → domain=firewall, platform=usg
- Test with H3C switching config → domain=switching, platform=comware
- `PYTHONPATH=. ./venv/bin/pytest tests/ -q` passes all 59

**Rollback**: Revert ParseNode changes, restore domain.py.

---

### Step 3: Registry, Profile, CapabilityMap

**Context**: Three new data files define the feature universe. These are pure data — no code dependency.

**Files to create/modify**:
- `knowledge_data/features/registry.yaml` (NEW)
- `knowledge_data/domains/{routing,switching,firewall}/{vendor}/profile.yaml` (NEW, ~11 files)
- `knowledge_data/capability_map.yaml` (MODIFY — add domain dimension)

**Task**:
1. Create `knowledge_data/features/registry.yaml` per spec:
   - All P0/P1/P2 features with domain, priority, risk, analyzer, manual_review_on_unknown
   - 28+ features total

2. Create profiles for routing/huawei, routing/cisco, routing/h3c, routing/ruijie, switching/huawei, switching/cisco, switching/h3c, switching/ruijie, firewall/huawei, firewall/h3c, firewall/cisco, firewall/hillstone (expand as needed):
   ```yaml
   # knowledge_data/domains/routing/huawei/profile.yaml
   domain: routing
   vendor: huawei
   default_platform: vrp
   platforms: [vrp, unknown]
   features: [system, interface, static_route, ospf, bgp, isis, acl, nat, qos]
   syntax_markers: [sysname, ip route-static, router ospf, acl number]
   risk_features:
     nat: high
     acl: high
   ```

3. Upgrade `capability_map.yaml`:
   - Restructure from `feature: {vendor: status}` to `feature: {domain: {vendor: {support, notes}}}`
   - Keep flat vendor fallback for backward compat in loader

**Verification**:
- `python3 -c "import yaml; d=yaml.safe_load(open('knowledge_data/features/registry.yaml')); print(len(d['features']))"` — 28+
- `python3 -c "import yaml; d=yaml.safe_load(open('knowledge_data/domains/routing/huawei/profile.yaml')); print(d['domain'])"` — routing
- YAML files parse without error

**Rollback**: Simple file revert — no code changes.

---

### Step 4: Cache Key Upgrade

**Context**: Cache key must now include domain/platform/features to prevent cross-domain cache collisions.

**Files to modify**:
- `core/graph/nodes.py` — CacheNode._build_key()

**Task**:
1. Extend `_build_key()`:
   ```python
   def _build_key(self, config_text, from_vendor, to_vendor,
                   source_domain, source_platform,
                   target_domain, target_platform,
                   features, llm_model):
       kh = self._knowledge_hash(to_vendor, target_domain)
       parts = "||".join([
           config_text,
           from_vendor, to_vendor,
           source_domain, source_platform or "",
           target_domain, target_platform or "",
           ",".join(sorted(features or [])),
           kh,
           _PROMPT_VERSION, _TRANSLATOR_VERSION, _NORMALIZER_VERSION,
           llm_model or "default",
       ])
       return hashlib.sha256(parts.encode()).hexdigest()
   ```

2. Update `_knowledge_hash()` to also hash `knowledge_data/domains/{domain}/{vendor}/` + `knowledge_data/features/` directory contents.

3. Read domain/platform/features from state, with fallback to old keys.

**Verification**:
- Same domain/vendor/config → same cache key
- Different domain (routing vs firewall) → different cache key
- Different features list → different cache key
- `PYTHONPATH=. ./venv/bin/pytest tests/ -q` passes all

**Rollback**: Revert `_build_key()` to previous signature.

---

### Step 5: Frontend Domain/Platform Selectors

**Context**: User needs to select source domain, source platform, target domain, target platform. These are interdependent — target vendor changes the available platforms. Frontend calls `/api/domain/meta` (created in Step 6) to populate dropdowns.

**Files to modify**:
- `frontend/index.html` — HTML + JS

**Task**:
1. Add HTML for `source_domain` dropdown:
   ```html
   <select id="sd">
     <option value="auto">自动检测</option>
     <option value="routing">路由</option>
     <option value="switching">交换</option>
     <option value="firewall">防火墙</option>
   </select>
   ```

2. Add `source_platform` dropdown, populated dynamically based on vendor + domain.

3. Add `target_domain` dropdown (same options, no "auto").

4. Add `target_platform` dropdown, populated dynamically.

5. Update JS `translate()` to send: `source_domain, source_platform, target_domain, target_platform`.

6. On page load, fetch `/api/domain/meta` and build cascading dropdown data:
   ```javascript
   fetch('/api/domain/meta')
     .then(r => r.json())
     .then(meta => {
       // build platform options per vendor
       // build domain options per vendor
     });
   ```

7. Update JS state persistence to include new fields.

8. Implement cascading dropdown logic:
   - Selecting vendor filters domain options
   - Selecting domain + vendor filters platform options

9. Add tooltips/help text explaining domain/platform meaning.

**Verification**:
- `python3 -c "from flask import Flask; app=Flask(__name__); app.testing=True; from web_app import app; c=app.test_client(); r=c.get('/'); assert b'source_domain' in r.data or b'sd' in r.data"`
- Manual: UI renders, dropdowns cascade correctly

**Rollback**: Revert `index.html` changes.

---

### Step 6: Web App API Updates

**Context**: API must accept and validate new domain/platform params.

**Files to modify**:
- `web_app.py` — translate endpoints
- `project_store.py` — run_translation() signature + agent.run() call

**Task**:
1. Update `translate_once()` to accept:
   ```python
   source_domain = (data.get("source_domain") or "auto").strip().lower()
   source_platform = (data.get("source_platform") or "auto").strip().lower()
   target_domain = (data.get("target_domain") or "").strip().lower()
   target_platform = (data.get("target_platform") or "").strip().lower()
   ```

2. Pass these to `project_store.run_translation()`:
   ```python
   project_store.run_translation(
       config_text=config_text,
       from_vendor=from_vendor, to_vendor=to_vendor,
       source_domain=source_domain, source_platform=source_platform,
       target_domain=target_domain, target_platform=target_platform,
       user="api_user",
   )
   ```

3. In `GraphAgent.run()`, set state from these params.

4. Update `register_project_routes` project endpoints to store/return domain/platform.

5. Add new `/api/domain/meta` endpoint returning available domains, vendors per domain, and platforms per vendor:
   ```python
   # Returns {
   #   "domains": ["routing", "switching", "firewall"],
   #   "vendors": {"routing": [...], "switching": [...], "firewall": [...]},
   #   "platforms": {"huawei": ["vrp", "usg", "unknown"], ...}
   # }
   ```
   Frontend uses this for cascading dropdowns.

6. Add validation: if source domain != target domain and neither is auto, issue warning (cross-domain translation).

**Verification**:
- `curl -X POST .../api/translate -d '{"config_text":"...","from_vendor":"cisco","to_vendor":"huawei","source_domain":"routing","target_domain":"routing"}'` → 200
- `curl -X POST .../api/translate -d '{"config_text":"...","from_vendor":"cisco","to_vendor":"huawei","source_domain":"firewall","target_domain":"routing"}'` → 200 with cross-domain warning
- `PYTHONPATH=. ./venv/bin/pytest tests/ -q` passes all

**Rollback**: Revert `web_app.py`, `project_store.py` function signatures.

---

### Step 7a: Feature Registry + Common Docs

**Context**: Create `knowledge_data/features/` with `registry.yaml` and per-feature `common.yaml`/`validator_rules.yaml`. Old `knowledge_data/{vendor}/*.md` stays unchanged.

**Files to create**:
- `knowledge_data/features/registry.yaml`
- `knowledge_data/features/{P0_feature}/common.yaml` — ~15 features
- `knowledge_data/features/{P0_feature}/validator_rules.yaml` — ~15 features

**Task**:
1. Create `knowledge_data/features/registry.yaml` per spec:
   - All P0/P1/P2 features with domain, priority, risk, analyzer, manual_review_on_unknown
   - 28+ features total (extend current 27 with `security_policy`, `zone`, etc.)

2. For each P0 feature, create `common.yaml`:
   ```yaml
   # knowledge_data/features/interface/common.yaml
   fields:
     - name: ip_address
       type: cidr_or_ip_mask
       risk: low
     - name: description
       type: string
       risk: info
     - name: mtu
       type: integer
       risk: medium
     - name: vrf
       type: string
       risk: medium
     - name: zone
       type: string
       risk: high
   field_aliases:
     ip_address: [address, ip]
     description: [desc]
   ```

3. For high-risk features (nat, security_policy, acl), create `validator_rules.yaml`:
   ```yaml
   # knowledge_data/features/nat/validator_rules.yaml
   rules:
     - id: nat-missing-zone
       description: "NAT policy without source/destination zone"
       severity: fatal
       pattern: "nat\\s+policy|ip\\s+nat\\s+inside"
       require_pattern: "zone|inside|outside"
     
     - id: nat-ambiguous-type
       description: "NAT type ambiguous"
       severity: warning
       pattern: "nat"
       require_pattern: "(source|destination|static|dynamic|pat|easy-ip)"
   ```

**P0 features** (full coverage):
`system`, `interface`, `ip_address`, `static_route`, `ospf`, `bgp`, `isis`, `vlan`, `access_port`, `trunk`, `stp`, `lacp`, `acl`, `prefix_list`, `route_policy`, `nat`, `security_policy`, `address_object`, `service_object`, `zone`, `ipsec`, `dhcp`, `vrrp`

**Verification**:
- All YAML files parse without error
- `python3 -c "import yaml; d=yaml.safe_load(open('knowledge_data/features/registry.yaml')); assert len(d['features']) >= 28"`
- `ls knowledge_data/features/ | wc -l` shows 23+ feature directories

**Rollback**: `rm -rf knowledge_data/features`

---

### Step 7b: Domain Knowledge Structure + Profiles

**Context**: Create `knowledge_data/domains/{domain}/{vendor}/` with `profile.yaml` per domain/vendor. These define what features are relevant in each domain, what platforms exist, and syntax markers.

**Files to create**:
- `knowledge_data/domains/routing/{huawei,h3c,cisco,ruijie}/profile.yaml`
- `knowledge_data/domains/switching/{huawei,h3c,cisco,ruijie}/profile.yaml`
- `knowledge_data/domains/firewall/{huawei,h3c,cisco,hillstone}/profile.yaml`

**Task**:
1. Create profiles for all domain/vendor combinations:
   ```yaml
   # knowledge_data/domains/routing/huawei/profile.yaml
   domain: routing
   vendor: huawei
   default_platform: vrp
   platforms: [vrp, unknown]
   features: [system, interface, static_route, ospf, bgp, isis, acl, nat, qos, vrrp, dhcp, bfd, multicast, pbr]
   syntax_markers: [sysname, ip route-static, router ospf, acl number]
   risk_features:
     nat: high
     acl: high
   ```

2. Each profile declares:
   - `domain`, `vendor`, `default_platform`
   - `platforms`: list of valid platform strings
   - `features`: which features this domain/vendor combination handles
   - `syntax_markers`: distinctive command keywords
   - `risk_features`: map of feature → risk level override

3. Firewall profiles include firewall-only features: `zone`, `security_policy`, `address_object`, `service_object`, `ipsec`

4. Switching profiles include switching-only features: `vlan`, `stp`, `lacp`, `stack`, `m-lag`

**Verification**:
- All YAML files parse without error
- `ls knowledge_data/domains/routing/huawei/profile.yaml` exists
- `ls knowledge_data/domains/firewall/huawei/profile.yaml` exists
- Each profile features list matches the feature registry

**Rollback**: `rm -rf knowledge_data/domains`

---

### Step 8: KnowledgeNode Dual-Path Loading

**Context**: KnowledgeNode must load from new structure while old structure still works. This enables gradual migration.

**Files to modify**:
- `tools/knowledge_manager.py` — KnowledgeRetriever + retriever functions
- `core/graph/nodes.py` — KnowledgeNode

**Task**:
1. Extend `KnowledgeRetriever.__init__()`:
   - Load from `knowledge_data/domains/{domain}/{vendor}/*.md` if domain+vendor provided
   - Fall back to old `knowledge_data/{vendor}/*.md` if not found
   - Load feature common docs from `knowledge_data/features/{feature}/common.yaml`

2. New method: `get_feature_knowledge(feature_name, domain, vendor)` → dict:
   ```python
   def get_feature_knowledge(self, feature: str, domain: str, vendor: str):
       # 1. Load features/<feature>/common.yaml
       # 2. Load domains/<domain>/<vendor>/<feature>.md (if exists)
       # 3. Fall back to old <vendor>/<feature>.md
       # 4. Merge into structured dict
   ```

3. Update `KnowledgeNode.execute()`:
   - Read domain/platform from state
   - Load knowledge using new path if domain is known
   - Fall back to old path if domain is unknown/auto
   - Build `knowledge_context` from merged structured dict

4. Add debug logging showing which path was used.

**Verification**:
- `python3 -c "from tools.knowledge_manager import KnowledgeRetriever; k=KnowledgeRetriever(); k2=k.get_feature_knowledge('nat', 'firewall', 'huawei'); print(type(k2))"` → dict
- Old `get_all_mapping_info('cisco', 'huawei')` still works
- `PYTHONPATH=. ./venv/bin/pytest tests/ -q` passes all

**Rollback**: Revert `knowledge_manager.py` changes.

---

### Step 9: Migrate Old Knowledge

**Context**: Move content from `knowledge_data/{vendor}/*.md` into `knowledge_data/domains/{domain}/{vendor}/*.md`. Content is split/generalized per domain.

**Files to modify**:
- All `knowledge_data/cisco/*.md`, `knowledge_data/huawei/*.md`, `knowledge_data/h3c/*.md`
- New files in `knowledge_data/domains/{routing,switching,firewall}/{vendor}/`

**Task**:
For each existing vendor knowledge file, decide its domain:
- `interface.md` → routing + switching + firewall (shared)
- `static_route.md` → routing + firewall
- `ospf.md`, `bgp.md`, `isis.md` → routing
- `vlan.md`, `stp.md`, `lacp.md` → switching
- `nat.md` → routing + firewall
- `security_zone.md` → firewall
- `vrrp.md` → routing + switching
- `aaa.md` → routing + switching + firewall (shared)

For files that span multiple domains, create copies and add domain-specific context.

After migration, update `KnowledgeRetriever` to prefer new path.

**Verification**:
- All features/domain/vendor combinations from registry.yaml have corresponding .md files
- Old `knowledge_data/{vendor}/*.md` files remain as fallback
- `PYTHONPATH=. ./venv/bin/pytest tests/ -q` passes all

**Rollback**: Not a single commit — can be reverted step by step.

---

### Step 10: Feature Analyzer Base + Registry

**Context**: Feature Analyzers provide structured IR extraction for high-risk features. Base class defines interface; registry maps feature names to analyzer classes.

**Files to create**:
- `core/analyzers/__init__.py`
- `core/analyzers/base.py`
- `core/analyzers/registry.py`

**Files to modify**:
- `core/graph/nodes.py` — add import

**Task**:
1. Create `core/analyzers/__init__.py`:
   ```python
   from .base import FeatureAnalyzer, FeatureAnalysis
   from .registry import get_analyzer, get_analyzers_for_features, register_analyzer
   ```

2. Create `core/analyzers/base.py`:
   ```python
   @dataclass
   class FeatureAnalysis:
       feature: str
       rules: list             # extracted rules
       references: dict        # referenced objects
       missing_context: list   # things needed but not found
       risk_level: str         # info | warning | fatal
       manual_review: bool
       source_lines: list      # matching source config lines
       ir_json: dict           # structured IR for the feature
   
   class FeatureAnalyzer(ABC):
       feature_name: str
       
       @abstractmethod
       def match(self, config_text: str, context: dict) -> bool:
           pass
       
       @abstractmethod
       def analyze(self, config_text: str, context: dict) -> FeatureAnalysis:
           pass
   ```

3. Create `core/analyzers/registry.py`:
   ```python
   _analyzers: Dict[str, Type[FeatureAnalyzer]] = {}
   
   def register_analyzer(analyzer_cls: Type[FeatureAnalyzer]):
       _analyzers[analyzer_cls.feature_name] = analyzer_cls
   
   def get_analyzer(feature: str) -> Optional[Type[FeatureAnalyzer]]:
       return _analyzers.get(feature)
   
   def get_analyzers_for_features(features: list[str]) -> list[FeatureAnalyzer]:
       return [cls() for f in features if (cls := _analyzers.get(f))]
   ```

**Verification**:
- `python3 -c "from core.analyzers.base import FeatureAnalyzer, FeatureAnalysis; print('OK')"`
- `python3 -c "from core.analyzers.registry import register_analyzer, get_analyzer; print('OK')"`
- Base class can be subclassed and registered

**Rollback**: Revert `core/analyzers/` completely.

---

### Step 11: NatAnalyzer

**Context**: NAT is the highest-risk translation feature. Analyzer must extract source zone, dest zone, inside/outside interfaces, source/dest addresses, translated addresses, address pools, port forwarding rules, ACL references, and rule order.

**Files to create**:
- `core/analyzers/nat.py`

**Files to modify**:
- `core/analyzers/__init__.py` — import NatAnalyzer

**Task**:
1. Create `NatAnalyzer(FeatureAnalyzer)`:
   ```python
   class NatAnalyzer(FeatureAnalyzer):
       feature_name = "nat"
       
       def match(self, config_text, context):
           # Detect: nat-policy, ip nat inside/outside, nat server, easy-ip, etc.
           patterns = [
               r'nat\s+policy',
               r'ip\s+nat\s+(inside|outside)',
               r'nat\s+server',
               r'easy-ip',
               r'nat\s+address-group',
               r'ip\s+nat\s+pool',
               r'nat\s+static',
               r'nat\s+destination',
           ]
           return any(re.search(p, config_text, re.I) for p in patterns)
       
       def analyze(self, config_text, context):
           # Extract structured IR:
           # {
           #   "rules": [{type, src_zone, dst_zone, src_addr, dst_addr,
           #              trans_addr, pool, acl, service, order, action}],
           #   "missing_context": [...],
           #   "references": {...}
           # }
           # Risk scoring:
           # - no zone/interface → fatal/manual_review
           # - missing pool reference → warning
           # - missing ACL → warning
           # - ambiguous type → fatal/manual_review
           ...
   ```

2. Register in `registry.py`:
   ```python
   from .nat import NatAnalyzer
   register_analyzer(NatAnalyzer)
   ```

3. Cover all NAT types:
   - Source NAT (masquerade, hide)
   - Destination NAT (mapping, redirect)
   - Static NAT (one-to-one)
   - Dynamic NAT (pool-based)
   - PAT (port address translation)
   - Policy NAT (zone/address-based rules)
   - Twice NAT (source + destination simultaneous)
   - NAT Server / Port Forwarding

**Verification**:
- `python3 -c "from core.analyzers import NatAnalyzer; a=NatAnalyzer(); assert a.match('nat-policy', {}); assert not a.match('nothing', {})"`
- Analyze a Cisco IOS NAT config → structured IR with rules, references, missing_context
- `PYTHONPATH=. ./venv/bin/pytest tests/ -q` passes all

**Rollback**: Revert `core/analyzers/nat.py`.

---

### Step 12: SecurityPolicyAnalyzer

**Context**: Firewall security policies (permit/deny between zones) are second-highest risk. Must extract zones, addresses, services, actions, logging, time ranges, rule order.

**Files to create**:
- `core/analyzers/security_policy.py`

**Files to modify**:
- `core/analyzers/__init__.py` — import

**Task**:
1. Create `SecurityPolicyAnalyzer(FeatureAnalyzer)`:
   ```python
   class SecurityPolicyAnalyzer(FeatureAnalyzer):
       feature_name = "security_policy"
       
       def match(self, config_text, context):
           patterns = [
               r'security-policy',
               r'security\s+policy',
               r'access-group',
               r'rule\s+\d+\s+(permit|deny)',
           ]
           ...
       
       def analyze(self, config_text, context):
           # Extract:
           # {rules: [{id, src_zone, dst_zone, src_addr_obj, dst_addr_obj,
           #           service, application, user, action, log, time_range,
           #           order}],
           #  missing_context: [...],
           #  references: {zones, addresses, services}}
           # 
           # Risk:
           # - missing zone → fatal
           # - missing address object → warning
           # - action not clear → fatal
           # - rule order changed → warning
           ...
   ```

2. Register in `registry.py`.

**Verification**:
- Match Cisco ASA access-group config
- Match Huawei security-policy config
- Extract structured IR from both
- `PYTHONPATH=. ./venv/bin/pytest tests/ -q`

**Rollback**: Revert file.

---

### Step 13: AclAnalyzer

**Context**: ACL translation is medium-high risk. Must extract entries, sequence numbers, protocols, source/dest, ports, actions, remarks.

**Files to create**:
- `core/analyzers/acl.py`

**Files to modify**:
- `core/analyzers/__init__.py`

**Task**:
1. Create `AclAnalyzer(FeatureAnalyzer)`:
   ```python
   class AclAnalyzer(FeatureAnalyzer):
       feature_name = "acl"
       
       def match(self, config_text, context):
           patterns = [r'access-list', r'acl\s+number', r'acl\s+basic', r'acl\s+advanced']
           ...
       
       def analyze(self, config_text, context):
           # Extract:
           # {acls: [{name/number, type (standard/extended/basic/advanced),
           #          entries: [{sequence, action, protocol, src, dst, port,
           #                     established, log, icmp_type, dscp}],
           #          remarks}]}
           # 
           # Risk:
           # - seq number mismatch → warning (order may change)
           # - implicit deny difference → warning
           # - named vs numbered → warning
           ...
   ```

2. Register.

**Verification**:
- Match and extract from Cisco `access-list 100 permit tcp any any eq 80`
- Match and extract from Huawei `acl number 3000`
- `PYTHONPATH=. ./venv/bin/pytest tests/ -q`

**Rollback**: Revert file.

---

### Step 14: FeatureAnalyzerNode

**Context**: A new graph node that runs all registered analyzers matching the detected features, stores results in state, and injects structured IR + risk info into the prompt context.

**Files to modify**:
- `core/graph/nodes.py` — new FeatureAnalyzerNode class
- `core/graph/translation_graph.py` — add node + edges
- `core/analyzers/registry.py` — export `get_analyzers_for_features`

**Task**:
1. Add `FeatureAnalyzerNode`:
   ```python
   class FeatureAnalyzerNode(Node):
       def __init__(self, node_id: str = "feature_analyzer"):
           super().__init__(node_id, "feature_analyzer")
       
       def execute(self, state: State) -> NodeResult:
           features = state.get("features", [])
           context = {
               "source_vendor": state.get("from_vendor"),
               "target_vendor": state.get("to_vendor"),
               "source_domain": state.get("source_domain"),
               "target_domain": state.get("target_domain"),
               "source_platform": state.get("source_platform"),
           }
           
           analyses = []
           for analyzer in get_analyzers_for_features(features):
               if analyzer.match(config_text, context):
                   analysis = analyzer.analyze(config_text, context)
                   analyses.append(analysis)
           
           state.set("feature_analyses", analyses)
           # Check for fatal analysis results
           fatal_features = [a.feature for a in analyses if a.risk_level == "fatal"]
           if fatal_features:
               state.set("feature_analysis_fatal", fatal_features)
   ```

2. Add to graph after parse, before knowledge:
   ```python
   graph.add_node(feature_analyzer_node, "feature_analyzer")
   graph.add_edge("parse", "feature_analyzer")
   graph.add_edge("feature_analyzer", "knowledge")
   # After feature_analyzer → if fatal, route differently
   ```

3. Inject analyzer IR into `knowledge_context` so TranslateNode sees it.

**Verification**:
- `python3 -c "from core.graph.nodes import FeatureAnalyzerNode; n=FeatureAnalyzerNode(); print(n.node_id)"`
- Run a full translate with NAT config → state has `feature_analyses`
- `PYTHONPATH=. ./venv/bin/pytest tests/ -q` passes all

**Rollback**: Revert `nodes.py` and `translation_graph.py` changes.

---

### Step 15: ValidateNode Multi-Layer Split

**Context**: ValidateNode currently does one pass. Split into: generic → domain → platform → feature.

**Files to modify**:
- `core/graph/nodes.py` — ValidateNode refactor
- `tools/__init__.py` — ConfigValidator extension

**Task**:
1. Split validation into ordered layers:
   ```
   Layer 1: Generic (always runs)
     - Empty output
     - Markdown fence
     - Placeholder/TODO
     - Source vendor residue
   
   Layer 2: Domain (if domain known)
     - routing: check route-map, prefix-list, redistribute consistency
     - switching: check VLAN range, trunk mode consistency
     - firewall: check zone existence, security-policy completeness
   
   Layer 3: Platform (if platform known)
     - cisco/ios: check interface naming (`GigabitEthernet`)
     - huawei/usg: check security-zone syntax
     - cisco/asa: check access-group on interface
   
   Layer 4: Feature (from feature_analyses or validator_rules.yaml)
     - nat: check zone/interface assignment, pool reference
     - acl: check seq numbering, implicit deny
     - security_policy: check action, zone pairs
   ```

2. Load `validator_rules.yaml` from `knowledge_data/features/{feature}/` for layer 4.

3. Store structured validation result with layer attribution:
   ```python
   {
       "level": "fatal|warning|info",
       "generic": [...],
       "domain": [...],
       "platform": [...],
       "feature": [...],
       "summary": "..."
   }
   ```

**Verification**:
- Same existing validation still works
- New layer-specific rules fire for known domain/platform
- `PYTHONPATH=. ./venv/bin/pytest tests/ -q` passes all

**Rollback**: Revert `ValidateNode`, `ConfigValidator`.

---

### Step 16: LLM Prompt Upgrade

**Context**: Prompt must include the full domain/vendor/platform/feature context, not just "translate Huawei to Cisco".

**Files to modify**:
- `core/ir.py` — `translate_config()` prompt builder

**Task**:
1. Build structured prompt header:
   ```
   Source: {domain} / {vendor} / {platform}
   Target: {domain} / {vendor} / {platform}
   Features detected: [nat, security_policy, address_object]
   Analyzer IR: {structured IR from analyzer}
   Capability gaps: {list of unsupported/partial features}
   ```

2. Generate platform-specific context:
   ```
   The target platform is Cisco ASA. ASA uses a different NAT model than IOS:
   - NAT is configured as object NAT or twice NAT
   - security-level replaces zone-based security
   - ACLs are applied via access-group on interfaces
   ```

3. If target platform is `unknown`:
   ```
   WARNING: Target platform not specified. Generate generic syntax for
   {vendor} {domain}. Clearly mark any platform-specific assumptions with
   "MANUAL_REVIEW" comment.
   ```

4. Inject analyzer IR into prompt as structured context before config text.

5. Add output format constraint: prohibit `<...>` placeholders, require `MANUAL_REVIEW` for any guess.

**Verification**:
- Run translate with routing domain → prompt says "routing / cisco / ios → routing / huawei / vrp"
- Run translate with firewall domain → prompt says "firewall / huawei / usg → firewall / cisco / asa"
- Analyzer IR appears in prompt
- `PYTHONPATH=. ./venv/bin/pytest tests/ -q` passes all

**Rollback**: Revert `ir.py`.

---

### Step 17: Tests + Benchmark Update

**Context**: All tests must reflect new domain/platform/feature structure. Benchmark cases should include domain/platform metadata.

**Files to modify**:
- `tests/` — various
- `tests/accuracy/translation_cases.json` — add domain/platform
- `tests/accuracy/run_benchmark.py` — pass domain/platform

**Task**:
1. Update existing translation tests with domain/platform params.

2. Update `translation_cases.json`:
   ```json
   {
     "name": "Cisco OSPF to Huawei",
     "source_domain": "routing",
     "source_vendor": "cisco",
     "source_platform": "ios",
     "target_domain": "routing",
     "target_vendor": "huawei",
     "target_platform": "vrp",
     "config_text": "...",
     "expected": "..."
   }
   ```

3. Add new test cases:
   - Cross-domain translation (firewall → routing) → should warn
   - Cisco ASA firewall NAT → Huawei USG firewall NAT
   - Cisco IOS routing ACL → H3C Comware routing ACL
   - Feature analyzer edge cases

4. Ensure benchmark runner passes domain/platform to translate API.

**Verification**:
- `PYTHONPATH=. ./venv/bin/pytest tests/ -q` passes all
- `PYTHONPATH=. python3 tests/accuracy/run_benchmark.py` runs without error
- New test cases cover domain/platform params

**Rollback**: Revert test changes.

---

## Rollback Strategy by Step

| Step | Rollback |
|------|----------|
| 1 | Revert `core/domain.py`, `__init__.py` |
| 2 | Revert ParseNode, domain.py |
| 3 | Delete new files, restore old capability_map.yaml |
| 4 | Revert `_build_key()` |
| 5 | Revert `index.html` |
| 6 | Revert `web_app.py`, `project_store.py` |
| 7a | `rm -rf knowledge_data/features` |
| 7b | `rm -rf knowledge_data/domains` |
| 8 | Revert `knowledge_manager.py` |
| 9 | `rm -rf knowledge_data/domains` (old still intact) |
| 10 | `rm -rf core/analyzers/` |
| 11 | `rm core/analyzers/nat.py` |
| 12 | `rm core/analyzers/security_policy.py` |
| 13 | `rm core/analyzers/acl.py` |
| 14 | Revert `nodes.py`, `translation_graph.py` |
| 15 | Revert `ValidateNode`, `ConfigValidator` |
| 16 | Revert `ir.py` |
| 17 | Revert test files |

## Verification Target

At the end of each step:
- `PYTHONPATH=. ./venv/bin/pytest tests/ -q` passes all tests
- `PYTHONPATH=. python3 -c "from web_app import app; c=app.test_client(); c.get('/healthz')"` returns 200
- No new lint warnings from `python3 -m flake8` (if installed)

## Metrics

After full migration:
1. Cache hit rate should be identical (cache key expansion doesn't reduce hits for same-params requests)
2. Cross-domain detection: 100% of firewall→routing translations flagged
3. Feature analyzer coverage: NAT/security_policy/ACL analysis on 100% of matching translations
4. Prompt contains domain/platform context for 100% of translations with known domain
5. ValidateNode fires layer-specific rules for 100% of known domain/platform
