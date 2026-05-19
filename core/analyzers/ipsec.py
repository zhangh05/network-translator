from __future__ import annotations
import re
from typing import Any, Dict, List, Optional

from core.analyzers.base import FeatureAnalysis, FeatureAnalyzer


# ── Huawei/H3C IKE ──────────────────────────────────────────────────────────────
_RE_HW_IKE_PROPOSAL = re.compile(r"^\s*ike\s+proposal\s+(\S+)", re.IGNORECASE)
_RE_HW_IKE_PEER = re.compile(r"^\s*ike\s+peer\s+(\S+)", re.IGNORECASE)

# ── Huawei/H3C IPsec ────────────────────────────────────────────────────────────
_RE_HW_IPSEC_PROPOSAL = re.compile(r"^\s*ipsec\s+proposal\s+(\S+)", re.IGNORECASE)
_RE_HW_IPSEC_POLICY = re.compile(
    r"^\s*ipsec\s+policy\s+(\S+)\s+(\S+)\s+isakmp",
    re.IGNORECASE,
)
_RE_HW_IPSEC_PROFILE = re.compile(r"^\s*ipsec\s+profile\s+(\S+)", re.IGNORECASE)

# Huawei/H3C sub-commands inside ipsec/ike blocks
_RE_HW_SECURITY_ACL = re.compile(r"^\s*security\s+acl\s+(\S+)", re.IGNORECASE)
_RE_HW_IKE_PEER_REF = re.compile(r"^\s*ike-peer\s+(\S+)", re.IGNORECASE)
_RE_HW_PROPOSAL_REF = re.compile(r"^\s*proposal\s+(\S+)", re.IGNORECASE)
_RE_HW_REMOTE_ADDR = re.compile(r"^\s*remote-address\s+(\S+)", re.IGNORECASE)
_RE_HW_PSK = re.compile(r"^\s*pre-shared-key\s+(?:\S+\s+)?(\S+)", re.IGNORECASE)
_RE_HW_SA_DURATION = re.compile(r"^\s*sa\s+duration\s+(\S+)", re.IGNORECASE)
_RE_HW_TRANSFORM = re.compile(
    r"^\s*(esp|ah)\s+(authentication-algorithm|encryption-algorithm)\s+(\S+)",
    re.IGNORECASE,
)

# ── Cisco IOS IKE ───────────────────────────────────────────────────────────────
_RE_CISCO_ISAKMP_POLICY = re.compile(
    r"^\s*crypto\s+isakmp\s+policy\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_ISAKMP_KEY = re.compile(
    r"^\s*crypto\s+isakmp\s+key\s+\S+\s+address\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_IPSEC_TRANSFORM = re.compile(
    r"^\s*crypto\s+ipsec\s+transform-set\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_CRYPTO_MAP = re.compile(
    r"^\s*crypto\s+map\s+(\S+)\s+(\S+)\s+ipsec-isakmp",
    re.IGNORECASE,
)
_RE_CISCO_IPSEC_PROFILE = re.compile(
    r"^\s*crypto\s+ipsec\s+profile\s+(\S+)", re.IGNORECASE,
)

# Cisco sub-commands
_RE_CISCO_MATCH_ADDR = re.compile(
    r"^\s*match\s+address\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_SET_PEER = re.compile(
    r"^\s*set\s+peer\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_SET_TRANSFORM = re.compile(
    r"^\s*set\s+transform-set\s+(.+)", re.IGNORECASE,
)
_RE_CISCO_SET_PFS = re.compile(
    r"^\s*set\s+pfs\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_ISAKMP_AUTH = re.compile(
    r"^\s*authentication\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_ISAKMP_ENCR = re.compile(
    r"^\s*encryption\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_ISAKMP_HASH = re.compile(
    r"^\s*hash\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_ISAKMP_GROUP = re.compile(
    r"^\s*group\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_ISAKMP_LIFETIME = re.compile(
    r"^\s*lifetime\s+(\S+)", re.IGNORECASE,
)

# ── Cisco ASA ───────────────────────────────────────────────────────────────────
_RE_ASA_IKEV1_POLICY = re.compile(
    r"^\s*crypto\s+ikev1\s+policy\s+(\S+)", re.IGNORECASE,
)
_RE_ASA_IKEV2_POLICY = re.compile(
    r"^\s*crypto\s+ikev2\s+policy\s+(\S+)", re.IGNORECASE,
)
_RE_ASA_IKEV1_KEY = re.compile(
    r"^\s*crypto\s+ikev1\s+key\s+\S+\s+address\s+(\S+)", re.IGNORECASE,
)
_RE_ASA_TUNNEL_GROUP = re.compile(
    r"^\s*tunnel-group\s+(\S+)\s+type\s+ipsec-l2l",
    re.IGNORECASE,
)
_RE_ASA_TUNNEL_ATTR = re.compile(
    r"^\s*tunnel-group\s+(\S+)\s+ipsec-attributes",
    re.IGNORECASE,
)
_RE_ASA_PSK = re.compile(
    r"^\s*ikev1\s+pre-shared-key\s+(\S+)", re.IGNORECASE,
)

# ── Vendor groups ────────────────────────────────────────────────────────────────
_HW_VENDORS = {"huawei", "h3c"}
_CISCO_VENDORS = {"cisco"}
_ASA_VENDORS = {"asa"}


class IpsecAnalyzer(FeatureAnalyzer):
    @property
    def feature_name(self) -> str:
        return "ipsec"

    def analyze(self, config_text: str, vendor: str, domain: str, platform: str) -> FeatureAnalysis:
        lines = config_text.splitlines()
        vendor_lower = vendor.lower()
        is_hw = vendor_lower in _HW_VENDORS
        is_cisco = vendor_lower in _CISCO_VENDORS
        is_asa = vendor_lower in _ASA_VENDORS

        # Quick scan: any IPsec keywords present?
        any_ipsec = any(
            "ike" in l.lower() or "ipsec" in l.lower()
            or "crypto" in l.lower()
            or "tunnel-group" in l.lower()
            for l in lines
        )
        if not any_ipsec:
            return FeatureAnalysis(
                feature="ipsec", status="skipped", risk_level="info",
                notes=["未发现 IPsec 配置"],
            )

        if not is_hw and not is_cisco and not is_asa:
            return FeatureAnalysis(
                feature="ipsec", status="skipped", risk_level="info",
                notes=[f"Vendor {vendor} not supported for IPsec analysis"],
            )

        # ── Phase 1: collect IPsec constructs ──
        ike_proposals: Dict[str, Dict] = {}
        ike_peers: Dict[str, Dict] = {}
        ipsec_proposals: Dict[str, Dict] = {}
        ipsec_policies: Dict[str, Dict] = {}
        ipsec_profiles: Dict[str, Dict] = {}
        isakmp_policies: Dict[str, Dict] = {}
        crypto_maps: Dict[str, Dict] = {}
        transform_sets: Dict[str, List[str]] = {}
        crypto_profiles: Dict[str, Dict] = {}
        asa_tunnel_groups: Dict[str, Dict] = {}
        asa_ikev1_policies: Dict[str, Dict] = {}
        asa_ikev2_policies: Dict[str, Dict] = {}

        if is_hw:
            self._parse_hw_ipsec(lines, ike_proposals, ike_peers,
                                  ipsec_proposals, ipsec_policies, ipsec_profiles)

        if is_cisco:
            self._parse_cisco_ipsec(lines, isakmp_policies, crypto_maps,
                                     transform_sets, crypto_profiles)

        if is_asa:
            self._parse_asa_ipsec(lines, asa_ikev1_policies, asa_ikev2_policies,
                                   asa_tunnel_groups)

        # ── Phase 2: build rules and check references ──
        rules: List[Dict[str, Any]] = []
        missing: List[str] = []
        source_lines: List[str] = []
        refs = {"ike_proposal": [], "ipsec_proposal": [], "transform_set": [],
                 "acl": [], "peer": [], "ike_peer": []}

        if is_hw:
            self._build_hw_rules(ipsec_policies, ipsec_profiles, ike_peers,
                                 ike_proposals, ipsec_proposals, rules, missing,
                                 source_lines, refs)

        if is_cisco:
            self._build_cisco_rules(crypto_maps, crypto_profiles, isakmp_policies,
                                     transform_sets, rules, missing,
                                     source_lines, refs)

        if is_asa:
            self._build_asa_rules(asa_tunnel_groups, asa_ikev1_policies,
                                  asa_ikev2_policies, rules, missing,
                                  source_lines, refs)

        if not rules and not ike_proposals and not isakmp_policies and not asa_ikev1_policies:
            # IPsec keywords present but no structured config found
            if is_hw:
                return FeatureAnalysis(
                    feature="ipsec", status="skipped",
                    risk_level="info",
                    notes=["包含 IPsec 关键词但未识别到完整策略结构"],
                )

        # ── Phase 3: risk ──
        has_fatal = any("peer 缺失" in m or "proposal 缺失" in m
                        or "transform-set 缺失" in m
                        or "match address" in m
                        for m in missing)

        risk = "info"
        if missing:
            risk = "warning"
        if has_fatal:
            risk = "fatal"

        return FeatureAnalysis(
            feature="ipsec",
            status="analyzed",
            risk_level=risk,
            manual_review_required=risk in ("warning", "fatal"),
            rules=rules,
            references=refs,
            missing_context=missing,
            source_lines=list(dict.fromkeys(source_lines)),
            metadata={
                "policy_count": len(ipsec_policies) + len(crypto_maps),
                "ike_policy_count": len(isakmp_policies) + len(asa_ikev1_policies),
            },
        )

    # ═══════════════════════════════════════════════════════════════════
    # Huawei/H3C parsers
    # ═══════════════════════════════════════════════════════════════════

    def _parse_hw_ipsec(self, lines, ike_proposals, ike_peers,
                        ipsec_proposals, ipsec_policies, ipsec_profiles):
        in_ike_prop: Optional[str] = None
        in_ike_peer: Optional[str] = None
        in_ipsec_prop: Optional[str] = None
        in_policy: Optional[tuple] = None
        in_profile: Optional[str] = None

        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue
            indent = len(raw) - len(raw.lstrip())

            # ── ike proposal ──
            m = _RE_HW_IKE_PROPOSAL.match(stripped)
            if m:
                in_ike_prop = m.group(1)
                ike_proposals[in_ike_prop] = {"id": in_ike_prop, "auth_algo": None,
                                               "encr_algo": None, "dh_group": None,
                                               "duration": None}
                in_ike_peer = in_ipsec_prop = in_policy = in_profile = None
                continue

            # ── ike peer ──
            m = _RE_HW_IKE_PEER.match(stripped)
            if m:
                in_ike_peer = m.group(1)
                ike_peers[in_ike_peer] = {"name": in_ike_peer, "pre_shared_key": None,
                                           "remote_address": None, "local_address": None,
                                           "ike_proposal": None, "local_id": None,
                                           "remote_id": None}
                in_ike_prop = in_ipsec_prop = in_policy = in_profile = None
                continue

            # ── ipsec proposal ──
            m = _RE_HW_IPSEC_PROPOSAL.match(stripped)
            if m:
                in_ipsec_prop = m.group(1)
                ipsec_proposals[in_ipsec_prop] = {"name": in_ipsec_prop, "esp_auth": None,
                                                   "esp_encr": None, "ah_auth": None}
                in_ike_prop = in_ike_peer = in_policy = in_profile = None
                continue

            # ── ipsec policy ──
            m = _RE_HW_IPSEC_POLICY.match(stripped)
            if m:
                pname = m.group(1)
                pseq = m.group(2)
                key = f"{pname}_{pseq}"
                in_policy = (pname, pseq)
                ipsec_policies[key] = {"name": pname, "seq": pseq,
                                        "ike_peer": None, "proposal": None,
                                        "security_acl": None, "remote_address": None,
                                        "sa_trigger": None, "pfs": None}
                in_ike_prop = in_ike_peer = in_ipsec_prop = in_profile = None
                continue

            # ── ipsec profile ──
            m = _RE_HW_IPSEC_PROFILE.match(stripped)
            if m:
                in_profile = m.group(1)
                ipsec_profiles[in_profile] = {"name": in_profile, "ike_peer": None,
                                               "proposal": None}
                in_ike_prop = in_ike_peer = in_ipsec_prop = in_policy = None
                continue

            # ── Sub-commands by context ──
            if in_ike_prop:
                mm = _RE_HW_SA_DURATION.match(stripped)
                if mm:
                    ike_proposals[in_ike_prop]["duration"] = mm.group(1)
                mm = _RE_HW_TRANSFORM.match(stripped)
                if mm:
                    proto = mm.group(1).lower()
                    attr = mm.group(2).lower()
                    val = mm.group(3)
                    if attr == "authentication-algorithm":
                        ike_proposals[in_ike_prop]["auth_algo"] = val
                    elif attr == "encryption-algorithm":
                        ike_proposals[in_ike_prop]["encr_algo"] = val
                continue

            if in_ike_peer:
                mm = _RE_HW_PSK.match(stripped)
                if mm:
                    ike_peers[in_ike_peer]["pre_shared_key"] = mm.group(1)
                mm = _RE_HW_REMOTE_ADDR.match(stripped)
                if mm:
                    ike_peers[in_ike_peer]["remote_address"] = mm.group(1)
                if re.match(r"^\s*local-address\s+(\S+)", stripped, re.IGNORECASE):
                    ike_peers[in_ike_peer]["local_address"] = \
                        re.match(r"^\s*local-address\s+(\S+)", stripped, re.IGNORECASE).group(1)
                mm = _RE_HW_PROPOSAL_REF.match(stripped)
                if mm:
                    ike_peers[in_ike_peer]["ike_proposal"] = mm.group(1)
                if re.match(r"^\s*local-id\s+(\S+)", stripped, re.IGNORECASE):
                    ike_peers[in_ike_peer]["local_id"] = \
                        re.match(r"^\s*local-id\s+(\S+)", stripped, re.IGNORECASE).group(1)
                if re.match(r"^\s*remote-id\s+(\S+)", stripped, re.IGNORECASE):
                    ike_peers[in_ike_peer]["remote_id"] = \
                        re.match(r"^\s*remote-id\s+(\S+)", stripped, re.IGNORECASE).group(1)
                continue

            if in_ipsec_prop:
                mm = _RE_HW_TRANSFORM.match(stripped)
                if mm:
                    proto = mm.group(1).lower()
                    attr = mm.group(2).lower()
                    val = mm.group(3)
                    if proto == "esp":
                        if attr == "authentication-algorithm":
                            ipsec_proposals[in_ipsec_prop]["esp_auth"] = val
                        elif attr == "encryption-algorithm":
                            ipsec_proposals[in_ipsec_prop]["esp_encr"] = val
                    elif proto == "ah":
                        ipsec_proposals[in_ipsec_prop]["ah_auth"] = val
                continue

            if in_policy:
                key = f"{in_policy[0]}_{in_policy[1]}"
                mm = _RE_HW_SECURITY_ACL.match(stripped)
                if mm:
                    ipsec_policies[key]["security_acl"] = mm.group(1)
                mm = _RE_HW_IKE_PEER_REF.match(stripped)
                if mm:
                    ipsec_policies[key]["ike_peer"] = mm.group(1)
                mm = _RE_HW_PROPOSAL_REF.match(stripped)
                if mm:
                    ipsec_policies[key]["proposal"] = mm.group(1)
                mm = _RE_HW_REMOTE_ADDR.match(stripped)
                if mm:
                    ipsec_policies[key]["remote_address"] = mm.group(1)
                if re.match(r"^\s*sa\s+trigger-mode\s+(\S+)", stripped, re.IGNORECASE):
                    ipsec_policies[key]["sa_trigger"] = \
                        re.match(r"^\s*sa\s+trigger-mode\s+(\S+)", stripped, re.IGNORECASE).group(1)
                if re.match(r"^\s*pfs\s+(\S+)", stripped, re.IGNORECASE):
                    ipsec_policies[key]["pfs"] = \
                        re.match(r"^\s*pfs\s+(\S+)", stripped, re.IGNORECASE).group(1)
                continue

            if in_profile:
                mm = _RE_HW_IKE_PEER_REF.match(stripped)
                if mm:
                    ipsec_profiles[in_profile]["ike_peer"] = mm.group(1)
                mm = _RE_HW_PROPOSAL_REF.match(stripped)
                if mm:
                    ipsec_profiles[in_profile]["proposal"] = mm.group(1)
                continue

    # ═══════════════════════════════════════════════════════════════════
    # Cisco IOS parsers
    # ═══════════════════════════════════════════════════════════════════

    def _parse_cisco_ipsec(self, lines, isakmp_policies, crypto_maps,
                           transform_sets, crypto_profiles):
        in_isakmp: Optional[str] = None
        in_crypto_map: Optional[tuple] = None
        in_crypto_profile: Optional[str] = None

        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue

            m = _RE_CISCO_ISAKMP_POLICY.match(stripped)
            if m:
                pid = m.group(1)
                in_isakmp = pid
                isakmp_policies[pid] = {"id": pid, "encryption": None, "hash": None,
                                         "auth": None, "group": None, "lifetime": None}
                in_crypto_map = in_crypto_profile = None
                continue

            m = _RE_CISCO_CRYPTO_MAP.match(stripped)
            if m:
                mname = m.group(1)
                mseq = m.group(2)
                key = f"{mname}_{mseq}"
                in_crypto_map = (mname, mseq)
                crypto_maps[key] = {"name": mname, "seq": mseq,
                                     "match_address": None, "set_peer": [],
                                     "set_transform": None, "pfs": None,
                                     "lifetime": None, "isakmp_profile": None}
                in_isakmp = in_crypto_profile = None
                continue

            m = _RE_CISCO_IPSEC_TRANSFORM.match(stripped)
            if m:
                tname = m.group(1)
                rest = stripped[m.end():].strip()
                transform_sets[tname] = rest.split() if rest else []
                continue

            m = _RE_CISCO_IPSEC_PROFILE.match(stripped)
            if m:
                in_crypto_profile = m.group(1)
                crypto_profiles[in_crypto_profile] = {"name": in_crypto_profile,
                                                       "transform_set": None,
                                                       "match_address": None,
                                                       "isakmp_profile": None}
                in_isakmp = in_crypto_map = None
                continue

            # Sub-commands
            if in_isakmp:
                mm = _RE_CISCO_ISAKMP_ENCR.match(stripped)
                if mm:
                    isakmp_policies[in_isakmp]["encryption"] = mm.group(1)
                mm = _RE_CISCO_ISAKMP_HASH.match(stripped)
                if mm:
                    isakmp_policies[in_isakmp]["hash"] = mm.group(1)
                mm = _RE_CISCO_ISAKMP_AUTH.match(stripped)
                if mm:
                    isakmp_policies[in_isakmp]["auth"] = mm.group(1)
                mm = _RE_CISCO_ISAKMP_GROUP.match(stripped)
                if mm:
                    isakmp_policies[in_isakmp]["group"] = mm.group(1)
                mm = _RE_CISCO_ISAKMP_LIFETIME.match(stripped)
                if mm:
                    isakmp_policies[in_isakmp]["lifetime"] = mm.group(1)
                continue

            if in_crypto_map:
                key = f"{in_crypto_map[0]}_{in_crypto_map[1]}"
                mm = _RE_CISCO_MATCH_ADDR.match(stripped)
                if mm:
                    crypto_maps[key]["match_address"] = mm.group(1)
                mm = _RE_CISCO_SET_PEER.match(stripped)
                if mm:
                    crypto_maps[key]["set_peer"].append(mm.group(1))
                mm = _RE_CISCO_SET_TRANSFORM.match(stripped)
                if mm:
                    crypto_maps[key]["set_transform"] = mm.group(1).strip()
                mm = _RE_CISCO_SET_PFS.match(stripped)
                if mm:
                    crypto_maps[key]["pfs"] = mm.group(1)
                mm = _RE_CISCO_ISAKMP_LIFETIME.match(stripped)
                if mm:
                    crypto_maps[key]["lifetime"] = mm.group(1)
                continue

            if in_crypto_profile:
                mm = _RE_CISCO_SET_TRANSFORM.match(stripped)
                if mm:
                    crypto_profiles[in_crypto_profile]["transform_set"] = mm.group(1).strip()
                mm = _RE_CISCO_MATCH_ADDR.match(stripped)
                if mm:
                    crypto_profiles[in_crypto_profile]["match_address"] = mm.group(1)
                continue

    # ═══════════════════════════════════════════════════════════════════
    # Cisco ASA parsers
    # ═══════════════════════════════════════════════════════════════════

    def _parse_asa_ipsec(self, lines, asa_ikev1_policies, asa_ikev2_policies,
                         asa_tunnel_groups):
        current_tunnel: Optional[str] = None

        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue

            m = _RE_ASA_IKEV1_POLICY.match(stripped)
            if m:
                pid = m.group(1)
                asa_ikev1_policies[pid] = {"id": pid}
                continue

            m = _RE_ASA_IKEV2_POLICY.match(stripped)
            if m:
                pid = m.group(1)
                asa_ikev2_policies[pid] = {"id": pid}
                continue

            m = _RE_ASA_TUNNEL_GROUP.match(stripped)
            if m:
                current_tunnel = m.group(1)
                asa_tunnel_groups[current_tunnel] = {
                    "name": current_tunnel, "psk": None,
                    "ikev1_policy": None, "ikev2_policy": None,
                    "peer_id_validate": None,
                }
                continue

            m = _RE_ASA_TUNNEL_ATTR.match(stripped)
            if m:
                current_tunnel = m.group(1)
                if current_tunnel not in asa_tunnel_groups:
                    asa_tunnel_groups[current_tunnel] = {
                        "name": current_tunnel, "psk": None,
                        "ikev1_policy": None, "ikev2_policy": None,
                        "peer_id_validate": None,
                    }
                continue

            if current_tunnel and current_tunnel in asa_tunnel_groups:
                mm = _RE_ASA_PSK.match(stripped)
                if mm:
                    asa_tunnel_groups[current_tunnel]["psk"] = mm.group(1)
                    continue
                if re.match(r"^\s*peer-id-validate\s+(\S+)", stripped, re.IGNORECASE):
                    asa_tunnel_groups[current_tunnel]["peer_id_validate"] = \
                        re.match(r"^\s*peer-id-validate\s+(\S+)", stripped, re.IGNORECASE).group(1)

    # ═══════════════════════════════════════════════════════════════════
    # Rule builders
    # ═══════════════════════════════════════════════════════════════════

    def _build_hw_rules(self, ipsec_policies, ipsec_profiles, ike_peers,
                        ike_proposals, ipsec_proposals, rules, missing,
                        source_lines, refs):
        for key, pol in ipsec_policies.items():
            acl_name = pol.get("security_acl")
            ike_peer_name = pol.get("ike_peer")
            proposal_name = pol.get("proposal")
            peer_addr = pol.get("remote_address")

            if acl_name:
                refs["acl"].append(acl_name)
            if ike_peer_name:
                refs["ike_peer"].append(ike_peer_name)
            if proposal_name:
                refs["ipsec_proposal"].append(proposal_name)
            if peer_addr:
                refs["peer"].append(peer_addr)

            if not acl_name:
                missing.append(f"IPsec policy {pol['name']} seq {pol['seq']}: security acl 缺失——fatal")
            if not ike_peer_name and not proposal_name:
                missing.append(f"IPsec policy {pol['name']} seq {pol['seq']}: IKE peer / proposal 缺失——fatal")
            if ike_peer_name and ike_peer_name not in ike_peers:
                missing.append(f"IKE peer {ike_peer_name} 被引用但未定义")
            if proposal_name and proposal_name not in ipsec_proposals:
                missing.append(f"IPsec proposal {proposal_name} 被引用但未定义")

            # Check PSK in referenced IKE peer
            if ike_peer_name and ike_peer_name in ike_peers:
                peer_data = ike_peers[ike_peer_name]
                if not peer_data.get("pre_shared_key"):
                    missing.append(f"IKE peer {ike_peer_name}: pre-shared-key 缺失或隐藏")
                if not peer_data.get("remote_address"):
                    missing.append(f"IKE peer {ike_peer_name}: remote-address 缺失")

            rules.append({
                "policy_name": f"{pol['name']} seq {pol['seq']}",
                "type": "ipsec_policy",
                "ike_peer": ike_peer_name,
                "ipsec_proposal": proposal_name,
                "security_acl": acl_name,
                "peer": peer_addr,
                "auth_method": "pre_shared_key" if (ike_peer_name and
                                                     ike_peers.get(ike_peer_name, {}).get("pre_shared_key")) else None,
                "source_lines": [],
            })

        for name, prof in ipsec_profiles.items():
            ike_peer_name = prof.get("ike_peer")
            proposal_name = prof.get("proposal")
            if ike_peer_name:
                refs["ike_peer"].append(ike_peer_name)
            if proposal_name:
                refs["ipsec_proposal"].append(proposal_name)
            if ike_peer_name and ike_peer_name not in ike_peers:
                missing.append(f"IKE peer {ike_peer_name} 被引用但未定义")

    def _build_cisco_rules(self, crypto_maps, crypto_profiles, isakmp_policies,
                           transform_sets, rules, missing, source_lines, refs):
        for key, cm in crypto_maps.items():
            match_addr = cm.get("match_address")
            peers = cm.get("set_peer", [])
            transform = cm.get("set_transform")
            pfs = cm.get("pfs")

            if match_addr:
                refs["acl"].append(match_addr)
            for p in peers:
                refs["peer"].append(p)
            if transform:
                refs["transform_set"].append(transform)

            if not match_addr:
                missing.append(f"Crypto map {cm['name']} seq {cm['seq']}: match address 缺失——fatal")
            if not transform:
                missing.append(f"Crypto map {cm['name']} seq {cm['seq']}: transform-set 缺失——fatal")
            if not peers:
                missing.append(f"Crypto map {cm['name']} seq {cm['seq']}: set peer 缺失——fatal")
            if transform and transform not in transform_sets:
                missing.append(f"Transform-set {transform} 被引用但未定义")

            rules.append({
                "policy_name": f"{cm['name']} seq {cm['seq']}",
                "type": "crypto_map",
                "match_address": match_addr,
                "set_peer": peers,
                "transform_set": transform,
                "pfs": pfs,
                "source_lines": [],
            })

        for name, cp in crypto_profiles.items():
            transform = cp.get("transform_set")
            match_addr = cp.get("match_address")
            if transform:
                refs["transform_set"].append(transform)
            if match_addr:
                refs["acl"].append(match_addr)
            if not transform:
                missing.append(f"Crypto profile {name}: transform-set 缺失——fatal")
            if transform and transform not in transform_sets:
                missing.append(f"Transform-set {transform} 被引用但未定义")

    def _build_asa_rules(self, asa_tunnel_groups, asa_ikev1_policies,
                         asa_ikev2_policies, rules, missing, source_lines, refs):
        for name, tg in asa_tunnel_groups.items():
            if not tg.get("psk"):
                missing.append(f"Tunnel-group {name}: pre-shared-key 缺失或隐藏")
            rules.append({
                "policy_name": name,
                "type": "tunnel_group",
                "ike_version": "ikev1" if name in asa_ikev1_policies else None,
                "pre_shared_key": "hidden" if tg.get("psk") else "missing",
                "source_lines": [],
            })
