from __future__ import annotations
import re
from typing import Any, Dict, List, Optional

from core.analyzers.base import FeatureAnalysis, FeatureAnalyzer


# ── Huawei / H3C ──────────────────────────────────────────────────
_RE_HW_BFD_GLOBAL = re.compile(
    r"^\s*bfd\s*$", re.IGNORECASE,
)
_RE_HW_BFD_SESSION = re.compile(
    r"^\s*bfd\s+(\S+)\s+bind\s+peer-ip\s+(\S+)", re.IGNORECASE,
)
_RE_HW_BFD_SESSION_NO_PEER = re.compile(
    r"^\s*bfd\s+(\S+)\s+bind\s+peer-ip\s*$", re.IGNORECASE,
)
_RE_HW_BFD_SOURCE = re.compile(
    r"^\s*bind\s+source-ip\s+(\S+)", re.IGNORECASE,
)
_RE_HW_DISCR_LOCAL = re.compile(
    r"^\s*discriminator\s+local\s+(\S+)", re.IGNORECASE,
)
_RE_HW_DISCR_REMOTE = re.compile(
    r"^\s*discriminator\s+remote\s+(\S+)", re.IGNORECASE,
)
_RE_HW_MIN_TX = re.compile(
    r"^\s*min-tx-interval\s+(\S+)", re.IGNORECASE,
)
_RE_HW_MIN_RX = re.compile(
    r"^\s*min-rx-interval\s+(\S+)", re.IGNORECASE,
)
_RE_HW_MULTIPLIER = re.compile(
    r"^\s*detect-multiplier\s+(\S+)", re.IGNORECASE,
)
_RE_HW_OSPF_BFD = re.compile(
    r"^\s*ospf\s+bfd\s+enable", re.IGNORECASE,
)
_RE_HW_OSPF_BFD_BLOCK = re.compile(
    r"^\s*bfd\s+enable", re.IGNORECASE,
)
_RE_HW_BGP_BFD = re.compile(
    r"^\s*bgp\s+(\S+)\s+bfd", re.IGNORECASE,
)
_RE_HW_PEER_BFD = re.compile(
    r"^\s*peer\s+(\S+)\s+bfd", re.IGNORECASE,
)
_RE_HW_STATIC_BFD = re.compile(
    r"^\s*static-route\s+bfd", re.IGNORECASE,
)
_RE_HW_TRACK_BFD = re.compile(
    r"^\s*track\s+bfd", re.IGNORECASE,
)
_RE_HW_IF_BFD = re.compile(
    r"^\s*interface\s+(\S+)", re.IGNORECASE,
)

# ── Cisco ─────────────────────────────────────────────────────────
_RE_CISCO_IF_BFD = re.compile(
    r"^\s*bfd\s+interval\s+(\S+)\s+min_rx\s+(\S+)\s+multiplier\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_BFD_TEMPLATE = re.compile(
    r"^\s*bfd-template\s+(\S+)\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_BFD_FAST = re.compile(
    r"^\s*bfd\s+fast-detect", re.IGNORECASE,
)
_RE_CISCO_OSPF_BFD = re.compile(
    r"^\s*ip\s+ospf\s+bfd", re.IGNORECASE,
)
_RE_CISCO_BGP_FALL = re.compile(
    r"^\s*neighbor\s+(\S+)\s+fall-over\s+bfd", re.IGNORECASE,
)
_RE_CISCO_BGP_BFD = re.compile(
    r"^\s*neighbor\s+(\S+)\s+bfd", re.IGNORECASE,
)
_RE_CISCO_IF = re.compile(
    r"^\s*interface\s+(\S+)", re.IGNORECASE,
)

_HW_VENDORS = {"huawei", "h3c"}
_CISCO_VENDORS = {"cisco"}


class BfdAnalyzer(FeatureAnalyzer):
    @property
    def feature_name(self) -> str:
        return "bfd"

    def analyze(self, config_text: str, vendor: str, domain: str, platform: str) -> FeatureAnalysis:
        lines = config_text.splitlines()
        vendor_lower = vendor.lower()
        is_hw = vendor_lower in _HW_VENDORS
        is_cisco = vendor_lower in _CISCO_VENDORS

        if not is_hw and not is_cisco:
            return FeatureAnalysis(
                feature="bfd", status="skipped", risk_level="info",
                notes=[f"Vendor {vendor} not supported"],
            )

        if not self._has_bfd_content(lines):
            return FeatureAnalysis(
                feature="bfd", status="skipped", risk_level="info",
                notes=["未发现 BFD 相关配置"],
            )

        sessions: List[Dict] = []
        refs: Dict[str, List[str]] = {"peer_ip": [], "protocols": []}
        missing: List[str] = []
        protocol_refs: List[str] = []

        if is_hw:
            self._parse_hw(lines, sessions, refs, missing, protocol_refs)
        if is_cisco:
            self._parse_cisco(lines, sessions, refs, missing, protocol_refs)

        risk = "info"
        has_fatal = any("fatal" in m for m in missing)

        if missing and not has_fatal:
            risk = "warning"

        if not sessions and protocol_refs and not has_fatal:
            risk = "warning"
            missing.append("BFD 被协议引用但未检测到 session 定义——warning")

        if has_fatal:
            risk = "fatal"

        return FeatureAnalysis(
            feature="bfd",
            status="analyzed" if (sessions or protocol_refs or has_fatal) else "skipped",
            risk_level=risk,
            manual_review_required=risk in ("warning", "fatal"),
            rules=sessions,
            references=refs,
            missing_context=missing,
            source_lines=[],
            notes=[],
        )

    def _has_bfd_content(self, lines) -> bool:
        keywords = ["bfd", "BFD"]
        for l in lines:
            ll = l.strip()
            if not ll:
                continue
            if "bfd" in ll.lower():
                return True
        return False

    def _parse_hw(self, lines, sessions, refs, missing, protocol_refs):
        current_session: Optional[Dict] = None
        in_bfd_session = False
        current_if: Optional[str] = None
        current_proto: Optional[str] = None
        _RE_PROTO = re.compile(r"^\s*(ospf|bgp|isis)\s", re.IGNORECASE)
        _RE_PROTO_END = re.compile(r"^\s*[a-z#!]", re.IGNORECASE)

        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue

            if not raw.startswith(" ") and stripped[0].isalpha():
                pm = _RE_PROTO.match(stripped)
                if pm:
                    current_proto = pm.group(1).lower()
                else:
                    current_proto = None

            # ── BFD session definition ──
            m = _RE_HW_BFD_SESSION.match(stripped)
            if m:
                if current_session is not None:
                    self._finalize_hw_session(current_session, sessions, refs, missing)
                name, peer = m.group(1), m.group(2)
                current_session = {
                    "session_name": name,
                    "peer_ip": peer,
                    "source_ip": "",
                    "local_discriminator": "",
                    "remote_discriminator": "",
                    "min_tx": "",
                    "min_rx": "",
                    "multiplier": "",
                    "binding": {},
                }
                in_bfd_session = True
                refs["peer_ip"].append(peer)
                continue

            m = _RE_HW_BFD_SESSION_NO_PEER.match(stripped)
            if m:
                if current_session is not None:
                    self._finalize_hw_session(current_session, sessions, refs, missing)
                current_session = {
                    "session_name": m.group(1),
                    "peer_ip": "",
                    "source_ip": "",
                    "local_discriminator": "",
                    "remote_discriminator": "",
                    "min_tx": "",
                    "min_rx": "",
                    "multiplier": "",
                    "binding": {},
                }
                in_bfd_session = True
                continue

            # ── BFD global enable ──
            if _RE_HW_BFD_GLOBAL.match(stripped):
                continue

            if not in_bfd_session or current_session is None:
                self._collect_hw_refs(stripped, refs, missing, protocol_refs, current_if, current_proto)
                m = _RE_HW_IF_BFD.match(stripped)
                if m:
                    current_if = m.group(1)
                continue

            # ── Inside BFD session ──
            mm = _RE_HW_DISCR_LOCAL.match(stripped)
            if mm:
                current_session["local_discriminator"] = mm.group(1)
                continue

            mm = _RE_HW_DISCR_REMOTE.match(stripped)
            if mm:
                current_session["remote_discriminator"] = mm.group(1)
                continue

            mm = _RE_HW_BFD_SOURCE.match(stripped)
            if mm:
                current_session["source_ip"] = mm.group(1)
                continue

            mm = _RE_HW_MIN_TX.match(stripped)
            if mm:
                current_session["min_tx"] = mm.group(1)
                continue

            mm = _RE_HW_MIN_RX.match(stripped)
            if mm:
                current_session["min_rx"] = mm.group(1)
                continue

            mm = _RE_HW_MULTIPLIER.match(stripped)
            if mm:
                current_session["multiplier"] = mm.group(1)
                continue

            # Exit BFD view — top-level command
            if not raw.startswith(" ") and stripped[0].isalpha() and "bfd" not in stripped.lower():
                self._finalize_hw_session(current_session, sessions, refs, missing)
                current_session = None
                in_bfd_session = False
                self._collect_hw_refs(stripped, refs, missing, protocol_refs, current_if, current_proto)
                continue

        if current_session is not None:
            self._finalize_hw_session(current_session, sessions, refs, missing)

    def _collect_hw_refs(self, stripped, refs, missing, protocol_refs, current_if, current_proto=None):
        if _RE_HW_OSPF_BFD.match(stripped):
            protocol_refs.append("ospf (bfd enable)")
            refs.setdefault("protocols", []).append("ospf")
            return

        if _RE_HW_OSPF_BFD_BLOCK.match(stripped) and current_proto == "ospf":
            protocol_refs.append("ospf bfd enable")
            refs.setdefault("protocols", []).append("ospf")
            return

        m = _RE_HW_PEER_BFD.match(stripped)
        if m:
            target = m.group(1)
            protocol_refs.append(f"bgp peer {target} bfd")
            refs.setdefault("protocols", []).append("bgp")
            refs["peer_ip"].append(target)
            return

        m = _RE_HW_BGP_BFD.match(stripped)
        if m:
            target = m.group(1)
            protocol_refs.append(f"bgp {target} bfd")
            refs.setdefault("protocols", []).append("bgp")
            refs["peer_ip"].append(target)
            return

        if _RE_HW_STATIC_BFD.match(stripped):
            protocol_refs.append("static-route bfd")
            refs.setdefault("protocols", []).append("static_route")
            return

        if _RE_HW_TRACK_BFD.match(stripped):
            protocol_refs.append("track bfd")
            refs.setdefault("protocols", []).append("track")
            return

    def _finalize_hw_session(self, s, sessions, refs, missing):
        if not s["session_name"]:
            return
        if not s["peer_ip"]:
            missing.append(f"BFD session {s['session_name']} 缺少 peer-ip——fatal")
        else:
            refs.setdefault("peer_ip", []).append(s["peer_ip"])
        if not s["local_discriminator"] and not s["remote_discriminator"]:
            missing.append(f"BFD session {s['session_name']} 未配置 discriminator——warning")
        sessions.append(dict(s))

    def _parse_cisco(self, lines, sessions, refs, missing, protocol_refs):
        current_if: Optional[str] = None
        current_template: Optional[Dict] = None
        in_template = False

        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue

            # ── Template ──
            m = _RE_CISCO_BFD_TEMPLATE.match(stripped)
            if m:
                if current_template is not None:
                    sessions.append(dict(current_template))
                current_template = {
                    "session_name": f"bfd-template {m.group(1)} {m.group(2)}",
                    "peer_ip": "",
                    "local_discriminator": "",
                    "remote_discriminator": "",
                    "min_tx": "",
                    "min_rx": "",
                    "multiplier": "",
                    "binding": {},
                }
                in_template = True
                continue

            # ── Interface BFD ──
            m = _RE_CISCO_IF.match(stripped)
            if m:
                current_if = m.group(1)
                continue

            m = _RE_CISCO_IF_BFD.match(stripped)
            if m:
                sessions.append({
                    "session_name": f"interface {current_if}" if current_if else "unknown-interface",
                    "peer_ip": "",
                    "local_discriminator": "",
                    "remote_discriminator": "",
                    "min_tx": m.group(1),
                    "min_rx": m.group(2),
                    "multiplier": m.group(3),
                    "binding": {"protocol": "interface", "target": current_if or "unknown"},
                })
                continue

            m = _RE_CISCO_BFD_FAST.match(stripped)
            if m and current_if:
                sessions.append({
                    "session_name": f"interface {current_if} fast-detect",
                    "peer_ip": "",
                    "local_discriminator": "",
                    "remote_discriminator": "",
                    "min_tx": "", "min_rx": "", "multiplier": "",
                    "binding": {"protocol": "interface", "target": current_if or "unknown"},
                })
                continue

            # ── Protocol references ──
            mm = _RE_CISCO_OSPF_BFD.match(stripped)
            if mm:
                protocol_refs.append("ip ospf bfd")
                refs.setdefault("protocols", []).append("ospf")
                continue

            mm = _RE_CISCO_BGP_FALL.match(stripped)
            if mm:
                target = mm.group(1)
                protocol_refs.append(f"neighbor {target} fall-over bfd")
                refs.setdefault("protocols", []).append("bgp")
                refs["peer_ip"].append(target)
                continue

            mm = _RE_CISCO_BGP_BFD.match(stripped)
            if mm:
                target = mm.group(1)
                protocol_refs.append(f"neighbor {target} bfd (fall-over)")
                refs.setdefault("protocols", []).append("bgp")
                refs["peer_ip"].append(target)
                continue

            if in_template and current_template is not None:
                if not stripped.startswith(" ") and "bfd" not in stripped.lower()[:5]:
                    sessions.append(dict(current_template))
                    current_template = None
                    in_template = False

        if current_template is not None:
            sessions.append(dict(current_template))
