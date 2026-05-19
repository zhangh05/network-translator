from __future__ import annotations
import re
from typing import Any, Dict, List, Optional

from core.analyzers.base import FeatureAnalysis, FeatureAnalyzer


# ── Huawei / H3C ──────────────────────────────────────────────────
_RE_HW_TUNNEL_IF = re.compile(
    r"^\s*interface\s+Tunnel\S*", re.IGNORECASE,
)
_RE_HW_TUNNEL_PROTO = re.compile(
    r"^\s*tunnel-protocol\s+(\S+)", re.IGNORECASE,
)
_RE_HW_TUNNEL_SRC = re.compile(
    r"^\s*source\s+(\S+)", re.IGNORECASE,
)
_RE_HW_TUNNEL_DST = re.compile(
    r"^\s*destination\s+(\S+)", re.IGNORECASE,
)
_RE_HW_GRE_KEY = re.compile(
    r"^\s*gre\s+key\s+(\S+)", re.IGNORECASE,
)
_RE_HW_KEEPALIVE = re.compile(
    r"^\s*keepalive", re.IGNORECASE,
)
_RE_HW_IP_ADDR = re.compile(
    r"^\s*ip\s+address\s+(\S+)\s+(\S+)", re.IGNORECASE,
)
_RE_HW_BIND_VPN = re.compile(
    r"^\s*ip\s+binding\s+vpn-instance\s+(\S+)", re.IGNORECASE,
)

# ── Cisco ─────────────────────────────────────────────────────────
_RE_CISCO_TUNNEL_IF = re.compile(
    r"^\s*interface\s+Tunnel\S*", re.IGNORECASE,
)
_RE_CISCO_TUNNEL_MODE = re.compile(
    r"^\s*tunnel\s+mode\s+(\S+)\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_TUNNEL_MODE_SINGLE = re.compile(
    r"^\s*tunnel\s+mode\s+(\S+)\s*", re.IGNORECASE,
)
_RE_CISCO_TUNNEL_SRC = re.compile(
    r"^\s*tunnel\s+source\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_TUNNEL_DST = re.compile(
    r"^\s*tunnel\s+destination\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_TUNNEL_KEY = re.compile(
    r"^\s*tunnel\s+key\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_KEEPALIVE = re.compile(
    r"^\s*keepalive", re.IGNORECASE,
)
_RE_CISCO_IP_ADDR = re.compile(
    r"^\s*ip\s+address\s+(\S+)\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_TUNNEL_VRF = re.compile(
    r"^\s*tunnel\s+vrf\s+(\S+)", re.IGNORECASE,
)
_RE_CISCO_VRF_FORWARDING = re.compile(
    r"^\s*vrf\s+forwarding\s+(\S+)", re.IGNORECASE,
)

_RE_INTERFACE = re.compile(
    r"^\s*interface\s+(\S+)", re.IGNORECASE,
)

_HW_VENDORS = {"huawei", "h3c"}
_CISCO_VENDORS = {"cisco"}

GRE_LIKE_MODES = {"gre", "gre-ip", "ipip"}


class TunnelAnalyzer(FeatureAnalyzer):
    @property
    def feature_name(self) -> str:
        return "tunnel"

    def analyze(self, config_text: str, vendor: str, domain: str, platform: str) -> FeatureAnalysis:
        lines = config_text.splitlines()
        vendor_lower = vendor.lower()
        is_hw = vendor_lower in _HW_VENDORS
        is_cisco = vendor_lower in _CISCO_VENDORS

        if not is_hw and not is_cisco:
            return FeatureAnalysis(
                feature="tunnel", status="skipped", risk_level="info",
                notes=[f"Vendor {vendor} not supported"],
            )

        if not any("Tunnel" in l for l in lines):
            return FeatureAnalysis(
                feature="tunnel", status="skipped", risk_level="info",
                notes=["未发现 Tunnel 接口配置"],
            )

        tunnels: List[Dict] = []
        refs: Dict[str, List[str]] = {"vrf": [], "source_interface": []}
        missing: List[str] = []

        if is_hw:
            self._parse_hw(lines, tunnels, refs, missing)
        if is_cisco:
            self._parse_cisco(lines, tunnels, refs, missing)

        if not tunnels:
            return FeatureAnalysis(
                feature="tunnel", status="skipped", risk_level="info",
                notes=["包含 Tunnel 关键词但未识别到有效定义"],
            )

        has_fatal = any("fatal" in m for m in missing)
        risk = "info"
        if missing:
            risk = "warning"
        if has_fatal:
            risk = "fatal"

        return FeatureAnalysis(
            feature="tunnel",
            status="analyzed",
            risk_level=risk,
            manual_review_required=risk in ("warning", "fatal"),
            rules=tunnels,
            references=refs,
            missing_context=missing,
            source_lines=[],
            notes=[],
        )

    def _parse_hw(self, lines, tunnels, refs, missing):
        current_tunnel: Optional[Dict] = None
        in_tunnel = False

        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue

            m = _RE_HW_TUNNEL_IF.match(stripped)
            if m:
                if current_tunnel is not None:
                    self._finalize_tunnel(current_tunnel, tunnels, refs, missing)
                current_tunnel = {
                    "interface": m.group(0).split(None, 1)[1],
                    "tunnel_type": "unknown",
                    "source": "", "destination": "",
                    "ip_address": "", "vrf": "",
                    "key": "", "keepalive": False,
                }
                in_tunnel = True
                continue

            if not in_tunnel or current_tunnel is None:
                m = _RE_HW_BIND_VPN.match(stripped)
                if m and current_tunnel is not None:
                    current_tunnel["vrf"] = m.group(1)
                    refs.setdefault("vrf", []).append(m.group(1))
                continue

            # ── Inside tunnel interface ──
            mm = _RE_HW_TUNNEL_PROTO.match(stripped)
            if mm:
                proto = mm.group(1).lower()
                if proto == "gre":
                    current_tunnel["tunnel_type"] = "gre"
                elif proto == "ipsec":
                    current_tunnel["tunnel_type"] = "ipsec"
                    missing.append(
                        f"Tunnel {current_tunnel['interface']} 使用 tunnel-protocol ipsec，"
                        f"建议用 IpsecAnalyzer 进一步确认——warning"
                    )
                else:
                    current_tunnel["tunnel_type"] = proto
                continue

            mm = _RE_HW_TUNNEL_SRC.match(stripped)
            if mm:
                src = mm.group(1)
                current_tunnel["source"] = src
                if src.lower().startswith(("gigabitethernet", "ethernet", "ge", "eth", "vlanif", "loopback", "tunnel", "serial", "pos", "multigiga", "xge")):
                    refs.setdefault("source_interface", []).append(src)
                continue

            mm = _RE_HW_TUNNEL_DST.match(stripped)
            if mm:
                current_tunnel["destination"] = mm.group(1)
                continue

            mm = _RE_HW_IP_ADDR.match(stripped)
            if mm:
                current_tunnel["ip_address"] = f"{mm.group(1)}/{mm.group(2)}"
                continue

            mm = _RE_HW_GRE_KEY.match(stripped)
            if mm:
                current_tunnel["key"] = mm.group(1)
                continue

            mm = _RE_HW_KEEPALIVE.match(stripped)
            if mm:
                current_tunnel["keepalive"] = True
                continue

            mm = _RE_HW_BIND_VPN.match(stripped)
            if mm:
                current_tunnel["vrf"] = mm.group(1)
                refs.setdefault("vrf", []).append(mm.group(1))
                continue

            # Exit tunnel: interface or top-level command at indent 0
            if stripped[0].isalpha() and raw[0].strip() and len(raw) - len(raw.lstrip()) == 0:
                self._finalize_tunnel(current_tunnel, tunnels, refs, missing)
                current_tunnel = None
                in_tunnel = False

        if current_tunnel is not None:
            self._finalize_tunnel(current_tunnel, tunnels, refs, missing)

    def _parse_cisco(self, lines, tunnels, refs, missing):
        current_tunnel: Optional[Dict] = None
        in_tunnel = False

        for raw in lines:
            stripped = raw.strip()
            if not stripped:
                continue

            m = _RE_CISCO_TUNNEL_IF.match(stripped)
            if m:
                if current_tunnel is not None:
                    self._finalize_tunnel(current_tunnel, tunnels, refs, missing)
                current_tunnel = {
                    "interface": m.group(0).split(None, 1)[1],
                    "tunnel_type": "unknown",
                    "source": "", "destination": "",
                    "ip_address": "", "vrf": "",
                    "key": "", "keepalive": False,
                }
                in_tunnel = True
                continue

            if not in_tunnel or current_tunnel is None:
                continue

            mm = _RE_CISCO_TUNNEL_MODE.match(stripped)
            if mm:
                t1 = mm.group(1).lower()
                t2 = mm.group(2).lower()
                combined = f"{t1} {t2}"
                if combined in GRE_LIKE_MODES or combined == "gre ip":
                    current_tunnel["tunnel_type"] = "gre"
                elif combined == "ipip":
                    current_tunnel["tunnel_type"] = "ipip"
                else:
                    current_tunnel["tunnel_type"] = combined
                continue
            mm = _RE_CISCO_TUNNEL_MODE_SINGLE.match(stripped)
            if mm:
                mode = mm.group(1).lower()
                if mode in ("gre", "ipip"):
                    current_tunnel["tunnel_type"] = mode
                else:
                    current_tunnel["tunnel_type"] = mode
                continue

            mm = _RE_CISCO_TUNNEL_SRC.match(stripped)
            if mm:
                src = mm.group(1)
                current_tunnel["source"] = src
                if src.lower().startswith(("gigabitethernet", "ethernet", "ge", "eth", "vlan", "loopback", "tunnel", "serial", "pos", "multigiga", "xge")):
                    refs.setdefault("source_interface", []).append(src)
                continue

            mm = _RE_CISCO_TUNNEL_DST.match(stripped)
            if mm:
                current_tunnel["destination"] = mm.group(1)
                continue

            mm = _RE_CISCO_IP_ADDR.match(stripped)
            if mm:
                current_tunnel["ip_address"] = f"{mm.group(1)}/{mm.group(2)}"
                continue

            mm = _RE_CISCO_TUNNEL_KEY.match(stripped)
            if mm:
                current_tunnel["key"] = mm.group(1)
                continue

            mm = _RE_CISCO_KEEPALIVE.match(stripped)
            if mm:
                current_tunnel["keepalive"] = True
                continue

            mm = _RE_CISCO_TUNNEL_VRF.match(stripped)
            if mm:
                current_tunnel["vrf"] = mm.group(1)
                refs.setdefault("vrf", []).append(mm.group(1))
                continue

            mm = _RE_CISCO_VRF_FORWARDING.match(stripped)
            if mm:
                current_tunnel["vrf"] = mm.group(1)
                refs.setdefault("vrf", []).append(mm.group(1))
                continue

            if stripped[0].isalpha() and raw[0].strip() and len(raw) - len(raw.lstrip()) == 0:
                self._finalize_tunnel(current_tunnel, tunnels, refs, missing)
                current_tunnel = None
                in_tunnel = False

        if current_tunnel is not None:
            self._finalize_tunnel(current_tunnel, tunnels, refs, missing)

    @staticmethod
    def _finalize_tunnel(t, tunnels, refs, missing):
        if not t["source"]:
            missing.append(f"Tunnel {t['interface']} 缺少 source——fatal")
        if not t["destination"]:
            missing.append(f"Tunnel {t['interface']} 缺少 destination——fatal")
        tunnels.append(dict(t))
