# -*- coding: utf-8 -*-
"""
Tools 模块 - 网络配置翻译专用的执行工具
- ConfigParser: 结构化解析配置文件
- ConfigDiffer: 对比原文/译文差异
- ConfigValidator: 语法校验
- KnowledgeRetriever: 从知识库检索相关配置参考
"""

import re
import json
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from pathlib import Path


# ============================================================================
# 数据结构
# ============================================================================

@dataclass
class ParsedInterface:
    """解析后的接口"""
    name: str
    raw_lines: List[str]
    has_ip: bool = False
    has_shutdown: bool = False
    description: Optional[str] = None
    vlan: Optional[int] = None
    trunk_vlans: Optional[str] = None


@dataclass
class ParsedConfig:
    """解析后的完整配置"""
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    version: Optional[str] = None
    interfaces: List[ParsedInterface] = field(default_factory=list)
    vlans: List[int] = field(default_factory=list)
    ospf_configs: List[str] = field(default_factory=list)
    bgp_configs: List[str] = field(default_factory=list)
    acl_configs: List[str] = field(default_factory=list)
    static_routes: List[str] = field(default_factory=list)
    raw_lines: List[str] = field(default_factory=list)
    raw_text: str = ""


@dataclass
class ConfigDiff:
    """配置差异"""
    diff_type: str  # interface_changed | command_changed | vlan_changed | new | removed
    location: str
    original: str
    translated: str
    note: Optional[str] = None


@dataclass
class ValidationResult:
    """校验结果"""
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


# ============================================================================
# ConfigParser - 结构化解析器
# ============================================================================

class ConfigParser:
    """
    结构化配置解析器
    将厂商配置文本解析为结构化对象
    支持：Cisco IOS/IOS-XE、华为 VRP、华三 Comware
    """

    VENDOR_SIGNATURES = {
        # 数通厂商（交换机/路由器）
        "huawei": ["huawei", "sysname", "vlanif", "port link-type", "stp ", "ospf", "interface vlan", "quit", "return"],
        "h3c": ["h3c", "comware", "port trunk permit", "port link-mode", "vlan-interface"],
        "ruijie": ["ruijie", "ruijieos", "interface", "vlan", "spanning-tree", "router ospf"],
        # 安全厂商（防火墙）
        "hillstone": ["hillstone", "hsfw", "zone", "security-zone", "context"],
        "topsec": ["topsec", "tos", "zone", "policy", "nat"],
        "dptech": ["dptech", "dpos", "zone", "security-policy", "nat"],
        # 通用数通
        "cisco": ["cisco", "hostname", "switchport", "spanning-tree", "router ospf", "interfac", "cdp", "lacp"],
    }

    def parse(self, config_text: str, vendor_hint: Optional[str] = None) -> ParsedConfig:
        """
        解析配置文本
        - 自动检测厂商
        - 提取接口、VLAN、路由协议、ACL、静态路由
        """
        lines = [l.rstrip() for l in config_text.splitlines()]
        lines = [l for l in lines if l.strip() and not l.lstrip().startswith("!")]

        result = ParsedConfig(raw_lines=lines, raw_text=config_text)

        # 检测厂商
        result.vendor = vendor_hint or self.detect_vendor(config_text)

        current_interface = None

        for line in lines:
            stripped = line.strip()
            lower_stripped = stripped.lower()
            is_child_line = line[:1].isspace()

            if current_interface is not None and not is_child_line:
                result.interfaces.append(current_interface)
                current_interface = None

            # 主机名
            if lower_stripped.startswith("hostname ") or lower_stripped.startswith("sysname "):
                result.hostname = stripped.split(maxsplit=1)[1]
                continue

            # 接口
            iface_match = re.match(r"^(?:interface)\s+(\S+)", stripped, re.IGNORECASE)
            if iface_match:
                if current_interface:
                    result.interfaces.append(current_interface)
                current_interface = ParsedInterface(
                    name=iface_match.group(1),
                    raw_lines=[stripped],
                )
                continue

            if current_interface is not None:
                current_interface.raw_lines.append(line)
                lower = stripped.lower()

                if re.match(r"^(?:description|desc)\s+", lower):
                    try:
                        current_interface.description = stripped.split(maxsplit=1)[1]
                    except IndexError:
                        pass
                if re.match(r"^(?:ip address|ip\s+address)\s+", lower):
                    current_interface.has_ip = True
                if "shutdown" in lower:
                    current_interface.has_shutdown = True
                # ACL 编号
                acl_m = re.search(r"(?:vlan|acl)\s+(\d+)", lower)
                if acl_m and "access-list" not in lower:
                    pass  # interface acl 应用

        if current_interface:
            result.interfaces.append(current_interface)

        # 全局解析
        all_text = "\n".join(lines).lower()

        # VLAN
        for line in lines:
            vl = re.match(r"^(?:vlan)\s+(\d+)", line.strip(), re.IGNORECASE)
            if vl:
                result.vlans.append(int(vl.group(1)))

        # OSPF
        in_ospf = False
        for line in lines:
            stripped = line.strip()
            if re.match(r"^(?:router\s+ospf|ospf)\s+", stripped, re.IGNORECASE):
                in_ospf = True
                result.ospf_configs.append(stripped)
            elif in_ospf:
                if not line.startswith(" ") and not line.startswith("\t"):
                    in_ospf = False
                else:
                    result.ospf_configs.append(line)

        # BGP
        in_bgp = False
        for line in lines:
            stripped = line.strip()
            if re.match(r"^(?:router\s+bgp|bgp)\s+", stripped, re.IGNORECASE):
                in_bgp = True
                result.bgp_configs.append(stripped)
            elif in_bgp:
                if not line.startswith(" ") and not line.startswith("\t"):
                    in_bgp = False
                else:
                    result.bgp_configs.append(line)

        # ACL (handle both Cisco flat style and indented continuation)
        acl_line_re = re.compile(r"^(?:access-list|acl)\s+", re.IGNORECASE)
        in_acl = False
        for line in lines:
            stripped = line.strip()
            if acl_line_re.match(stripped):
                in_acl = True
                result.acl_configs.append(stripped)
            elif in_acl:
                if line[:1].isspace():
                    result.acl_configs.append(line)
                elif acl_line_re.match(stripped):
                    result.acl_configs.append(stripped)
                else:
                    in_acl = False

        # 静态路由
        for line in lines:
            stripped = line.strip()
            if re.match(r"^(?:ip route|ip\s+route|ip route-static)", stripped, re.IGNORECASE):
                result.static_routes.append(stripped)

        return result

    def detect_vendor(self, config_text: str) -> str:
        """自动检测配置来源厂商"""
        lower = config_text.lower()

        strong_signals = [
            ("huawei", ["sysname ", "vlanif", "port link-type", "port trunk allow-pass", "\nreturn"]),
            ("h3c", ["h3c", "comware", "port trunk permit", "port link-mode"]),
            ("cisco", ["hostname ", "switchport", "router ospf", "spanning-tree", "access-list "]),
            ("ruijie", ["ruijie", "ruijieos"]),
            ("hillstone", ["hillstone", "hsfw", "security-zone"]),
            ("topsec", ["topsec", "tos"]),
            ("dptech", ["dptech", "dpos"]),
        ]
        for vendor, signals in strong_signals:
            if any(sig in lower for sig in signals):
                return vendor

        scores = {}
        for vendor, signatures in self.VENDOR_SIGNATURES.items():
            score = sum(1 for sig in signatures if sig.strip() and sig in lower)
            scores[vendor] = score
        if max(scores.values()) == 0:
            return "unknown"
        return max(scores, key=scores.get)


# ============================================================================
# ConfigDiffer - 差异对比
# ============================================================================

class ConfigDiffer:
    """
    配置差异对比器
    对比原文和译文，生成结构化的差异列表
    """

    def diff(self, original: ParsedConfig, translated: ParsedConfig) -> List[ConfigDiff]:
        """对比两份配置"""
        diffs = []

        # 接口名称映射
        orig_iface_names = {i.name for i in original.interfaces}
        trans_iface_names = {i.name for i in translated.interfaces}
        for orig_name in orig_iface_names:
            if orig_name not in trans_iface_names:
                diffs.append(ConfigDiff(
                    diff_type="interface_changed",
                    location=orig_name,
                    original=orig_name,
                    translated="(已映射到目标厂商)",
                    note="接口名称已根据厂商规范映射",
                ))

        # 接口数量
        if len(original.interfaces) != len(translated.interfaces):
            diffs.append(ConfigDiff(
                diff_type="count_changed",
                location="interfaces",
                original=f"{len(original.interfaces)} 个接口",
                translated=f"{len(translated.interfaces)} 个接口",
            ))

        # VLAN
        orig_vlans = set(original.vlans)
        trans_vlans = set(translated.vlans)
        for v in orig_vlans - trans_vlans:
            diffs.append(ConfigDiff(diff_type="vlan_removed", location=f"vlan {v}", original=f"vlan {v}", translated="(已移除或合并)"))
        for v in trans_vlans - orig_vlans:
            diffs.append(ConfigDiff(diff_type="vlan_new", location=f"vlan {v}", original="(新增)", translated=f"vlan {v}"))

        return diffs


# ============================================================================
# ConfigValidator - 语法校验
# ============================================================================

class ConfigValidator:
    """
    配置校验器
    基于规则的语法和最佳实践校验
    """

    RULES = {
        "huawei": [
            ("ospf_no_router_id", r"ospf", r"^((?!router-id).)*$", "OSPF 建议配置 router-id"),
            ("vlan_range", r"vlan\s+(\d+)", None, "VLAN ID 应在 1-4094 范围内"),
        ],
        "cisco": [
            ("vlan_range", r"vlan\s+(\d+)", None, "VLAN ID 应在 1-4094 范围内"),
            ("ip_address_format", r"ip address ([\d.]+)", None, "IP 地址格式检查"),
        ],
        "h3c": [
            ("vlan_range", r"vlan\s+(\d+)", None, "VLAN ID 应在 1-4094 范围内"),
        ],
    }

    BEST_PRACTICES = {
        "huawei": [
            "OSPF 进程建议指定 router-id（使用 Loopback 地址）",
            "建议为接口配置 description 描述用途",
            "Trunk 端口需确保对端设备允许对应 VLAN",
            "STP 边缘端口建议配置 stp edged-port enable",
            "ACL 规则按先精细后粗糙顺序配置",
        ],
        "cisco": [
            "建议为接口配置 description",
            "STP 边缘端口建议配置 spanning-tree portfast",
            "建议启用 BPDU Guard: spanning-tree bpduguard enable",
            "命名 ACL 便于维护",
        ],
        "h3c": [
            "建议为接口配置 description",
            "华三 v7 支持 OAA 开放式架构",
        ],
    }

    def validate(self, config: ParsedConfig) -> ValidationResult:
        """校验配置"""
        errors = []
        warnings = []

        if not config.vendor or config.vendor == "unknown":
            warnings.append("无法识别配置厂商，跳过厂商特定校验")
            return ValidationResult(valid=True, warnings=warnings)

        # 规则校验
        all_text = config.raw_text
        rules = self.RULES.get(config.vendor, [])
        for rule_name, pattern, exclude_pattern, msg in rules:
            matches = re.finditer(pattern, all_text, re.IGNORECASE | re.MULTILINE)
            for m in matches:
                if exclude_pattern and re.search(exclude_pattern, m.group(), re.IGNORECASE):
                    continue
                if "vlan" in rule_name:
                    vlan_id = int(m.group(1)) if m.groups() else 0
                    if vlan_id < 1 or vlan_id > 4094:
                        errors.append(f"VLAN ID {vlan_id} 超出范围 (1-4094)")
                elif "ospf" in rule_name and "router-id" not in all_text.lower():
                    warnings.append(msg)
                    break  # 只警告一次

        # 最佳实践
        practices = self.BEST_PRACTICES.get(config.vendor, [])
        has_description = any("description" in line.lower() for line in config.raw_lines)
        if not has_description and len(config.interfaces) > 0:
            warnings.append("建议: 为接口配置 description 描述用途")

        return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings)


# ============================================================================
# KnowledgeRetriever - 知识检索
# ============================================================================

class KnowledgeRetriever:
    """
    知识检索工具
    从 knowledge_data/ 目录读取厂商知识（按 vendor/feature.md 组织）
    """

    def __init__(self, knowledge_dir: str = "knowledge_data"):
        self.knowledge_dir = Path(knowledge_dir)
        self._reference: Dict[str, Dict[str, str]] = {}  # {vendor: {feature: content}}
        self._load_markdown_knowledge()

    def _load_markdown_knowledge(self):
        if not self.knowledge_dir.exists():
            return
        # Phase 1: Load old path {vendor}/{feature}.md
        for vendor_dir in self.knowledge_dir.iterdir():
            if not vendor_dir.is_dir() or vendor_dir.name == "features" or vendor_dir.name == "domains":
                continue
            vendor = vendor_dir.name.lower()
            self._reference.setdefault(vendor, {})
            for fpath in vendor_dir.glob("*.md"):
                try:
                    content = fpath.read_text(encoding="utf-8").strip()
                    if content:
                        self._reference[vendor][fpath.stem] = content
                except Exception as e:
                    print(f"[KnowledgeRetriever] load {fpath} failed: {e}")
        # Phase 2: Load new path domains/{domain}/{vendor}/{feature}.md (overrides old)
        domains_dir = self.knowledge_dir / "domains"
        if domains_dir.exists():
            for domain_dir in domains_dir.iterdir():
                if not domain_dir.is_dir():
                    continue
                for vendor_dir in domain_dir.iterdir():
                    if not vendor_dir.is_dir():
                        continue
                    vendor = vendor_dir.name.lower()
                    self._reference.setdefault(vendor, {})
                    for fpath in vendor_dir.glob("*.md"):
                        if fpath.stem == "profile":
                            continue
                        try:
                            content = fpath.read_text(encoding="utf-8").strip()
                            if content:
                                self._reference[vendor][fpath.stem] = content
                        except Exception as e:
                            print(f"[KnowledgeRetriever] load {fpath} failed: {e}")

    def get_interface_mapping(self, from_vendor: str, to_vendor: str) -> Dict[str, str]:
        """获取接口映射（从 markdown 知识提取）"""
        mapping = {}
        for vendor in (from_vendor, to_vendor):
            iface = self._reference.get(vendor.lower(), {}).get("interface", "")
            for line in iface.splitlines():
                if "→" in line or "->" in line:
                    parts = line.replace("→", "→").replace("->", "→").split("→")
                    if len(parts) == 2:
                        mapping[parts[0].strip().lower()] = parts[1].strip()
        return mapping

    def get_command_mapping(self, from_vendor: str, to_vendor: str) -> List[Dict[str, str]]:
        """获取命令映射列表（从 markdown 知识提取）"""
        items = []
        for content in self._reference.get(from_vendor, {}).values():
            for line in content.splitlines():
                if "→" in line or "->" in line:
                    parts = line.replace("→", "→").replace("->", "→").split("→")
                    if len(parts) == 2:
                        items.append({"from": parts[0].strip(), "to": parts[1].strip()})
        return items

    def get_reference_config(self, vendor: str, feature: str) -> Optional[str]:
        """获取特定厂商、特定功能的参考知识"""
        return self._reference.get(vendor.lower(), {}).get(feature)

    def get_all_mapping_info(self, from_vendor: str, to_vendor: str) -> str:
        """生成完整的映射信息文本，供 LLM 参考"""
        parts = ["【配置映射参考】", f"翻译方向: {from_vendor} → {to_vendor}", ""]
        for vendor in (from_vendor, to_vendor):
            vendor_refs = self._reference.get(vendor.lower(), {})
            if vendor_refs:
                parts.append(f"## {vendor.upper()} 参考知识")
                for feature, content in vendor_refs.items():
                    parts.append(f"### {feature}")
                    parts.append(content)
                    parts.append("")
        return "\n".join(parts) if len(parts) > 3 else ""
