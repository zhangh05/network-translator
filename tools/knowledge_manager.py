# -*- coding: utf-8 -*-
"""
Knowledge Manager - File-based Knowledge Retrieval for IR Translation

Architecture:
- Knowledge stored as Markdown files per vendor per IR type
- retrieve(ir_block, vendor) -> relevant knowledge content
- Files read on-demand, not loaded into memory
"""

import logging
import os
import re
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger("translator.knowledge_manager")

# 知识库根目录
KNOWLEDGE_DIR = Path(__file__).parent.parent / "knowledge_data"

_CACHE_MAX_ITEMS = 100
_CACHE_TTL_SECS = 3600  # 1h
_file_cache: Dict[str, Tuple[str, float]] = {}  # cache_key -> (content, timestamp)


def clear_knowledge_cache() -> None:
    """Clear process-local knowledge file cache."""
    _file_cache.clear()


def _trim_cache():
    if len(_file_cache) <= _CACHE_MAX_ITEMS:
        return
    now = time.time()
    expired = [k for k, (_, ts) in _file_cache.items() if now - ts > _CACHE_TTL_SECS]
    for k in expired:
        del _file_cache[k]
    if len(_file_cache) > _CACHE_MAX_ITEMS:
        ordered = sorted(_file_cache.items(), key=lambda x: x[1][1])
        for k, _ in ordered[: len(_file_cache) - _CACHE_MAX_ITEMS]:
            del _file_cache[k]


def _read_knowledge_file(file_path: Path) -> str:
    cache_key = str(file_path.resolve())
    now = time.time()
    entry = _file_cache.get(cache_key)
    if entry is not None and now - entry[1] < _CACHE_TTL_SECS:
        return entry[0]
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        logger.warning("Failed to read knowledge file %s", file_path)
        content = ""
    _file_cache[cache_key] = (content, now)
    _trim_cache()
    return content

# IR type 到文件名映射
TYPE_TO_FILE = {
    "vlan": "vlan.md",
    "interface": "interface.md",
    "ospf": "ospf.md",
    "bgp": "bgp.md",
    "acl": "acl.md",
    "dhcp": "dhcp.md",
    "stp": "stp.md",
    "vrrp": "vrrp.md",
    "hsrp": "vrrp.md",
    "nat": "nat.md",
    "aaa": "aaa.md",
    "static_route": "static_route.md",
    "isis": "isis.md",
    "tunnel": "tunnel.md",
    "ipsec": "ipsec.md",
    "qos": "qos.md",
    "wireless_service_template": "wireless_service_template.md",
    "wireless_ap_group": "wireless_ap_group.md",
    "wireless_ap": "wireless_ap.md",
    "lldp": "lldp.md",
    "cdp": "cdp.md",
    "security_zone": "security_zone.md",
    "security_policy": "security_zone.md",
    "wireless_radio": "wireless_ap.md",
    "l2tp": "tunnel.md",
    "system": "system.md",
    "irf": "irf.md",
}

# 目录名映射（vendor name -> directory name）
VENDOR_DIR = {
    "huawei": "huawei",
    "h3c": "h3c",
    "cisco": "cisco",
    "ruijie": "ruijie",
    "juniper": "juniper",
    "hillstone": "huawei",
    "topsec": "huawei",
    "dptech": "huawei",
}


def retrieve_knowledge(ir_block: dict, target_vendor: str) -> str:
    """
    根据 IR block 检索相关知识
    双路径：domains/{domain}/{vendor}/{feature}.md 优先
            {vendor}/{feature}.md fallback
    """
    block_type = ir_block.get("type", "")
    vendor_dir = VENDOR_DIR.get(target_vendor.lower())
    if not vendor_dir or not block_type:
        return ""
    filename = TYPE_TO_FILE.get(block_type)
    if not filename:
        return ""

    # Phase 2: New path first — check all domains for this vendor
    domain_base = KNOWLEDGE_DIR / "domains"
    if domain_base.exists():
        for domain_dir in sorted(domain_base.iterdir()):
            if not domain_dir.is_dir():
                continue
            new_path = domain_dir / vendor_dir / filename
            if new_path.exists():
                content = _read_knowledge_file(new_path)
                if content:
                    return content

    # Fallback to old path
    file_path = KNOWLEDGE_DIR / vendor_dir / filename
    if not file_path.exists():
        if vendor_dir != "huawei":
            file_path = KNOWLEDGE_DIR / "huawei" / filename
        if not file_path.exists():
            return ""
    return _read_knowledge_file(file_path)


# 基于正则的特征检测（无需 LLM 或 IR）
_FEATURE_PATTERNS = [
    ("vlan", r"(vlan\s+\d+|interface\s+Vlan)|vlan\s+batch"),
    ("interface", r"interface\s+\S+"),
    ("ospf", r"router\s+(ospf|ospfv3)"),
    ("bgp", r"router\s+bgp"),
    ("static_route", r"(ip\s+route|ip\s+route-static)"),
    ("acl", r"(access-list|acl\s+|traffic\s+filter)"),
    ("dhcp", r"(dhcp|dhcp\s+server|ip\s+dhcp\s+pool)"),
    ("nat", r"(nat\s+|ip\s+nat\s+|easy-ip)"),
    ("stp", r"(spanning-tree|stp\s+|stp\s+mode)"),
    ("vrrp", r"(vrrp|hsrp|standby\s+[0-9]+)"),
    ("aaa", r"(aaa\s+|local-user|radius)"),
    ("qos", r"(qos|traffic\s+|class-map|policy-map|service-policy)"),
    ("tunnel", r"(tunnel|interface\s+Tunnel)"),
    ("ipsec", r"(crypto\s+ipsec|ipsec|ike|ipsec\s+proposal)"),
    ("lldp", r"(lldp\s+|lldp\s+enable)"),
    ("cdp", r"(cdp\s+run|cdp\s+enable)"),
    ("system", r"(hostname|sysname)"),
    ("mpls", r"(mpls|mpls\s+label|mpls\s+lsr-id)"),
    ("ntp", r"(ntp\s+server|ntp\s+peer|ntp\s+master)"),
    ("snmp", r"(snmp-server|snmp\s+agent)"),
    ("vxlan", r"(vxlan|nve|evpn)"),
    ("poe", r"(power\s+inline|poe\s+|lldp\s+power)"),
    ("vrf", r"(vrf\s+|ip\s+vrf|vpn-instance)"),
    ("multicast", r"(pim|igmp|multicast|mroute)"),
    ("bfd", r"(bfd|bfd\s+session)"),
    ("ipv6", r"(ipv6\s+|ipv6\s+address|ipv6\s+route)"),
    ("port_channel", r"(port-channel|interface\s+Port-Channel|eth-trunk|bridge-aggregation)"),
    ("pbr", r"(route-map\s+|policy-based-route|traffic\s+policy)"),
    ("route_policy", r"(route-map\s+|prefix-list|route-policy|ip ip-prefix)"),
    ("irf", r"(irf\s+(member|port|domain|mad)|stacking|stack\s+ports)"),
]


def detect_features_from_config(config_text: str) -> list:
    """从原始配置文本检测 IR type，返回匹配的 type 列表"""
    text_lower = config_text.lower()
    features = []
    for ftype, pattern in _FEATURE_PATTERNS:
        if re.search(pattern, text_lower):
            features.append(ftype)
    return features


def retrieve_knowledge_by_config(config_text: str, target_vendor: str) -> str:
    """从原始配置文本检测特征并检索知识（无需 IR）"""
    features = detect_features_from_config(config_text)
    knowledge_contents = []
    for ftype in features:
        mock_block = {"type": ftype, "function": ""}
        content = retrieve_knowledge(mock_block, target_vendor)
        if content:
            knowledge_contents.append(f"## [{ftype}]\n\n{content}")
    if not knowledge_contents:
        return ""
    return "【命令参考】\n\n" + "\n\n---\n\n".join(knowledge_contents)

def retrieve_for_translation(ir_blocks: list, target_vendor: str) -> str:
    """
    为翻译过程检索所有相关知识

    Args:
        ir_blocks: IR 语义块列表
        target_vendor: 目标厂商

    Returns:
        格式化后的知识上下文
    """
    knowledge_contents = []

    for block in ir_blocks:
        content = retrieve_knowledge(block, target_vendor)
        if content:
            block_type = block.get("type", "unknown")
            block_func = block.get("function", "")[:50]
            knowledge_contents.append(
                f"## [{block_type}] {block_func}\n\n{content}"
            )

    if not knowledge_contents:
        return ""

    return "【命令参考】\n\n" + "\n\n---\n\n".join(knowledge_contents)


# 全局实例（不再使用，因为现在是文件直接读取）
_knowledge_store = None


def get_knowledge_store():
    """兼容旧接口"""
    global _knowledge_store
    if _knowledge_store is None:
        _knowledge_store = _KnowledgeStore()
    return _knowledge_store


class _KnowledgeStore:
    """兼容旧接口的封装"""

    def retrieve(self, block_type: str = None, vendor: str = None, purpose: str = None):
        """兼容旧接口"""
        if not block_type:
            return []
        mock_block = {"type": block_type}
        content = retrieve_knowledge(mock_block, vendor or "huawei")
        if content:
            return [_MockChunk(block_type, content, vendor)]
        return []

    def retrieve_for_ir_block(self, ir_block: dict, target_vendor: str = None):
        """兼容旧接口"""
        content = retrieve_knowledge(ir_block, target_vendor or "huawei")
        if content:
            return [_MockChunk(ir_block.get("type", ""), content, target_vendor)]
        return []

    def format_for_prompt(self, chunks, max_chars: int = 2000):
        """兼容旧接口"""
        if not chunks:
            return ""
        content = "\n\n".join(c.content for c in chunks)
        if len(content) > max_chars:
            content = content[:max_chars] + "\n\n...(知识内容过长，已截断)"
        return content


class _MockChunk:
    """兼容旧接口的 mock 对象"""

    def __init__(self, chunk_id: str, content: str, vendor: str):
        self.chunk_id = chunk_id
        self.content = content
        self.vendor = vendor
