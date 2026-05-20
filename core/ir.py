# -*- coding: utf-8 -*-
"""
IR Layer - LLM-driven 中间表示层
不预定义类型，LLM 自由表达语义
"""

import json
import re


_COMMENT_PREFIX = {
    "cisco": "!",
    "ruijie": "!",
    "huawei": "#",
    "h3c": "#",
    "hillstone": "#",
    "topsec": "#",
    "dbappsecurity": "!",
    "dptech": "#",
}


def _comment_prefix(vendor: str) -> str:
    return _COMMENT_PREFIX.get(vendor.lower(), "#")


def _json_candidates(content: str, open_char: str, close_char: str):
    text = content or ""
    for start, char in enumerate(text):
        if char != open_char:
            continue
        depth = 0
        in_string = False
        escaped = False
        for idx in range(start, len(text)):
            current = text[idx]
            if escaped:
                escaped = False
                continue
            if current == "\\":
                escaped = True
                continue
            if current == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if current == open_char:
                depth += 1
            elif current == close_char:
                depth -= 1
                if depth == 0:
                    yield text[start : idx + 1]
                    break


def _extract_json_array(content: str):
    for candidate in _json_candidates(content, "[", "]"):
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, list):
            return value
    # Fallback: use bracket-matching for safe extraction
    candidates = list(_json_candidates(content, "[", "]"))
    for candidate in candidates:
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, list):
            return value
    return None


def _extract_json_object(content: str):
    for candidate in _json_candidates(content, "{", "}"):
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


from typing import Union


def _trim_config(text: str) -> str:
    lines = []
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s == "!" or s.startswith("!"):
            continue
        lines.append(line)
    return "\n".join(lines)

def parse_to_ir(config_text: str, vendor: str, llm) -> Union[list, dict]:
    """解析配置为 IR（仅校验辅助用，不在翻译主路径）"""
    trimmed = _trim_config(config_text)
    prompt = f"""解析 {vendor} 配置为 IR JSON 数组：
每条含 type,function,params,original_lines,confidence。
预定义 type: vlan,interface,ospf,bgp,acl,stp,dhcp,nat,static_route,vrrp,tunnel,ipsec,qos,system
只输出 JSON。

配置：
{trimmed}
"""
    result = llm.chat(
        messages=[{"role": "user", "content": prompt}],
        system="你是一个网络配置语义分析专家。只输出 JSON 数组。",
        temperature=0.2,
        max_tokens=8192,
    )
    if "error" in result:
        return {"error": result["error"]}

    parsed = _extract_json_array(result.get("content", ""))
    if parsed is None:
        return {"error": "无法解析 IR JSON"}
    return parsed


def _asa_nat_rule(cp: str, target_platform: str) -> str:
    if target_platform != "asa":
        return ""
    return (
        "6. 目标为 Cisco ASA NAT 约束：禁止使用 IOS 风格 ip nat inside/source/outside/overload/pool 命令；"
        "禁止保留 nat source/nat server 原命令。"
        f"NAT 须使用 object network ... nat (...) 或 nat (src,dst) ... 语法。"
        f"缺少 inside/outside 接口映射时以 {cp} MANUAL_REVIEW 标记，不得编造。\n"
    )


def _bfd_rule(cp: str, target_platform: str) -> str:
    return (
        "7. 源配置存在 OSPF/BGP 与 BFD 绑定时，目标配置必须保留对应协议的 BFD 绑定语义；"
        f"无法确定目标平台绑定语法时以 {cp} MANUAL_REVIEW 标记，不得省略。\n"
    )


def _stp_rule(cp: str) -> str:
    return (
        "8. 源配置包含 STP/MSTP root primary/root secondary/priority 语义时，"
        "目标输出必须保留等价根桥语义。"
        f"合法形式：stp instance <id> root primary / root secondary，"
        f"或等价 priority 配置（primary=24576，secondary=28672）。"
        f"无法确定 instance/vlan 映射时以 {cp} MANUAL_REVIEW 标记，不得静默省略。\n"
    )


def translate_config(
    config_text: str, from_vendor: str, to_vendor: str, llm,
    knowledge_context: str = None,
    source_domain: str = "", source_platform: str = "",
    target_domain: str = "", target_platform: str = "",
    features: list = None,
    analyzer_context: str = None,
    capability_notes: list = None,
) -> Union[list, dict]:
    """翻译配置：一次 LLM 调用，原始配置 → 结构化翻译块"""
    trimmed = _trim_config(config_text)

    feat_str = ", ".join(sorted(features)) if features else "（自动检测）"
    cap_str = "; ".join(capability_notes) if capability_notes else "无特殊约束"
    ctx_parts = [
        f"源：{source_domain or '?'}/{from_vendor}/{source_platform or '?'}",
        f"目标：{target_domain or '?'}/{to_vendor}/{target_platform or '?'}",
        f"检测特性：{feat_str}",
    ]
    if analyzer_context:
        ctx_parts.append(f"分析器风险：{analyzer_context}")
    ctx_parts.append(f"能力约束：{cap_str}")
    context_block = "\n".join(f"- {p}" for p in ctx_parts)

    cp = _comment_prefix(to_vendor)
    prompt = f"""将以下 {from_vendor} 配置翻译为 {to_vendor} 配置。

{context_block}

{knowledge_context or ""}

硬约束（违反即视为输出错误）：
1. 只输出目标配置，不含 Markdown 代码围栏。
2. 禁止输出占位符：<...>、TODO、PLACEHOLDER、"请替换" 等模板内容；无从确定等价命令时 translated_lines 留空，notes 说明原因，不要在 translated_lines 中填充占位文本。
3. 目标命令若缺少必填参数（如 BGP AS 号、ACL 编号、接口名等），禁止编造该参数值；而是：
   - 不生成该危险命令；
   - 若需保留语义线索，以目标平台注释格式 {cp} MANUAL_REVIEW 在 translated_lines 中标记，并在 notes 中说明缺失参数。
4. NAT / security-policy / ACL 须保持规则顺序和引用关系；缺少被引用对象时，仍输出规则本身并在行末追加 {cp} MANUAL_REVIEW 注释。
5. 目标 {to_vendor} ({target_platform or to_vendor}) 是权威平台命令集；禁止混入其他平台（如源或第三方）的命令。
{_asa_nat_rule(cp, target_platform)}
{_bfd_rule(cp, target_platform)}
{_stp_rule(cp) if features and "stp" in features else ""}

返回**非空** JSON 数组，每条含 type, translated_lines, original_lines, notes, confidence。
type 选预定义: vlan,interface,ospf,bgp,acl,stp,dhcp,nat,static_route,vrrp,tunnel,ipsec,qos,system。
original_lines 为该功能在源配置中的原始行，translated_lines 为该功能的目标配置行列表。
无等价能力则 translated_lines 留空，notes 说明原因。

源配置：
{trimmed}
"""
    result = llm.chat(
        messages=[{"role": "user", "content": prompt}],
        system=f"你是一个网络配置翻译专家。只输出 JSON 数组。",
        temperature=0.2,
        max_tokens=8192,
    )
    if "error" in result:
        return [{"error": result["error"]}]

    parsed = _extract_json_array(result.get("content", ""))
    if parsed is None:
        return [{"error": "无法解析翻译 JSON"}]
    return parsed


def backtranslate_to_ir(translated_config: str, target_vendor: str, llm) -> list:
    """Step 3: 回译目标配置为 IR（用于验证）"""
    trimmed = _trim_config(translated_config)
    prompt = f"""回译 {target_vendor} 配置为 IR JSON 数组：
每条含 type,function,params,original_lines,confidence。
{trimmed}
"""
    result = llm.chat(
        messages=[{"role": "user", "content": prompt}],
        system="你是一个网络配置语义分析专家。只输出 JSON 数组。",
        temperature=0.2,
        max_tokens=8192,
    )
    if "error" in result:
        return {"error": result["error"]}

    parsed = _extract_json_array(result.get("content", ""))
    if parsed is None:
        return {"error": "无法解析回译 JSON"}
    return parsed


def compare_ir(ir_source: list, ir_back: list, llm) -> dict:
    """Step 4: 对比两份 IR，输出差异报告"""
    prompt = f"""你是网络配置语义审核专家。对比两份 IR 的语义等价性。

原始 IR（源配置）：
{json.dumps(ir_source, ensure_ascii=False, indent=2)}

回译 IR（从目标配置回译）：
{json.dumps(ir_back, ensure_ascii=False, indent=2)}

要求：
1. 按 type 匹配 IR 块
2. 对比每对块的 params 差异和 function 语义相似度
3. 输出一个 JSON 对象：
{{
  "overall_match": true/false,
  "matched_blocks": [
    {{"type": "...", "match": true/false, "similarity": 0.0-1.0, "params_diff": [], "function_diff": ""}}
  ],
  "unmatched_source": ["无法匹配到目标块的源IR块type列表"],
  "summary": "整体差异摘要"
}}

只输出 JSON，不要其他内容。
"""
    result = llm.chat(
        messages=[{"role": "user", "content": prompt}],
        system="你是一个网络配置语义审核专家。只输出 JSON。",
        temperature=0.1,
        max_tokens=4096,
    )
    if "error" in result:
        return {"error": result["error"]}

    parsed = _extract_json_object(result.get("content", ""))
    if parsed is not None:
        return parsed
    return {"overall_match": False, "summary": "对比失败"}
