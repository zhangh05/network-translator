# -*- coding: utf-8 -*-
"""
IR Layer - LLM-driven 中间表示层
不预定义类型，LLM 自由表达语义
"""

import json
import re


# 当前 prompt 版本。每次修改 prompt 逻辑前应递增。
# 记录在 translation _meta 中供回放/归因。
PROMPT_VERSION = "2026-05-20-v1"

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
prompt_version: {PROMPT_VERSION}
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
    if isinstance(parsed, list):
        parsed.insert(0, {"type": "_meta", "prompt_version": PROMPT_VERSION})
    return parsed


def _asa_nat_rule(cp: str, target_platform: str) -> str:
    if target_platform != "asa":
        return ""
    return (
        "7. 目标为 Cisco ASA NAT 约束：禁止使用 IOS 风格 ip nat inside/source/outside/overload/pool 命令；"
        "禁止保留 nat source/nat server 原命令。"
        f"NAT 须使用 object network ... nat (...) 或 nat (src,dst) ... 语法。"
        f"缺少 inside/outside 接口映射时以 {cp} MANUAL_REVIEW 标记，不得编造。\n"
    )


def _bfd_rule(cp: str, target_platform: str) -> str:
    return (
        "8. 源配置存在 OSPF/BGP 与 BFD 绑定时，目标配置必须保留对应协议的 BFD 绑定语义；"
        f"无法确定目标平台绑定语法时以 {cp} MANUAL_REVIEW 标记，不得省略。\n"
    )


def _stp_rule(cp: str) -> str:
    return (
        "9. 源配置包含 STP/MSTP root primary/root secondary/priority 语义时，"
        "目标输出必须保留等价根桥语义。"
        f"合法形式：stp instance <id> root primary / root secondary，"
        f"或等价 priority 配置（primary=24576，secondary=28672）。"
        f"无法确定 instance/vlan 映射时以 {cp} MANUAL_REVIEW 标记，不得静默省略。\n"
    )


def _asa_access_group_rule(cp: str, target_platform: str) -> str:
    if target_platform != "asa":
        return ""
    return (
        "10. 目标为 Cisco ASA 时，所有 ACL 必须通过 access-group 绑定到接口。"
        "源配置有 zone-to-zone security-policy 或 interface 级别 ACL 绑定时，"
        "必须根据接口所属 zone 生成 access-group <name> in/out interface <if_name>。"
        f"无法确定接口命名或绑定时以 {cp} MANUAL_REVIEW 标记，不得省略 access-group。\n"
    )


def _vrf_rule(cp: str) -> str:
    return (
        "11. 源配置存在 VRF 静态路由（ip route vrf）时，"
        "目标必须使用 vpn-instance 参数（ip route-static vpn-instance <name>）。"
        f"不得省略 vpn-instance 参数或将 VRF 静态路由混入全局路由表。"
        f"VRF interface 绑定必须为目标平台等价形式（ip binding vpn-instance）。\n"
    )


def _dhcp_snooping_rule(cp: str) -> str:
    return (
        "12. 源配置有 DHCP snooping 且 trunk 端口配置了信任时，"
        "目标 trunk 端口必须配置 dhcp snooping trust（华为 VRP）或等价信任命令。"
        f"华为 VRP 语法为 interface 下配置 dhcp snooping trust，不是 dhcp snooping trusted。"
        f"不得遗漏 trunk 端口的信任配置。\n"
    )


_REQUIRED_ITEM_FIELDS = {"type", "translated_lines", "original_lines", "notes", "confidence"}
_PLACEHOLDER_PATTERNS = re.compile(
    r'(<[^>]+>|TODO|PLACEHOLDER|请替换|请修改|根据实际情况|your\s+\w+|example\.com)',
    re.IGNORECASE,
)


def validate_and_repair_llm_output(
    raw_content: str,
    from_vendor: str,
    to_vendor: str,
) -> dict:
    """Validate and repair LLM output.

    Returns:
        {"ok": True, "parsed": [...], "repairs": [...], "errors": []}
        or {"ok": False, "parsed": None, "repairs": [], "errors": [...]}
    """
    repairs = []
    errors = []

    if not raw_content or not raw_content.strip():
        return {"ok": False, "parsed": None, "repairs": repairs,
                "errors": ["LLM 输出为空"]}

    content = raw_content.strip()

    # Step 1: Strip markdown fences
    fence_match = re.search(r"```(?:json)?\s*\n?(.+?)```", content, re.DOTALL)
    if fence_match:
        content = fence_match.group(1).strip()
        repairs.append("已剥离 Markdown 代码围栏")
    else:
        raw_fence = re.search(r"```", content)
        if raw_fence:
            content = re.sub(r"```[\w-]*", "", content).strip()
            repairs.append("已修复不完整 Markdown 围栏")

    # Step 2: Remove explanatory text before/after JSON
    # Only strip if the outermost structure matches (top-level [ or {)
    first_outer = None
    last_outer = None
    for i, ch in enumerate(content):
        if ch in ("[", "{"):
            first_outer = i
            break
    for i in range(len(content) - 1, -1, -1):
        ch = content[i]
        if ch in ("]", "}"):
            last_outer = i
            break

    if first_outer is not None and last_outer is not None and last_outer > first_outer:
        opener = content[first_outer]
        closer = content[last_outer]
        if (opener == "[" and closer == "]") or (opener == "{" and closer == "}"):
            before = content[:first_outer].strip()
            after = content[last_outer + 1:].strip()
            if before:
                repairs.append(f"已移除 JSON 前导文本 ({len(before)} 字符)")
            if after:
                repairs.append(f"已移除 JSON 尾部文本 ({len(after)} 字符)")
            content = content[first_outer:last_outer + 1]
    else:
        if "[" not in content and "{" not in content:
            return {"ok": False, "parsed": None, "repairs": repairs,
                    "errors": ["LLM 输出不包含 JSON 数组"]}

    # Step 3: Parse JSON
    stripped_content = content.strip()
    parsed = None

    # If content starts with {, it's a single object — don't use _extract_json_array
    # which may find nested [] brackets.
    if stripped_content.startswith("{"):
        try:
            parsed = json.loads(stripped_content)
        except (json.JSONDecodeError, Exception):
            parsed = None
    else:
        try:
            parsed = _extract_json_array(content)
        except Exception:
            pass

    if parsed is None:
        try:
            parsed = json.loads(content)
        except (json.JSONDecodeError, Exception):
            try:
                cleaned = re.sub(r",\s*}", "}", content)
                cleaned = re.sub(r",\s*]", "]", cleaned)
                cleaned = re.sub(r"(['\"])\s*:\s*(['\"])([^'\"]*)(['\"])",
                                 r'"\3"', cleaned)
                cleaned = re.sub(r"(['\"]?)(\w+)(['\"]?)\s*:", r'"\2":', cleaned)
                parsed = json.loads(cleaned)
                repairs.append("已修复 JSON 格式错误（引号/逗号）")
            except (json.JSONDecodeError, Exception):
                return {"ok": False, "parsed": None, "repairs": repairs,
                        "errors": ["无法解析 LLM 输出为 JSON 数组"]}

    if not isinstance(parsed, list):
        return {"ok": False, "parsed": None, "repairs": repairs,
                "errors": [f"LLM 输出不是数组（类型: {type(parsed).__name__}）"]}

    if len(parsed) == 0:
        return {"ok": False, "parsed": None, "repairs": repairs,
                "errors": ["LLM 输出了空数组"]}

    # Step 4: Validate each item
    validated = []
    for idx, item in enumerate(parsed):
        if not isinstance(item, dict):
            errors.append(f"第 {idx} 项不是对象（类型: {type(item).__name__}）")
            validated.append({
                "type": "unknown",
                "translated_lines": [],
                "original_lines": [],
                "notes": f"格式异常：{type(item).__name__}",
                "confidence": 0.0,
                "_validation_error": True,
            })
            continue

        missing = _REQUIRED_ITEM_FIELDS - set(item.keys())
        if missing:
            repairs.append(f"第 {idx} 项缺少字段: {', '.join(sorted(missing))}")
            for field in missing:
                if field == "translated_lines":
                    item["translated_lines"] = []
                elif field == "original_lines":
                    item["original_lines"] = []
                elif field == "notes":
                    item["notes"] = f"LLM 未输出 {field}"
                elif field == "confidence":
                    item["confidence"] = 0.5
                elif field == "type":
                    item["type"] = "unknown"

        if not isinstance(item.get("translated_lines"), list):
            repairs.append(f"第 {idx} 项 translated_lines 不是列表，已重置为空")
            item["translated_lines"] = []

        if not isinstance(item.get("original_lines"), list):
            repairs.append(f"第 {idx} 项 original_lines 不是列表，已重置为空")
            item["original_lines"] = []

        conf = item.get("confidence", 0.5)
        if not isinstance(conf, (int, float)):
            try:
                item["confidence"] = float(conf)
                repairs.append(f"第 {idx} 项 confidence 已转换为数值")
            except (ValueError, TypeError):
                item["confidence"] = 0.5
                repairs.append(f"第 {idx} 项 confidence 无法解析，使用默认值 0.5")

        for orig_line in item.get("translated_lines", []):
            if not isinstance(orig_line, str):
                repairs.append(f"第 {idx} 项 translated_lines 包含非字符串元素")
                break

        for orig_line in item.get("original_lines", []):
            if not isinstance(orig_line, str):
                repairs.append(f"第 {idx} 项 original_lines 包含非字符串元素")
                break

        validated.append(item)

    # Step 5: Check for empty translated_lines without explanation
    for idx, item in enumerate(validated):
        if not item.get("translated_lines") and not item.get("notes", "").strip():
            repairs.append(f"第 {idx} 项 ({item.get('type', '?')}) translated_lines 为空且缺少 notes 说明")
            item["notes"] = "translated_lines 为空，notes 由校验器补填"

    # Step 6: Scan for placeholder patterns in translated_lines
    for idx, item in enumerate(validated):
        for line in item.get("translated_lines", []):
            if _PLACEHOLDER_PATTERNS.search(line):
                errors.append(
                    f"第 {idx} 项 ({item.get('type', '?')}) 包含占位符: {line[:60]}"
                )

    # Step 7: Scan for source vendor residue in translated_lines
    for idx, item in enumerate(validated):
        for line in item.get("translated_lines", []):
            if from_vendor.lower() in line.lower() and "MANUAL_REVIEW" not in line.upper():
                ref_name = _comment_prefix(from_vendor)
                repairs.append(
                    f"第 {idx} 项可能含源厂商残留，已修复提示"
                )

    return {
        "ok": len(errors) == 0,
        "parsed": validated,
        "repairs": repairs,
        "errors": errors,
    }


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
prompt_version: {PROMPT_VERSION}

{context_block}

{knowledge_context or ""}

硬约束（违反即视为输出错误）：
1. 只输出目标配置，不含 Markdown 代码围栏。
2. 禁止输出占位符：<...>、TODO、PLACEHOLDER、"请替换" 等模板内容；无从确定等价命令时 translated_lines 留空，notes 说明原因，不要在 translated_lines 中填充占位文本。
3. 目标命令若缺少必填参数（如 BGP AS 号、ACL 编号、接口名等），禁止编造该参数值；而是：
   - 不生成该危险命令；
   - 若需保留语义线索，以目标平台注释格式 {cp} MANUAL_REVIEW 在 translated_lines 中标记，并在 notes 中说明缺失参数。
4. NAT / security-policy / ACL 须保持规则顺序和引用关系；缺少被引用对象时，仍输出规则本身并在行末追加 {cp} MANUAL_REVIEW 注释。
5. 地址组/服务组（address-set / service-set / object-group network / object-group service）必须保持引用语义：源配置多个地址组成一组时，目标必须保留等价的分组结构（如 object-group network），不得将其拆散为单个 object network 条目。
6. 目标 {to_vendor} ({target_platform or to_vendor}) 是权威平台命令集；禁止混入其他平台（如源或第三方）的命令。
{_asa_nat_rule(cp, target_platform)}
{_bfd_rule(cp, target_platform)}
{_stp_rule(cp) if features and "stp" in features else ""}
{_asa_access_group_rule(cp, target_platform)}
{_vrf_rule(cp) if features and "vrf" in features else ""}
{_dhcp_snooping_rule(cp) if features and "dhcp" in features else ""}

返回**非空** JSON 数组，每条含 type, translated_lines, original_lines, notes, confidence。
type 选预定义: vlan,interface,ospf,bgp,acl,stp,dhcp,nat,static_route,vrrp,tunnel,ipsec,qos,system,address_object,service_object。
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

    raw_content = result.get("content", "")
    vresult = validate_and_repair_llm_output(raw_content, from_vendor, to_vendor)
    if not vresult["ok"]:
        error_detail = "; ".join(vresult["errors"])
        result_obj = [{"error": f"LLM 输出校验失败: {error_detail}"}]
        if vresult["repairs"]:
            result_obj[0]["_repairs"] = vresult["repairs"]
        return result_obj

    parsed = vresult["parsed"]

    if vresult["repairs"]:
        parsed.insert(0, {"_repairs": vresult["repairs"],
                          "type": "_meta", "translated_lines": [],
                          "original_lines": [],
                          "notes": "; ".join(vresult["repairs"]),
                          "confidence": 1.0})

    parsed.insert(0, {"type": "_meta", "translated_lines": [],
                      "original_lines": [],
                      "prompt_version": PROMPT_VERSION,
                      "notes": f"prompt_version={PROMPT_VERSION}",
                      "confidence": 1.0})

    return parsed


def backtranslate_to_ir(translated_config: str, target_vendor: str, llm) -> list:
    """Step 3: 回译目标配置为 IR（用于验证）"""
    trimmed = _trim_config(translated_config)
    prompt = f"""回译 {target_vendor} 配置为 IR JSON 数组：
prompt_version: {PROMPT_VERSION}
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
    if isinstance(parsed, list):
        parsed.insert(0, {"type": "_meta", "prompt_version": PROMPT_VERSION})
    return parsed


def compare_ir(ir_source: list, ir_back: list, llm) -> dict:
    """Step 4: 对比两份 IR，输出差异报告"""
    prompt = f"""你是网络配置语义审核专家。对比两份 IR 的语义等价性。
prompt_version: {PROMPT_VERSION}

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
