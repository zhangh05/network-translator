# -*- coding: utf-8 -*-
"""Management-plane (AAA/SNMP/NTP/logging/hostname) translation rules for the fallback translator.

These rules are domain-agnostic: they apply to SWITCH, ROUTER, and FIREWALL devices alike.
"""

import re
from typing import Optional, Union, List


def manual_review_comment(stripped: str, to_vendor: str, indent: str = "") -> str:
    prefix = "!" if (to_vendor or "").lower() in ("cisco", "ruijie") else "#"
    return indent + f"{prefix} MANUAL_REVIEW unsupported source command: {stripped}"


def _is_cipher_or_password(line: str) -> bool:
    """Return True if line contains cipher/password keywords that must be redacted."""
    lower = line.lower()
    patterns = (
        "cipher", "password", "irreversible-cipher", "simple-text",
        "secret", "encrypted", "community",
    )
    return any(p in lower for p in patterns)


def _redact_passwords_in_line(line: str, to_vendor: str, indent: str = "") -> str:
    """Replace plain-text password/secret values with <redacted>, output MANUAL_REVIEW."""
    prefix = "!" if to_vendor.lower() in ("cisco", "ruijie") else "#"
    pats = [
        (r"(password\s+)\S+", r"\1<redacted>"),
        (r"(secret\s+)\S+", r"\1<redacted>"),
        (r"(irreversible-cipher\s+)\S+", r"\1<redacted>"),
        (r"(simple-text\s+)\S+", r"\1<redacted>"),
        (r"(cipher\s+)\S+", r"\1<redacted>"),
    ]
    redacted = line
    for pat, repl in pats:
        redacted = re.sub(pat, repl, redacted, flags=re.IGNORECASE)
    if redacted != line:
        return f"{indent}{prefix} MANUAL_REVIEW <redacted>: {redacted}"
    return indent + redacted


# ─────────────────────────────────────────────────────────────────────────────
# hostname / sysname
# ─────────────────────────────────────────────────────────────────────────────

def translate_hostname_to_huawei(stripped: str, lower: str, from_vendor: str) -> Optional[str]:
    """Cisco/Ruijie hostname → Huawei sysname."""
    if from_vendor.lower() in ("cisco", "ruijie") and lower.startswith("hostname "):
        return "sysname " + stripped.split(maxsplit=1)[1]
    if lower.startswith("sysname ") and from_vendor.lower() in ("huawei", "h3c"):
        return stripped
    return None


def translate_hostname_to_cisco(stripped: str, lower: str, from_vendor: str) -> Optional[str]:
    """Huawei/Ruijie hostname → Cisco hostname."""
    if from_vendor.lower() in ("huawei", "h3c") and lower.startswith("sysname "):
        return "hostname " + stripped.split(maxsplit=1)[1]
    if lower.startswith("hostname ") and from_vendor.lower() == "cisco":
        return stripped
    return None


def translate_hostname_to_h3c(stripped: str, lower: str, from_vendor: str) -> Optional[str]:
    """Cisco/Ruijie hostname → H3C sysname."""
    if from_vendor.lower() in ("cisco", "ruijie") and lower.startswith("hostname "):
        return "sysname " + stripped.split(maxsplit=1)[1]
    if lower.startswith("sysname ") and from_vendor.lower() == "h3c":
        return stripped
    return None


def translate_hostname_to_ruijie(stripped: str, lower: str, from_vendor: str) -> Optional[str]:
    """Huawei/Cisco hostname → Ruijie hostname."""
    if from_vendor.lower() in ("huawei", "h3c") and lower.startswith("sysname "):
        return "hostname " + stripped.split(maxsplit=1)[1]
    if lower.startswith("hostname ") and from_vendor.lower() == "ruijie":
        return stripped
    return None


# ─────────────────────────────────────────────────────────────────────────────
# NTP
# ─────────────────────────────────────────────────────────────────────────────

def translate_ntp_to_huawei(stripped: str, lower: str, indent: str, from_vendor: str) -> Optional[Union[str, List[str]]]:
    """Cisco/Ruijie NTP → Huawei NTP."""
    if from_vendor.lower() == "huawei":
        return None
    m = re.match(r"ntp server vrf (\S+) (\S+)", lower)
    if m:
        return [f"ntp-service unicast-server {m.group(2)} vrf {m.group(1)}"]
    m = re.match(r"ntp server (\S+)", lower)
    if m:
        return [f"ntp-service unicast-server {m.group(1)}"]
    m = re.match(r"ntp source-interface (\S+)", lower)
    if m:
        iface = _normalize_interface_to_huawei(m.group(1))
        return [f"ntp-service source-interface {iface}"]
    if lower.startswith("ntp "):
        return indent + manual_review_comment(stripped, "huawei", indent)
    return None


def translate_ntp_to_cisco(stripped: str, lower: str, indent: str, from_vendor: str) -> Optional[Union[str, List[str]]]:
    """Huawei/Ruijie NTP → Cisco NTP."""
    if from_vendor.lower() == "cisco":
        return None
    m = re.match(r"ntp-service unicast-server (\S+) vrf (\S+)", lower)
    if m:
        return [
            f"ntp server {m.group(1)}",
            f"! MANUAL_REVIEW NTP vrf {m.group(2)} not supported in flat Cisco NTP model",
        ]
    m = re.match(r"ntp-service unicast-server (\S+)", lower)
    if m:
        return [f"ntp server {m.group(1)}"]
    m = re.match(r"ntp-service source-interface (\S+)", lower)
    if m:
        iface = _normalize_interface_to_cisco(m.group(1))
        if iface:
            return [f"ntp source-interface {iface}"]
        return indent + manual_review_comment(stripped, "cisco", indent)
    if lower.startswith("ntp ") and not lower.startswith("ntp server"):
        return indent + manual_review_comment(stripped, "cisco", indent)
    return None


def translate_ntp_to_h3c(stripped: str, lower: str, indent: str, from_vendor: str) -> Optional[Union[str, List[str]]]:
    """Cisco/Ruijie NTP → H3C NTP; also handles Huawei NTP unicast-server."""
    if from_vendor.lower() == "h3c":
        return None
    m = re.match(r"ntp server (\S+)", lower)
    if m:
        return [f"ntp server {m.group(1)}"]
    m = re.match(r"ntp-service unicast-server (\S+)", lower)
    if m:
        return [f"ntp server {m.group(1)}"]
    m = re.match(r"ntp source-interface (\S+)", lower)
    if m:
        return [f"ntp source {m.group(1)}"]
    if lower.startswith("ntp ") and not lower.startswith("ntp server"):
        return indent + manual_review_comment(stripped, "h3c", indent)
    return None


def translate_ntp_to_ruijie(stripped: str, lower: str, indent: str, from_vendor: str) -> Optional[Union[str, List[str]]]:
    """Huawei/Cisco NTP → Ruijie NTP."""
    if from_vendor.lower() == "ruijie":
        return None
    m = re.match(r"ntp-service unicast-server (\S+)", lower)
    if m:
        return [f"ntp server {m.group(1)}"]
    m = re.match(r"ntp server (\S+)", lower)
    if m:
        return [f"ntp server {m.group(1)}"]
    m = re.match(r"ntp-service source-interface (\S+)", lower)
    if m:
        return [f"ntp source {m.group(1)}"]
    if lower.startswith("ntp "):
        return indent + manual_review_comment(stripped, "ruijie", indent)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# logging / info-center
# ─────────────────────────────────────────────────────────────────────────────

def translate_logging_to_huawei(stripped: str, lower: str, indent: str, from_vendor: str) -> Optional[Union[str, List[str]]]:
    """Cisco/Ruijie logging → Huawei info-center."""
    if from_vendor.lower() == "huawei":
        return None
    m = re.match(r"logging host (\S+)(?:\s+udp-port (\d+))?", lower)
    if m:
        port = m.group(2) or "514"
        return [f"info-center loghost {m.group(1)}", f" info-center sourceimonitor channel 0 loghost {m.group(1)} udp-port {port}"]
    m = re.match(r"logging source-interface (\S+)", lower)
    if m:
        iface = _normalize_interface_to_huawei(m.group(1))
        return [f"info-center source {iface}"]
    m = re.match(r"logging (\S+) (\S+)", lower)
    if m:
        facility, level = m.group(1), m.group(2)
        if facility == "facility" and level in ("local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"):
            return [f"info-center loghost {m.group(2)}"]  # best-effort
        return indent + manual_review_comment(stripped, "huawei", indent)
    if lower.startswith("logging "):
        return indent + manual_review_comment(stripped, "huawei", indent)
    return None


def translate_logging_to_cisco(stripped: str, lower: str, indent: str, from_vendor: str) -> Optional[Union[str, List[str]]]:
    """Huawei/Ruijie info-center → Cisco logging."""
    if from_vendor.lower() == "cisco":
        return None
    m = re.match(r"info-center loghost (\S+)(?:\s+udp-port\s+(\d+))?", lower)
    if m:
        udp = f" udp-port {m.group(2)}" if m.group(2) else ""
        return [f"logging host {m.group(1)}{udp}"]
    m = re.match(r"info-center source (\S+)", lower)
    if m:
        iface = _normalize_interface_to_cisco(m.group(1))
        if iface:
            return [f"logging source-interface {iface}"]
        return indent + manual_review_comment(stripped, "cisco", indent)
    if lower.startswith("info-center "):
        return indent + manual_review_comment(stripped, "cisco", indent)
    return None


def translate_logging_to_h3c(stripped: str, lower: str, indent: str, from_vendor: str) -> Optional[Union[str, List[str]]]:
    """Cisco/Ruijie/Huawei logging → H3C logging."""
    if from_vendor.lower() == "h3c":
        return None
    m = re.match(r"info-center loghost (\S+)", lower)
    if m:
        return [f"logging {m.group(1)}"]
    m = re.match(r"logging host (\S+)", lower)
    if m:
        return [f"logging {m.group(1)}"]
    if lower.startswith("logging ") or lower.startswith("info-center "):
        return indent + manual_review_comment(stripped, "h3c", indent)
    return None


def translate_logging_to_ruijie(stripped: str, lower: str, indent: str, from_vendor: str) -> Optional[Union[str, List[str]]]:
    """Huawei/Cisco logging → Ruijie logging."""
    if from_vendor.lower() == "ruijie":
        return None
    m = re.match(r"info-center loghost (\S+)", lower)
    if m:
        return [f"logging {m.group(1)}"]
    m = re.match(r"logging host (\S+)", lower)
    if m:
        return [f"logging {m.group(1)}"]
    if lower.startswith("info-center ") or lower.startswith("logging "):
        return indent + manual_review_comment(stripped, "ruijie", indent)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# AAA / local-user / username
# ─────────────────────────────────────────────────────────────────────────────

def translate_aaa_to_huawei(stripped: str, lower: str, indent: str, from_vendor: str) -> Optional[str]:
    """Cisco/Ruijie aaa → Huawei aaa; redacts passwords."""
    if from_vendor.lower() == "huawei":
        return None
    if lower.startswith("aaa new-model"):
        return stripped
    if lower.startswith("username ") and _is_cipher_or_password(lower):
        return indent + manual_review_comment(f"username <redacted>", "huawei", indent)
    if lower.startswith("username "):
        parts = stripped.split(maxsplit=1)
        if len(parts) == 2:
            return indent + manual_review_comment(f"username {parts[1]}", "huawei", indent)
        return indent + stripped
    if lower.startswith("local-user ") and _is_cipher_or_password(lower):
        return indent + manual_review_comment(f"local-user <redacted>", "huawei", indent)
    if lower.startswith("local-user "):
        return indent + manual_review_comment(stripped, "huawei", indent)
    if lower.startswith("aaa authentication login"):
        return indent + manual_review_comment(stripped, "huawei", indent)
    if lower.startswith("aaa authorization"):
        return indent + manual_review_comment(stripped, "huawei", indent)
    if lower.startswith("aaa accounting"):
        return indent + manual_review_comment(stripped, "huawei", indent)
    if lower.startswith("aaa "):
        return indent + manual_review_comment(stripped, "huawei", indent)
    return None


def translate_aaa_to_cisco(stripped: str, lower: str, indent: str, from_vendor: str) -> Optional[str]:
    """Huawei/Ruijie aaa → Cisco aaa; redacts passwords."""
    if from_vendor.lower() == "cisco":
        return None
    if lower.startswith("local-user ") and _is_cipher_or_password(lower):
        return indent + manual_review_comment(f"local-user <redacted>", "cisco", indent)
    if lower.startswith("local-user "):
        parts = stripped.split()
        if len(parts) >= 2:
            user = parts[1]
            return indent + manual_review_comment(f"local-user {user}", "cisco", indent)
        return indent + stripped
    if lower.startswith("aaa authentication"):
        return indent + manual_review_comment(stripped, "cisco", indent)
    if lower.startswith("aaa authorization"):
        return indent + manual_review_comment(stripped, "cisco", indent)
    if lower.startswith("aaa accounting"):
        return indent + manual_review_comment(stripped, "cisco", indent)
    if lower.startswith("aaa "):
        return indent + manual_review_comment(stripped, "cisco", indent)
    return None


def translate_aaa_to_h3c(stripped: str, lower: str, indent: str, from_vendor: str) -> Optional[str]:
    """Cisco/Ruijie aaa → H3C aaa; redacts passwords."""
    if from_vendor.lower() == "h3c":
        return None
    if lower.startswith("username ") and _is_cipher_or_password(lower):
        return indent + manual_review_comment(f"username <redacted>", "h3c", indent)
    if lower.startswith("username "):
        return indent + manual_review_comment(stripped, "h3c", indent)
    if lower.startswith("aaa "):
        return indent + manual_review_comment(stripped, "h3c", indent)
    return None


def translate_aaa_to_ruijie(stripped: str, lower: str, indent: str, from_vendor: str) -> Optional[str]:
    """Huawei/Cisco aaa → Ruijie aaa; redacts passwords."""
    if from_vendor.lower() == "ruijie":
        return None
    if lower.startswith("local-user ") and _is_cipher_or_password(lower):
        return indent + manual_review_comment(f"local-user <redacted>", "ruijie", indent)
    if lower.startswith("local-user "):
        return indent + manual_review_comment(stripped, "ruijie", indent)
    if lower.startswith("username ") and _is_cipher_or_password(lower):
        return indent + manual_review_comment(f"username <redacted>", "ruijie", indent)
    if lower.startswith("username "):
        return indent + manual_review_comment(stripped, "ruijie", indent)
    if lower.startswith("aaa "):
        return indent + manual_review_comment(stripped, "ruijie", indent)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# SNMP
# ─────────────────────────────────────────────────────────────────────────────

def translate_snmp_to_huawei(stripped: str, lower: str, indent: str, from_vendor: str) -> Optional[Union[str, List[str]]]:
    """Cisco/Ruijie SNMP → Huawei SNMP."""
    if from_vendor.lower() == "huawei":
        return None
    if lower == "snmp-server enable traps":
        return indent + "snmp-agent trap enable"
    if lower == "snmp-server enable traps snmp":
        return indent + "snmp-agent trap enable"
    if lower.startswith("snmp-server trap-source "):
        iface_part = stripped.split("trap-source", 1)[1].strip()
        iface = _normalize_interface_to_huawei(iface_part)
        return indent + f"snmp-agent trap source {iface}"
    if lower.startswith("snmp-server host ") and " v3 " in lower:
        return None
    if lower.startswith("snmp-server host ") and " community " in lower:
        return None
    if lower.startswith("snmp-server "):
        return indent + manual_review_comment(stripped, "huawei", indent)
    if lower.startswith("snmp "):
        return indent + manual_review_comment(stripped, "huawei", indent)
    return None


def translate_snmp_to_cisco(stripped: str, lower: str, indent: str, from_vendor: str) -> Optional[Union[str, List[str]]]:
    """Huawei/Ruijie SNMP → Cisco SNMP; redacts community strings.

    Note: snmp-agent target-host/trap-source are NOT handled here —
    rule_translator._translate_huawei_snmp_to_cisco provides those.
    """
    if from_vendor.lower() == "cisco":
        return None
    if lower == "snmp-agent trap enable":
        return indent + "snmp-server enable traps"
    m = re.match(r"snmp-agent community (\S+)", stripped, re.IGNORECASE)
    if m:
        return indent + manual_review_comment(f"snmp-agent community <redacted>", "cisco", indent)
    if lower.startswith("snmp-agent "):
        return None  # let rule_translator._translate_huawei_snmp_to_cisco handle it
    return None


def translate_snmp_to_h3c(stripped: str, lower: str, indent: str, from_vendor: str) -> Optional[Union[str, List[str]]]:
    """Cisco/Ruijie SNMP → H3C SNMP."""
    if from_vendor.lower() == "h3c":
        return None
    if lower == "snmp-server enable traps":
        return indent + stripped  # passthrough
    if lower.startswith("snmp-server "):
        return indent + manual_review_comment(stripped, "h3c", indent)
    if lower.startswith("snmp-agent "):
        return indent + manual_review_comment(stripped, "h3c", indent)
    return None


def translate_snmp_to_ruijie(stripped: str, lower: str, indent: str, from_vendor: str) -> Optional[Union[str, List[str]]]:
    """Huawei/Cisco SNMP → Ruijie SNMP; redacts community strings."""
    if from_vendor.lower() == "ruijie":
        return None
    if lower == "snmp-agent trap enable":
        return indent + "snmp-server enable traps"
    if lower.startswith("snmp-agent community "):
        return indent + manual_review_comment(f"snmp-agent community <redacted>", "ruijie", indent)
    if lower.startswith("snmp-server "):
        return indent + manual_review_comment(stripped, "ruijie", indent)
    if lower.startswith("snmp-agent "):
        return indent + manual_review_comment(stripped, "ruijie", indent)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Interface normalization helpers (avoid circular import)
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_interface_to_huawei(name: str) -> str:
    normalized = re.sub(r"(?i)^Vlan-interface(\d+)$", r"Vlanif\1", name)
    normalized = re.sub(r"(?i)^Port-channel(\d+)$", r"Eth-Trunk\1", normalized)
    normalized = re.sub(r"(?i)^AggregatePort\s*(\d+)$", r"Eth-Trunk\1", normalized)
    normalized = re.sub(r"(?i)^TenGigabitEthernet", "XGigabitEthernet", normalized)
    normalized = re.sub(r"(?i)^Bridge-Aggregation(\d+)$", r"Eth-Trunk\1", normalized)
    normalized = re.sub(r"(?i)^Loopback(\d+)$", r"LoopBack\1", normalized)
    normalized = re.sub(r"(?i)^NULL(\d+)$", r"NULL\1", normalized)
    return normalized


def _normalize_interface_to_cisco(name: str) -> Optional[str]:
    normalized = re.sub(r"(?i)^Vlan-interface(\d+)$", r"Vlan\1", name)
    normalized = re.sub(r"(?i)^Vlanif(\d+)$", r"Vlan\1", normalized)
    normalized = re.sub(r"(?i)^Bridge-Aggregation(\d+)$", r"Port-channel\1", normalized)
    normalized = re.sub(r"(?i)^Eth-Trunk(\d+)$", r"Port-channel\1", normalized)
    normalized = re.sub(r"(?i)^AggregatePort\s*(\d+)$", r"Port-channel\1", normalized)
    normalized = re.sub(r"(?i)^XGigabitEthernet", "TenGigabitEthernet", normalized)
    normalized = re.sub(r"(?i)^LoopBack(\d+)$", r"Loopback\1", normalized)
    normalized = re.sub(r"(?i)^NULL(\d+)$", r"Null\1", normalized)
    if re.match(r"(?i)^MEth", normalized):
        return None
    return normalized