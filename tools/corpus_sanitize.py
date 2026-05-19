"""
corpus_sanitize.py — Sanitize raw network configs for corpus inclusion.

Redacts sensitive information while preserving config structure:
  - IP addresses → 198.18.0.0/15 (documentation range)
  - Passwords / secrets → [REDACTED]
  - SNMP community strings → [REDACTED]
  - Hostnames → descriptive placeholder
  - AS numbers → 65000–65535 range
  - Usernames → [REDACTED]

Usage:
    python3 tools/corpus_sanitize.py samples/raw.txt > sanitized/entry.txt
    python3 tools/corpus_sanitize.py samples/ --out-dir sanitized/
"""

import argparse
import re
import sys
from pathlib import Path


# ── Redaction patterns ──

# real-world IPs → 198.18.0.0/15 documentation range
IP_RE = re.compile(
    r"\b(?!(?:198\.18\.|10\.|127\.|169\.254\.))"
    r"(?:\d{1,3}\.){3}\d{1,3}\b"
)

# password/key/value after known keywords
SECRET_KEYWORDS = re.compile(
    r"(password|secret|key|community|auth|encryption-key"
    r"|psk|pre-shared-key|authentication-key)"
    r"\s+(\S+)",
    re.IGNORECASE,
)

# snmp-server community (handle the unique syntax)
SNMP_COMMUNITY = re.compile(
    r"(snmp-server community\s+)\S+",
    re.IGNORECASE,
)

# hostname lines
HOSTNAME_LINE = re.compile(
    r"^(hostname|sysname)\s+\S+",
    re.IGNORECASE | re.MULTILINE,
)

# username with password
USER_LINE = re.compile(
    r"^(username\s+\S+)\s+(password|secret)\s+\S+",
    re.IGNORECASE | re.MULTILINE,
)

# enable secret / enable password
ENABLE_LINE = re.compile(
    r"^(enable\s+(secret|password)\s+)\S+",
    re.IGNORECASE | re.MULTILINE,
)

# AS numbers outside the private range
ASN_RE = re.compile(r"\b(?:[1-9]\d{4,9}|6553[6-9]\d|655[4-9]\d{2}|65[6-9]\d{3}|6[6-9]\d{4}|[7-9]\d{5,9})\b")


def sanitize_line(line: str, line_index: int) -> str:
    # preserve blank lines and comments
    stripped = line.strip()
    if not stripped or stripped.startswith("!"):
        return line

    # hostname → placeholder
    line = HOSTNAME_LINE.sub(r"\1 CORPUS-REDACTED", line)

    # enable secret/password
    line = ENABLE_LINE.sub(r"\1[REDACTED]", line)

    # username password/secret
    line = USER_LINE.sub(r"\1 \2 [REDACTED]", line)

    # snmp community
    line = SNMP_COMMUNITY.sub(r"\1[REDACTED]", line)

    # password/secret/key after keyword
    line = SECRET_KEYWORDS.sub(r"\1 [REDACTED]", line)

    # IP addresses (except already-redacted 198.18.x.x and 10.x.x.x)
    line = IP_RE.sub(_replace_ip, line)

    # Large AS numbers → private range
    line = ASN_RE.sub(lambda m: str(65000 + hash(m.group(0)) % 536), line)

    return line


_IP_COUNTER = 0


def _replace_ip(m: re.Match) -> str:
    global _IP_COUNTER
    _IP_COUNTER += 1
    host_octet = (_IP_COUNTER % 253) + 1
    subnet = (_IP_COUNTER // 253) % 256
    return f"198.18.{subnet}.{host_octet}"


def sanitize_text(text: str) -> str:
    lines = text.splitlines(keepends=True)
    result = []
    for i, line in enumerate(lines):
        result.append(sanitize_line(line, i))
    return "".join(result)


def main():
    parser = argparse.ArgumentParser(description="Sanitize network configs for corpus inclusion")
    parser.add_argument("input", help="Input file or directory")
    parser.add_argument("--out-dir", help="Output directory (required for directory input)")
    args = parser.parse_args()

    input_path = Path(args.input)

    if input_path.is_file():
        text = input_path.read_text()
        sanitized = sanitize_text(text)
        if args.out_dir:
            out_path = Path(args.out_dir) / input_path.name
            out_path.write_text(sanitized)
            print(f"saved: {out_path}", file=sys.stderr)
        else:
            sys.stdout.write(sanitized)

    elif input_path.is_dir():
        if not args.out_dir:
            print("error: --out-dir required for directory input", file=sys.stderr)
            sys.exit(1)
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        for f in sorted(input_path.iterdir()):
            if f.is_file() and not f.name.startswith("."):
                text = f.read_text()
                sanitized = sanitize_text(text)
                out_path = out_dir / f.name
                out_path.write_text(sanitized)
                print(f"saved: {out_path}", file=sys.stderr)

    else:
        print(f"error: {input_path} not found", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
