from core.rule_translator import RuleBasedTranslator


def _executable_lines(text: str) -> list[str]:
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip()
        and not line.strip().startswith(("```", "!", "#"))
    ]


HUAWEI_USG_KEYWORDS = [
    "security-zone", "security-policy", "ip address-set", "ip service-set",
]
HILLSTONE_KEYWORDS = [
    "zone ", "policy ",
]
TOPSEC_KEYWORDS = [
    "zone name", "address name", "policy name",
]
DPTECH_KEYWORDS = [
    "object address", "security-policy name",
]


def _check_no_source_residue(output: str, source_keywords: list[str]):
    exe_lines = _executable_lines(output)
    for exe in exe_lines:
        for kw in source_keywords:
            if exe.startswith(kw):
                raise AssertionError(
                    f"Source residue detected: '{kw}' starts executable line: {exe!r}"
                )


def test_huawei_usg_to_hillstone_zone():
    result = RuleBasedTranslator().translate(
        "security-zone name trust\nsecurity-zone name untrust\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    assert "zone trust" in result
    assert "zone untrust" in result
    assert "security-zone" not in _executable_lines(result)
    _check_no_source_residue(result, HUAWEI_USG_KEYWORDS)


def test_huawei_usg_to_hillstone_zone_with_add_interface():
    result = RuleBasedTranslator().translate(
        "security-zone name trust\n add interface GigabitEthernet0/0/1\n"
        "security-zone name untrust\n add interface GigabitEthernet0/0/2\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    assert "zone trust" in result
    assert "zone untrust" in result
    _check_no_source_residue(result, HUAWEI_USG_KEYWORDS)


def test_huawei_usg_to_hillstone_address_object():
    result = RuleBasedTranslator().translate(
        "ip address-set WEB type object\n address 0 10.0.0.10 mask 32\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    assert "address WEB 10.0.0.10 255.255.255.255" in result
    _check_no_source_residue(result, HUAWEI_USG_KEYWORDS)


def test_huawei_usg_to_hillstone_service_object():
    result = RuleBasedTranslator().translate(
        "ip service-set HTTP type object\n service 0 protocol tcp destination-port 80\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    assert "service HTTP tcp dst-port 80" in result
    _check_no_source_residue(result, HUAWEI_USG_KEYWORDS)


def test_huawei_usg_to_hillstone_security_policy():
    result = RuleBasedTranslator().translate(
        "security-policy\n rule name allow-http\n  source-zone trust\n"
        "  destination-zone untrust\n  destination-address WEB\n"
        "  service HTTP\n  action permit\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    exe = _executable_lines(result)
    policy_lines = [l for l in exe if l.startswith("policy ")]
    assert len(policy_lines) == 1, f"Expected 1 policy line, got {policy_lines}"
    assert "allow-http" in policy_lines[0]
    assert "trust" in policy_lines[0]
    assert "untrust" in policy_lines[0]
    assert "WEB" in policy_lines[0]
    assert "HTTP" in policy_lines[0]
    assert "permit" in policy_lines[0]
    _check_no_source_residue(result, HUAWEI_USG_KEYWORDS)


def test_huawei_usg_to_hillstone_full():
    result = RuleBasedTranslator().translate(
        "security-zone name trust\n add interface GigabitEthernet0/0/1\n"
        "security-zone name untrust\n add interface GigabitEthernet0/0/2\n"
        "ip address-set WEB type object\n address 0 10.0.0.10 mask 32\n"
        "ip service-set HTTP type object\n service 0 protocol tcp destination-port 80\n"
        "security-policy\n rule name allow-http\n"
        "  source-zone trust\n  destination-zone untrust\n"
        "  destination-address WEB\n  service HTTP\n  action permit\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    assert "zone trust" in result
    assert "zone untrust" in result
    assert "address WEB 10.0.0.10 255.255.255.255" in result
    assert "service HTTP tcp dst-port 80" in result
    exe = _executable_lines(result)
    policy_lines = [l for l in exe if l.startswith("policy ")]
    assert len(policy_lines) == 1
    _check_no_source_residue(result, HUAWEI_USG_KEYWORDS)


def test_hillstone_to_huawei_usg_zone():
    result = RuleBasedTranslator().translate(
        "zone trust\nzone untrust\n",
        from_vendor="hillstone",
        to_vendor="huawei_usg",
    )
    assert "security-zone name trust" in result
    assert "security-zone name untrust" in result
    _check_no_source_residue(result, HILLSTONE_KEYWORDS)


def test_hillstone_to_huawei_usg_address_object():
    result = RuleBasedTranslator().translate(
        "address WEB 10.0.0.10 255.255.255.255\n",
        from_vendor="hillstone",
        to_vendor="huawei_usg",
    )
    assert "ip address-set WEB type object" in result
    assert "address 0 10.0.0.10 mask 32" in result
    _check_no_source_residue(result, HILLSTONE_KEYWORDS)


def test_hillstone_to_huawei_usg_service_object():
    result = RuleBasedTranslator().translate(
        "service HTTP tcp dst-port 80\n",
        from_vendor="hillstone",
        to_vendor="huawei_usg",
    )
    assert "ip service-set HTTP type object" in result
    assert "service 0 protocol tcp destination-port 80" in result
    _check_no_source_residue(result, HILLSTONE_KEYWORDS)


def test_hillstone_to_huawei_usg_policy():
    result = RuleBasedTranslator().translate(
        "policy allow-http from trust to untrust source any destination WEB service HTTP action permit\n",
        from_vendor="hillstone",
        to_vendor="huawei_usg",
    )
    assert "security-policy" in result
    assert "rule name allow-http" in result
    assert "source-zone trust" in result
    assert "destination-zone untrust" in result
    assert "destination-address WEB" in result
    assert "service HTTP" in result
    assert "action permit" in result
    _check_no_source_residue(result, HILLSTONE_KEYWORDS)


def test_hillstone_to_huawei_usg_full():
    result = RuleBasedTranslator().translate(
        "zone trust\nzone untrust\n"
        "address WEB 10.0.0.10 255.255.255.255\n"
        "service HTTP tcp dst-port 80\n"
        "policy allow-http from trust to untrust source any destination WEB service HTTP action permit\n",
        from_vendor="hillstone",
        to_vendor="huawei_usg",
    )
    assert "security-zone name trust" in result
    assert "security-zone name untrust" in result
    assert "ip address-set WEB type object" in result
    assert "ip service-set HTTP type object" in result
    assert "security-policy" in result
    assert "rule name allow-http" in result
    _check_no_source_residue(result, HILLSTONE_KEYWORDS)


def test_topsec_to_hillstone_zone():
    result = RuleBasedTranslator().translate(
        "zone name inside\nzone name outside\n",
        from_vendor="topsec",
        to_vendor="hillstone",
    )
    assert "zone inside" in result
    assert "zone outside" in result
    _check_no_source_residue(result, TOPSEC_KEYWORDS)


def test_topsec_to_hillstone_address_object():
    result = RuleBasedTranslator().translate(
        "address name SERVER ip 192.168.1.100 255.255.255.255\n",
        from_vendor="topsec",
        to_vendor="hillstone",
    )
    assert "address SERVER 192.168.1.100 255.255.255.255" in result
    _check_no_source_residue(result, TOPSEC_KEYWORDS)


def test_topsec_to_hillstone_policy():
    result = RuleBasedTranslator().translate(
        "policy name allow-web from inside to outside src any dst SERVER service HTTP action permit\n",
        from_vendor="topsec",
        to_vendor="hillstone",
    )
    exe = _executable_lines(result)
    policy_lines = [l for l in exe if l.startswith("policy ")]
    assert len(policy_lines) == 1
    assert "allow-web" in policy_lines[0]
    assert "inside" in policy_lines[0]
    assert "outside" in policy_lines[0]
    assert "SERVER" in policy_lines[0]
    assert "HTTP" in policy_lines[0]
    assert "permit" in policy_lines[0]
    assert "src" not in policy_lines[0]
    assert "source" in policy_lines[0]
    _check_no_source_residue(result, TOPSEC_KEYWORDS)


def test_topsec_to_hillstone_full():
    result = RuleBasedTranslator().translate(
        "zone name inside\nzone name outside\n"
        "address name SERVER ip 192.168.1.100 255.255.255.255\n"
        "policy name allow-web from inside to outside src any dst SERVER service HTTP action permit\n",
        from_vendor="topsec",
        to_vendor="hillstone",
    )
    assert "zone inside" in result
    assert "zone outside" in result
    assert "address SERVER 192.168.1.100 255.255.255.255" in result
    exe = _executable_lines(result)
    policy_lines = [l for l in exe if l.startswith("policy ")]
    assert len(policy_lines) == 1
    assert "allow-web" in policy_lines[0]
    _check_no_source_residue(result, TOPSEC_KEYWORDS)


def test_dptech_to_huawei_usg_zone():
    result = RuleBasedTranslator().translate(
        "zone lan\nzone wan\n",
        from_vendor="dptech",
        to_vendor="huawei_usg",
    )
    assert "security-zone name lan" in result
    assert "security-zone name wan" in result
    _check_no_source_residue(result, DPTECH_KEYWORDS)


def test_dptech_to_huawei_usg_address_object():
    result = RuleBasedTranslator().translate(
        "object address DNS 8.8.8.8 255.255.255.255\n",
        from_vendor="dptech",
        to_vendor="huawei_usg",
    )
    assert "ip address-set DNS type object" in result
    assert "address 0 8.8.8.8 mask 32" in result
    _check_no_source_residue(result, DPTECH_KEYWORDS)


def test_dptech_to_huawei_usg_policy():
    result = RuleBasedTranslator().translate(
        "security-policy name allow-dns source-zone lan destination-zone wan "
        "source-address 10.0.0.0 destination-address DNS service dns action permit\n",
        from_vendor="dptech",
        to_vendor="huawei_usg",
    )
    assert "security-policy" in result
    assert "rule name allow-dns" in result
    assert "source-zone lan" in result
    assert "destination-zone wan" in result
    assert "source-address 10.0.0.0" in result
    assert "destination-address DNS" in result
    assert "service dns" in result
    assert "action permit" in result
    _check_no_source_residue(result, DPTECH_KEYWORDS)


def test_dptech_to_huawei_usg_full():
    result = RuleBasedTranslator().translate(
        "zone lan\nzone wan\n"
        "object address DNS 8.8.8.8 255.255.255.255\n"
        "security-policy name allow-dns source-zone lan destination-zone wan "
        "source-address 10.0.0.0 destination-address DNS service dns action permit\n",
        from_vendor="dptech",
        to_vendor="huawei_usg",
    )
    assert "security-zone name lan" in result
    assert "security-zone name wan" in result
    assert "ip address-set DNS type object" in result
    assert "security-policy" in result
    assert "rule name allow-dns" in result
    assert "source-address 10.0.0.0" in result
    _check_no_source_residue(result, DPTECH_KEYWORDS)


def test_unknown_firewall_command_goes_to_manual_review():
    result = RuleBasedTranslator().translate(
        "nat source 10.0.0.0 255.255.255.0\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    assert "MANUAL_REVIEW" in result
    _check_no_source_residue(result, HUAWEI_USG_KEYWORDS)


def test_firewall_cipher_redacted():
    result = RuleBasedTranslator().translate(
        "snmp-agent community read cipher Test@123\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    exe = _executable_lines(result)
    for line in exe:
        assert "Test@" not in line, f"Secret leaked in: {line}"
        assert "cipher" not in line.lower()


def test_huawei_usg_to_hillstone_multiple_rules():
    result = RuleBasedTranslator().translate(
        "security-policy\n"
        " rule name p1\n"
        "  source-zone trust\n"
        "  destination-zone untrust\n"
        "  action permit\n"
        " rule name p2\n"
        "  source-zone trust\n"
        "  destination-zone untrust\n"
        "  action deny\n"
        " rule name p3\n"
        "  source-zone dmz\n"
        "  destination-zone untrust\n"
        "  service HTTP\n"
        "  action permit\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    exe = _executable_lines(result)
    policy_lines = [l for l in exe if l.startswith("policy ")]
    assert len(policy_lines) == 3, f"Expected 3 policy lines, got {len(policy_lines)}: {policy_lines}"
    assert any("p1" in l and "permit" in l for l in policy_lines), f"Missing p1/permit in {policy_lines}"
    assert any("p2" in l and "deny" in l for l in policy_lines), f"Missing p2/deny in {policy_lines}"
    assert any("p3" in l and "permit" in l for l in policy_lines), f"Missing p3/permit in {policy_lines}"
    assert "no rule defined" not in result
    assert "security-policy (incomplete" not in result
    _check_no_source_residue(result, HUAWEI_USG_KEYWORDS)


def test_huawei_usg_to_hillstone_multiple_rules_no_false_no_rule_review():
    result = RuleBasedTranslator().translate(
        "security-policy\n"
        " rule name p1\n"
        "  source-zone trust\n"
        "  destination-zone untrust\n"
        "  action permit\n"
        " rule name p2\n"
        "  source-zone trust\n"
        "  destination-zone untrust\n"
        "  action deny\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    exe = _executable_lines(result)
    policy_lines = [l for l in exe if l.startswith("policy ")]
    assert len(policy_lines) == 2, f"Expected 2 policy lines, got {len(policy_lines)}: {policy_lines}"
    assert "no rule defined" not in result, f"False 'no rule defined' in {result}"
    assert "security-policy (incomplete" not in result, f"False incomplete in {result}"
    _check_no_source_residue(result, HUAWEI_USG_KEYWORDS)


def test_huawei_usg_to_hillstone_incomplete_policy_flushes_manual_review_at_eof():
    result = RuleBasedTranslator().translate(
        "security-policy\n rule name p1\n  source-zone trust\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    assert "MANUAL_REVIEW" in result
    assert "p1" in result
    assert "incomplete" in result
    _check_no_source_residue(result, HUAWEI_USG_KEYWORDS)


def test_huawei_usg_to_hillstone_incomplete_policy_before_next_top_level_flushes_manual_review():
    result = RuleBasedTranslator().translate(
        "security-policy\n rule name p1\n  source-zone trust\n  destination-zone untrust\n"
        "zone other\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    assert "MANUAL_REVIEW" in result
    assert "p1" in result
    assert "incomplete" in result
    # Next top-level command should still be translated
    assert "zone other" in result
    _check_no_source_residue(result, HUAWEI_USG_KEYWORDS)


def test_huawei_usg_to_hillstone_secpol_header_no_rules():
    result = RuleBasedTranslator().translate(
        "security-policy\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    assert "MANUAL_REVIEW" in result
    assert "no rule" in result.lower()
    _check_no_source_residue(result, HUAWEI_USG_KEYWORDS)


def test_huawei_usg_to_hillstone_unknown_policy_subcommand_manual_review():
    result = RuleBasedTranslator().translate(
        "security-policy\n"
        " rule name p1\n"
        "  source-zone trust\n"
        "  destination-zone untrust\n"
        "  time-range WORK\n"
        "  action permit\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    assert "policy p1" in result, f"Missing policy: {result}"
    assert "MANUAL_REVIEW" in result, f"Missing MANUAL_REVIEW: {result}"
    assert "time-range WORK" in result, f"Missing time-range WORK: {result}"
    assert "no rule defined" not in result
    # No Huawei executable source residue
    exe = _executable_lines(result)
    for line in exe:
        assert "security-policy" not in line, f"Source command leaked: {line}"
        assert "time-range" not in line, f"Source sub-command leaked: {line}"
    _check_no_source_residue(result, HUAWEI_USG_KEYWORDS)


def test_huawei_usg_to_hillstone_zone_interface_binding_manual_review():
    result = RuleBasedTranslator().translate(
        "security-zone name trust\n"
        " add interface GigabitEthernet0/0/1\n",
        from_vendor="huawei_usg",
        to_vendor="hillstone",
    )
    assert "zone trust" in result, f"Missing zone: {result}"
    assert "MANUAL_REVIEW" in result, f"Missing MANUAL_REVIEW: {result}"
    assert "GigabitEthernet0/0/1" in result, f"Missing interface: {result}"
    exe = _executable_lines(result)
    assert not any("add interface" in l for l in exe), f"add interface is executable: {result}"
    _check_no_source_residue(result, HUAWEI_USG_KEYWORDS)
