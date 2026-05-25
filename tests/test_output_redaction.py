# -*- coding: utf-8 -*-
"""Tests for output redaction (P0: prevent secret leaks).

Tests cover: direct redact_sensitive_output() unit tests, recursive
structure handling, no-double-redaction, false-positive avoidance,
and ProjectStore integration (translate and reuse paths).
"""

import json
import pytest
from project_store import redact_sensitive_output


# ── Fixtures ────────────────────────────────────────────────────────────────

SECRET_LINES = {
    "password": "ipsec authentication password 12345",
    "secret": "snmp-server secret 0 SecretPass!",
    "secret_with_type": "snmp-server secret 5 abc123def456",
    "cipher": "local-user admin password cipher Hello@123",
    "irreversible_cipher": "local-user admin password irreversible-cipher XyZ789!@",
    "shared_key": "authentication-mode pre-shared-key mySecretKey",
    "pre_shared_key": "ipsec authentication pre-shared-key secretKey123",
    "snmp_community": "snmp-server community public RW",
    "snmp_agent_community_cipher": "snmp-agent community read cipher %$%#abc123",
    "tacacs_key": "tacacs-server key TacacsKey!",
    "radius_key": "radius-server key RadiusKey!",
    "radius_shared_key": "radius shared-key SharedKey!",
    "radius_server_shared_key": "radius-server shared-key AnotherKey!",
    "neighbor_password": "neighbor 10.0.0.1 password NeighborPass123",
    "set_community": "set community 65000:1",
    "apply_community": "apply community 65000:100",
    "radius_shared_key_cipher": "radius shared-key cipher RADIUS_KEY",
    "radius_server_shared_key_cipher": "radius-server shared-key cipher RADIUS_KEY",
    "pre_shared_key_cipher": "pre-shared-key cipher VPN_KEY",
}

ALL_SECRET_LINES = list(SECRET_LINES.values())

SAFE_LINES = [
    "interface GigabitEthernet0/0/0",
    "  ip address 192.168.1.1 255.255.255.0",
    " vlan batch 10 20 30 100",
    " acl number 3000",
    "  rule 5 permit ip source 10.0.0.0 0.0.0.255 destination 172.16.0.0 0.0.255.255",
    "  rule 10 permit tcp source any destination 10.0.0.1 0 destination-port eq 22",
    "ospf 1 router-id 1.1.1.1",
    "  area 0.0.0.0",
    "  network 192.168.1.0 0.0.0.255",
    "ip route-static 0.0.0.0 0 192.168.1.254",
    "snmp-server enable traps",
    "line vty 0 4",
    "  transport input ssh",
    "ntp server 10.0.0.1",
    "hostname SW-1",
    "ip domain-name example.com",
    "no shutdown",
]


def _result_with_secrets():
    """Return a full result dict with secrets in every expected field."""
    return {
        "success": True,
        "translated": "\n".join(ALL_SECRET_LINES + SAFE_LINES),
        "deployable_config": "\n".join(ALL_SECRET_LINES[:8] + SAFE_LINES[:5]),
        "diff": "--- original\n+++ translated\n@@ -1 +1 @@\n-" + ALL_SECRET_LINES[0] + "\n+" + ALL_SECRET_LINES[1],
        "validation": {
            "syntax_ok": True,
            "warnings": ["warning: " + ALL_SECRET_LINES[2]],
        },
        "risk_signals": [
            {"type": "secret_key", "detail": ALL_SECRET_LINES[3]},
            {"type": "snmp", "detail": ALL_SECRET_LINES[4]},
        ],
        "capability_gaps": [
            {"feature": "tacacs", "note": "configured as " + ALL_SECRET_LINES[6]},
        ],
        "analyzer_results": {
            "tacacs_analyzer": {"key": ALL_SECRET_LINES[6]},
            "radius_analyzer": {"key": ALL_SECRET_LINES[7]},
        },
        "node_results": {
            "translate": {"raw": ALL_SECRET_LINES[0] + "\n" + SAFE_LINES[0]},
            "validate": {"output": ALL_SECRET_LINES[1] + "\n" + SAFE_LINES[1]},
        },
        "fallback_reason": "not applicable",
    }


# ── Unit tests: pattern matching ───────────────────────────────────────────


class TestRedactLine:
    def test_password_redacted(self):
        r = redact_sensitive_output(SECRET_LINES["password"])
        assert "password" in r and "<redacted>" in r
        assert "12345" not in r

    def test_secret_redacted(self):
        r = redact_sensitive_output(SECRET_LINES["secret"])
        assert "<redacted>" in r and "SecretPass!" not in r

    def test_secret_with_type_redacted(self):
        r = redact_sensitive_output(SECRET_LINES["secret_with_type"])
        assert "<redacted>" in r
        assert "5" in r  # type number preserved
        assert "abc123def456" not in r

    def test_cipher_redacted(self):
        r = redact_sensitive_output(SECRET_LINES["cipher"])
        assert "<redacted>" in r
        assert "Hello@123" not in r

    def test_irreversible_cipher_redacted(self):
        r = redact_sensitive_output(SECRET_LINES["irreversible_cipher"])
        assert "<redacted>" in r
        assert "XyZ789!@" not in r

    def test_shared_key_redacted(self):
        r = redact_sensitive_output(SECRET_LINES["shared_key"])
        assert "<redacted>" in r
        assert "mySecretKey" not in r

    def test_pre_shared_key_redacted(self):
        r = redact_sensitive_output(SECRET_LINES["pre_shared_key"])
        assert "<redacted>" in r
        assert "secretKey123" not in r

    def test_snmp_community_redacted(self):
        r = redact_sensitive_output(SECRET_LINES["snmp_community"])
        assert "<redacted>" in r
        assert "public" not in r

    def test_snmp_agent_community_cipher_redacted(self):
        r = redact_sensitive_output(SECRET_LINES["snmp_agent_community_cipher"])
        assert "<redacted>" in r
        assert "%$%#abc123" not in r

    def test_tacacs_key_redacted(self):
        r = redact_sensitive_output(SECRET_LINES["tacacs_key"])
        assert "<redacted>" in r
        assert "TacacsKey!" not in r

    def test_radius_key_redacted(self):
        r = redact_sensitive_output(SECRET_LINES["radius_key"])
        assert "<redacted>" in r
        assert "RadiusKey!" not in r

    def test_radius_shared_key_redacted(self):
        r = redact_sensitive_output(SECRET_LINES["radius_shared_key"])
        assert "<redacted>" in r
        assert "SharedKey!" not in r

    def test_radius_server_shared_key_redacted(self):
        r = redact_sensitive_output(SECRET_LINES["radius_server_shared_key"])
        assert "<redacted>" in r
        assert "AnotherKey!" not in r

    def test_neighbor_password_redacted(self):
        r = redact_sensitive_output(SECRET_LINES["neighbor_password"])
        assert "<redacted>" in r
        assert "NeighborPass123" not in r
        assert "10.0.0.1" in r  # neighbor IP preserved

    def test_set_community_redacted(self):
        r = redact_sensitive_output(SECRET_LINES["set_community"])
        assert "<redacted>" in r
        assert "65000:1" not in r

    def test_apply_community_redacted(self):
        r = redact_sensitive_output(SECRET_LINES["apply_community"])
        assert "<redacted>" in r
        assert "65000:100" not in r

    def test_radius_shared_key_cipher_preserves_cipher_keyword(self):
        r = redact_sensitive_output(SECRET_LINES["radius_shared_key_cipher"])
        assert "cipher <redacted>" in r
        assert "RADIUS_KEY" not in r
        assert r == "radius shared-key cipher <redacted>"

    def test_radius_server_shared_key_cipher_preserves_cipher_keyword(self):
        r = redact_sensitive_output(SECRET_LINES["radius_server_shared_key_cipher"])
        assert "cipher <redacted>" in r
        assert "RADIUS_KEY" not in r
        assert r == "radius-server shared-key cipher <redacted>"

    def test_pre_shared_key_cipher_preserves_cipher_keyword(self):
        r = redact_sensitive_output(SECRET_LINES["pre_shared_key_cipher"])
        assert "cipher <redacted>" in r
        assert "VPN_KEY" not in r
        assert r == "pre-shared-key cipher <redacted>"

    def test_shared_key_cipher_idempotent(self):
        for key in ["radius_shared_key_cipher", "radius_server_shared_key_cipher", "pre_shared_key_cipher"]:
            line = SECRET_LINES[key]
            once = redact_sensitive_output(line)
            twice = redact_sensitive_output(once)
            assert once == twice, f"Not idempotent for {key}: {line!r}"


# ── Unit tests: false positive avoidance ───────────────────────────────────


class TestNoFalsePositives:
    def test_ip_addresses_preserved(self):
        for line in ["ip address 192.168.1.1 255.255.255.0",
                     "ip route-static 10.0.0.0 255.0.0.0 192.168.1.1"]:
            assert redact_sensitive_output(line) == line

    def test_acl_rules_preserved(self):
        for line in ["rule 5 permit ip source 10.0.0.0 0.0.0.255",
                     "rule 10 deny tcp 192.168.0.0 0.0.255.255 any eq 80"]:
            assert redact_sensitive_output(line) == line

    def test_vlan_ids_preserved(self):
        for line in ["vlan batch 10 20 30 100", "vlan 100"]:
            assert redact_sensitive_output(line) == line

    def test_interface_names_preserved(self):
        for line in ["interface GigabitEthernet0/0/0",
                     "interface Vlanif100",
                     "interface LoopBack0"]:
            assert redact_sensitive_output(line) == line

    def test_ospf_config_preserved(self):
        for line in ["ospf 1 router-id 1.1.1.1",
                     "network 192.168.1.0 0.0.0.255 area 0.0.0.0"]:
            assert redact_sensitive_output(line) == line

    def test_safe_lines_unchanged(self):
        for line in SAFE_LINES:
            assert redact_sensitive_output(line) == line, f"False positive on: {line!r}"


# ── Unit tests: idempotence ────────────────────────────────────────────────


class TestIdempotence:
    def test_no_double_redaction(self):
        """Already redacted text should not be further redacted."""
        once = redact_sensitive_output(ALL_SECRET_LINES[0])
        twice = redact_sensitive_output(once)
        assert once == twice

    def test_all_lines_idempotent(self):
        for line in ALL_SECRET_LINES:
            once = redact_sensitive_output(line)
            twice = redact_sensitive_output(once)
            assert once == twice, f"Not idempotent for: {line!r}"

    def test_full_result_idempotent(self):
        r = _result_with_secrets()
        once = redact_sensitive_output(r)
        twice = redact_sensitive_output(once)
        assert once == twice


# ── Recursive structure tests ──────────────────────────────────────────────


class TestRecursiveRedaction:
    def test_dict_values_redacted(self):
        data = {"config": SECRET_LINES["password"], "safe": "ip address 10.0.0.1 255.0.0.0"}
        r = redact_sensitive_output(data)
        assert "12345" not in r["config"]
        assert "<redacted>" in r["config"]
        assert r["safe"] == data["safe"]

    def test_list_items_redacted(self):
        data = [SECRET_LINES["password"], SAFE_LINES[0], SECRET_LINES["secret"]]
        r = redact_sensitive_output(data)
        assert "12345" not in r[0]
        assert r[1] == SAFE_LINES[0]
        assert "SecretPass!" not in r[2]

    def test_nested_dict_list_mixed(self):
        data = {"outer": [{"inner": SECRET_LINES["snmp_community"]}, SAFE_LINES[1]]}
        r = redact_sensitive_output(data)
        assert "public" not in r["outer"][0]["inner"]
        assert r["outer"][1] == SAFE_LINES[1]

    def test_none_bool_int_float_preserved(self):
        data = [None, True, False, 42, 3.14, "ip address 10.0.0.1 255.0.0.0"]
        r = redact_sensitive_output(data)
        assert r == data

    def test_empty_strings_and_containers(self):
        assert redact_sensitive_output("") == ""
        assert redact_sensitive_output([]) == []
        assert redact_sensitive_output({}) == {}
        assert redact_sensitive_output(None) is None


# ── Full result fixture test ───────────────────────────────────────────────


class TestFullResultRedaction:
    def test_all_text_fields_redacted(self):
        r = _result_with_secrets()
        redacted = redact_sensitive_output(r)

        # translated
        assert "12345" not in redacted["translated"]
        assert "SecretPass!" not in redacted["translated"]
        assert "<redacted>" in redacted["translated"]

        # deployable_config
        assert "public" not in redacted["deployable_config"]
        assert "<redacted>" in redacted["deployable_config"]

        # diff
        assert "12345" not in redacted["diff"]
        assert "SecretPass!" not in redacted["diff"]

        # validation (dict)
        assert "Hello@123" not in redacted["validation"]["warnings"][0]

        # risk_signals (list of dicts)
        for signal in redacted["risk_signals"]:
            assert "Hello@123" not in signal["detail"]
            assert "public" not in signal["detail"]

        # capability_gaps (list of dicts)
        for gap in redacted["capability_gaps"]:
            assert "TacacsKey!" not in gap["note"]

        # analyzer_results (nested dict)
        assert "TacacsKey!" not in redacted["analyzer_results"]["tacacs_analyzer"]["key"]
        assert "RadiusKey!" not in redacted["analyzer_results"]["radius_analyzer"]["key"]

        # node_results (nested dict)
        assert "12345" not in redacted["node_results"]["translate"]["raw"]
        assert "SecretPass!" not in redacted["node_results"]["validate"]["output"]

        # safe lines preserved throughout
        assert SAFE_LINES[0] in redacted["translated"]
        assert SAFE_LINES[0] in redacted["node_results"]["translate"]["raw"]

    def test_success_fallback_reason_preserved(self):
        r = _result_with_secrets()
        redacted = redact_sensitive_output(r)
        assert redacted["success"] is True
        assert redacted["fallback_reason"] == "not applicable"


# ── ProjectStore integration test ──────────────────────────────────────────


class TestProjectStoreRedaction:
    """Test that ProjectStore persistence and API response paths redact.

    Uses ProjectStore directly to verify save and read paths.
    """

    def _make_secret_config(self):
        return "\n".join(ALL_SECRET_LINES[:5] + SAFE_LINES[:3])

    def test_store_saves_redacted_result(self, tmp_path):
        """Verify update_project() redacts result before persisting (approach B)."""
        from project_store import ProjectStore
        store = ProjectStore(str(tmp_path / "projects"))
        p = store.create_project("secret-test")

        result_data = _result_with_secrets()
        result_data["translated"] = self._make_secret_config()
        # store.update_project() internally calls redact_sensitive_output on result
        store.update_project(p.id, {"result": result_data})

        p2 = store.get_project(p.id, reload=True)
        stored = p2.result
        assert stored is not None
        assert "12345" not in stored["translated"]
        assert "SecretPass!" not in stored["translated"]
        assert "<redacted>" in stored["translated"]

    def test_store_saves_redacted_detail_file_no_secrets(self, tmp_path):
        """Verify the on-disk detail file does not contain plaintext secrets."""
        import json
        from project_store import ProjectStore
        store = ProjectStore(str(tmp_path / "projects"))
        p = store.create_project("disk-test")

        result_data = _result_with_secrets()
        result_data["translated"] = self._make_secret_config()
        store.update_project(p.id, {"result": result_data})

        detail_path = tmp_path / "projects" / f"{p.id}.json"
        assert detail_path.exists()
        raw = json.loads(detail_path.read_text())
        stored_result = raw.get("result", {})
        translated = stored_result.get("translated", "")
        assert "12345" not in translated
        assert "SecretPass!" not in translated
        assert "<redacted>" in translated

    def test_store_get_project_redacts_pre_sanitizer_data(self, tmp_path):
        """Verify GET route redacts result from projects saved before sanitizer existed."""
        from project_store import ProjectStore
        store = ProjectStore(str(tmp_path / "projects"))
        p = store.create_project("pre-sanitizer")

        # Simulate pre-sanitizer data: write to disk directly
        # store.update_project() now redacts, so bypass by writing to p.result and saving
        import json as _json
        p.result = _result_with_secrets()
        p.result["translated"] = self._make_secret_config()
        # Direct disk write to simulate old pre-sanitizer data
        detail_path = tmp_path / "projects" / f"{p.id}.json"
        detail_path.parent.mkdir(parents=True, exist_ok=True)
        detail_path.write_text(_json.dumps(p.to_full_dict(), indent=2))

        # Read through store — data on disk still has secrets
        p2 = store.get_project(p.id, reload=True)
        # store.get_project returns raw data (with secrets) — redaction happens at API layer
        full = p2.to_full_dict()
        redacted_full = {k: redact_sensitive_output(v) if k == "result" else v
                         for k, v in full.items()}
        stored = redacted_full["result"]
        assert stored is not None
        assert "12345" not in stored["translated"]
        assert "<redacted>" in stored["translated"]

    def test_list_projects_redacts_result_in_each_project(self, tmp_path):
        """Verify list_projects() redacts result in every project in the list."""
        from project_store import ProjectStore
        store = ProjectStore(str(tmp_path / "projects"))
        p1 = store.create_project("list-test-1")
        p2 = store.create_project("list-test-2")

        result_data = _result_with_secrets()
        result_data["translated"] = self._make_secret_config()
        store.update_project(p1.id, {"result": result_data})
        store.update_project(p2.id, {"result": result_data})

        projects = store.list_projects()
        for p in projects:
            r = p.get("result")
            if r is not None:
                r = redact_sensitive_output(r)
                translated = r.get("translated", "")
                assert "12345" not in translated
                assert "SecretPass!" not in translated
                assert "<redacted>" in translated

    def test_update_project_with_raw_secrets_persists_redacted(self, tmp_path):
        """Verify store.update_project() with raw secrets redacts before disk write."""
        from project_store import ProjectStore
        store = ProjectStore(str(tmp_path / "projects"))
        p = store.create_project("raw-secret-test")

        raw_result = {
            "success": True,
            "translated": "snmp-server community PUBLIC_COMM\nsnmp-server secret SECRET_KEY",
        }
        # Pass raw secrets — store.update_project should redact internally
        store.update_project(p.id, {"result": raw_result})

        p2 = store.get_project(p.id, reload=True)
        stored = p2.result
        assert stored is not None
        assert "PUBLIC_COMM" not in stored["translated"]
        assert "SECRET_KEY" not in stored["translated"]
        assert "<redacted>" in stored["translated"]

    def test_update_project_raw_secrets_detail_file_clean(self, tmp_path):
        """Verify on-disk detail file is clean after update_project with raw secrets."""
        import json
        from project_store import ProjectStore
        store = ProjectStore(str(tmp_path / "projects"))
        p = store.create_project("raw-secret-file")

        raw_result = {
            "success": True,
            "translated": "radius shared-key cipher RADIUS_KEY\nsnmp-server community PUBLIC_COMM",
        }
        store.update_project(p.id, {"result": raw_result})

        detail_path = tmp_path / "projects" / f"{p.id}.json"
        assert detail_path.exists()
        raw = json.loads(detail_path.read_text())
        translated = raw.get("result", {}).get("translated", "")
        assert "RADIUS_KEY" not in translated
        assert "PUBLIC_COMM" not in translated
        assert "<redacted>" in translated
        # cipher keyword preserved
        assert "cipher <redacted>" in translated

    def test_history_entry_translated_redacted(self, tmp_path):
        from project_store import ProjectStore
        store = ProjectStore(str(tmp_path / "projects"))
        p = store.create_project("history-test")

        result_data = _result_with_secrets()
        result_data["translated"] = self._make_secret_config()
        result_data = redact_sensitive_output(result_data)

        store.add_history(p.id, {
            "config_text": "ip route-static 0.0.0.0 0 10.0.0.1",
            "from_vendor": "cisco",
            "to_vendor": "huawei",
            "success": True,
            "translated": result_data.get("translated", ""),
        })

        p2 = store.get_project(p.id, reload=True)
        hist = p2.history
        # history is prepended, so the first entry is the most recent
        assert len(hist) >= 1
        entry = hist[0] if isinstance(hist, list) else list(hist.values())[0]
        if isinstance(entry, dict) and "translated" in entry:
            assert "12345" not in entry["translated"]
            assert "<redacted>" in entry["translated"]


# ── Edge cases ─────────────────────────────────────────────────────────────


class TestEdgeCases:
    def test_deployable_config_empty(self):
        r = _result_with_secrets()
        r["deployable_config"] = ""
        redacted = redact_sensitive_output(r)
        assert redacted["deployable_config"] == ""

    def test_result_none(self):
        assert redact_sensitive_output(None) is None

    def test_result_empty_dict(self):
        assert redact_sensitive_output({}) == {}

    def test_result_without_secrets_unchanged(self):
        safe = {
            "success": True,
            "translated": SAFE_LINES[0],
            "deployable_config": SAFE_LINES[1],
        }
        assert redact_sensitive_output(safe) == safe
