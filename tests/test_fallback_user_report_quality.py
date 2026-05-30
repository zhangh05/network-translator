import pytest
from core.graph import State
from core.graph.nodes import FallbackNode


def _state(from_v, to_v, error, config):
    s = State()
    s.set("from_vendor", from_v)
    s.set("to_vendor", to_v)
    s.set("translate_error", error)
    s.set("config_text", config)
    return s


def _report_lines(text):
    return [l for l in text.splitlines() if l.startswith("!")]


class TestHuaweiToCiscoFallbackReportQuality:

    def test_huawei_vlan_and_acl_falls_back_cleanly(self):
        state = _state(
            "huawei", "cisco",
            "LLM 输出校验失败: 第 0 项不是对象",
            "sysname HW-SW\nvlan batch 10 20\nacl number 3000\n rule 5 permit ip\n",
        )
        FallbackNode().execute(state)

        report = state.get("translated_config", "")
        deployable = state.get("deployable_config", "")

        assert "MANUAL_REVIEW" in report
        assert "fallback_reason=" not in report
        assert "block_count=" not in report
        assert "第 0 项不是对象" not in report
        assert "hostname HW-SW" in deployable
        assert "vlan 10,20" in deployable
        assert state.get("fallback_reason") == "LLM 输出不是结构化翻译结果，已切换到规则兜底"
        assert "vlan batch" not in deployable
        assert "rule 5 permit ip" not in deployable

    def test_huawei_qos_traffic_policy_goes_to_manual_review(self):
        state = _state(
            "huawei", "cisco",
            "LLM 输出校验失败: 输出包含无效字段",
            "sysname HW-SW\ntraffic classifier TC operator and\n if-match acl 3000\ntraffic behavior TB\n qos car cir 100000",
        )
        FallbackNode().execute(state)

        report = state.get("translated_config", "")
        metadata = state.get("_fallback_metadata", {})

        assert "MANUAL_REVIEW" in report
        assert "fallback_reason=" not in report
        assert "traffic classifier TC" in report
        assert isinstance(metadata.get("block_count"), int)
        assert metadata.get("source_vendor") == "huawei"
        assert metadata.get("target_vendor") == "cisco"

    def test_huawei_aaa_local_user_password_is_redacted(self):
        state = _state(
            "huawei", "cisco",
            "LLM 输出校验失败: 第 0 项不是对象",
            "aaa\n local-user admin password irreversible-cipher SuperPassword123\n",
        )
        FallbackNode().execute(state)

        report = state.get("translated_config", "")
        deployable = state.get("deployable_config", "")

        assert "SuperPassword123" not in report
        assert "SuperPassword123" not in deployable
        assert "MANUAL_REVIEW" in report


class TestCiscoToHuaweiFallbackReportQuality:

    def test_cisco_acl_to_huawei_manual_review_with_rule_fallback(self):
        state = _state(
            "cisco", "huawei",
            "LLM 输出校验失败: 第 0 项不是对象",
            "ip access-list extended ACL-FW\n permit tcp any host 10.0.1.100 eq 80\n",
        )
        FallbackNode().execute(state)

        report = state.get("translated_config", "")
        deployable = state.get("deployable_config", "")

        assert "MANUAL_REVIEW" in report
        assert "fallback_reason=" not in report
        assert "ACL 与安全策略" in report
        assert "ACL-FW" in report


class TestTopsecToHuaweiUSGFallbackReportQuality:

    def test_topsec_policy_to_huawei_usg_manual_review(self):
        state = _state(
            "topsec", "huawei_usg",
            "LLM 输出校验失败: 第 0 项不是对象",
            "policy id 1\n name P1\n action accept\n src-zone trust\n dst-zone untrust\n",
        )
        FallbackNode().execute(state)

        report = state.get("translated_config", "")
        metadata = state.get("_fallback_metadata", {})

        assert "MANUAL_REVIEW" in report
        assert "fallback_reason=" not in report
        assert metadata.get("source_vendor") == "topsec"
        assert metadata.get("target_vendor") == "huawei_usg"


class TestHillstoneToTopsecFallbackReportQuality:

    def test_hillstone_zone_policy_to_topsec_manual_review(self):
        state = _state(
            "hillstone", "topsec",
            "LLM 输出校验失败: 第 0 项不是对象",
            "zone trust\n zone untrust\n policy from trust to untrust\n  action accept\n",
        )
        FallbackNode().execute(state)

        report = state.get("translated_config", "")
        deployable = state.get("deployable_config", "")
        manual_review = state.get("manual_review_config", "")

        assert "MANUAL_REVIEW" in report
        assert "fallback_reason=" not in report
        assert "block_count=" not in report
        assert "zone trust" in report
        assert "MANUAL_REVIEW" not in deployable
        assert "zone trust" in manual_review


class TestMixedUnsupportedCommandsQuality:

    def test_mixed_unsupported_shows_multiple_categories(self):
        state = _state(
            "huawei", "cisco",
            "LLM 输出校验失败: 第 0 项不是对象",
            """sysname Multi-Device
vlan batch 100 200 300
aaa
 local-user admin password irreversible-cipher SecretKey99
interface Vlanif100
 ip address 10.0.100.1 255.255.255.0
traffic classifier C1 operator and
 if-match acl 4000
traffic behavior B1
 qos car pir 50000
acl number 4000
 rule 10 permit tcp
""",
        )
        FallbackNode().execute(state)

        report = state.get("translated_config", "")
        metadata = state.get("_fallback_metadata", {})

        assert "MANUAL_REVIEW" in report
        assert "fallback_reason=" not in report
        assert "block_count=" not in report
        assert "SecretKey99" not in report
        assert "SecretKey99" not in state.get("deployable_config", "")

        cats = metadata.get("feature_summary", {})
        assert isinstance(cats, dict)
        assert len(cats) >= 3

        report_text = report.lower()
        has_management = any(k in report_text for k in ["管理面", "aaa", "local-user"])
        has_interface = any(k in report_text for k in ["接口", "vlan", "interface"])
        has_acl = any(k in report_text for k in ["acl", "访问控制"])
        assert has_management or has_interface or has_acl

    def test_deployable_config_contains_only_deterministic_fallback(self):
        state = _state(
            "huawei", "cisco",
            "LLM 输出校验失败: 第 0 项不是对象",
            "sysname HW\nvlan batch 10\nip route-static 0.0.0.0 0.0.0.0 10.0.0.254\n",
        )
        FallbackNode().execute(state)

        deployable = state.get("deployable_config", "")
        report = state.get("translated_config", "")

        assert "hostname HW" in deployable
        assert "vlan 10" in deployable
        assert "ip route 0.0.0.0 0.0.0.0 10.0.0.254" in deployable
        assert "MANUAL_REVIEW" in report
        assert "人工复核摘要" in report
        assert "fallback_reason=" not in report
        assert "block_count=" not in report
        assert "第 0 项不是对象" not in report
        assert "analyzer missing" not in report


class TestMetadataSeparation:

    def test_metadata_stored_in_state_not_in_user_report(self):
        state = _state(
            "huawei", "cisco",
            "LLM 输出校验失败: 输出不包含 JSON",
            "sysname HW2\nvlan batch 5\n",
        )
        FallbackNode().execute(state)

        report = state.get("translated_config", "")

        assert "source_vendor=" not in report
        assert "target_vendor=" not in report
        assert "fallback_reason=" not in report
        assert "block_count=" not in report
        assert "feature_summary=" not in report

        metadata = state.get("_fallback_metadata", {})
        assert metadata.get("source_vendor") == "huawei"
        assert metadata.get("target_vendor") == "cisco"
        assert state.get("fallback_reason") is not None
        assert state.get("block_count") is not None

    def test_error_detail_not_leaked_to_user(self):
        state = _state(
            "huawei", "cisco",
            "LLM 输出校验失败: analyzer missing for object type",
            "sysname LeakTest\nvlan batch 99\n",
        )
        FallbackNode().execute(state)

        report = state.get("translated_config", "")

        assert "analyzer missing" not in report
        assert "LLM 输出校验失败" not in report
        assert "MANUAL_REVIEW" in report
