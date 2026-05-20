"""P0-3: LLM output structure validation and repair tests."""
import pytest
from core.ir import validate_and_repair_llm_output


# ═══════════════════════════════════════════════════════════════════
# Valid JSON
# ═══════════════════════════════════════════════════════════════════

class TestValidJson:
    def test_clean_json_array(self):
        raw = '''[{"type": "interface", "translated_lines": ["interface GigabitEthernet0/0"], "original_lines": ["interface GigabitEthernet0/0"], "notes": "", "confidence": 0.9}]'''
        r = validate_and_repair_llm_output(raw, "cisco", "huawei")
        assert r["ok"]
        assert len(r["parsed"]) == 1
        assert r["parsed"][0]["type"] == "interface"

    def test_multiple_items(self):
        raw = '''[
            {"type": "vlan", "translated_lines": ["vlan 10"], "original_lines": ["vlan 10"], "notes": "", "confidence": 0.9},
            {"type": "interface", "translated_lines": ["interface GigabitEthernet0/0"], "original_lines": ["interface GigabitEthernet0/0"], "notes": "", "confidence": 0.8}
        ]'''
        r = validate_and_repair_llm_output(raw, "cisco", "huawei")
        assert r["ok"]
        assert len(r["parsed"]) == 2


# ═══════════════════════════════════════════════════════════════════
# Markdown fence wrapping
# ═══════════════════════════════════════════════════════════════════

class TestMarkdownFence:
    def test_fence_wrapped_json(self):
        raw = '''```json
[{"type": "interface", "translated_lines": ["interface GigabitEthernet0/0"], "original_lines": [""], "notes": "", "confidence": 0.9}]
```'''
        r = validate_and_repair_llm_output(raw, "cisco", "huawei")
        assert r["ok"]
        assert any("代码围栏" in x for x in r["repairs"])

    def test_fence_without_lang(self):
        raw = '''```
[{"type": "ospf", "translated_lines": ["router ospf 1"], "original_lines": [""], "notes": "", "confidence": 0.9}]
```'''
        r = validate_and_repair_llm_output(raw, "cisco", "huawei")
        assert r["ok"]


# ═══════════════════════════════════════════════════════════════════
# Explanatory text before/after JSON
# ═══════════════════════════════════════════════════════════════════

class TestExplanatoryText:
    def test_text_before_json(self):
        raw = '''以下是翻译结果：
[{"type": "interface", "translated_lines": ["interface GigabitEthernet0/0"], "original_lines": [""], "notes": "", "confidence": 0.9}]
'''
        r = validate_and_repair_llm_output(raw, "cisco", "huawei")
        assert r["ok"]
        assert any("前导文本" in x for x in r["repairs"])

    def test_text_after_json(self):
        raw = '''[{"type": "interface", "translated_lines": ["interface GigabitEthernet0/0"], "original_lines": [""], "notes": "", "confidence": 0.9}]
以上是翻译结果。'''
        r = validate_and_repair_llm_output(raw, "cisco", "huawei")
        assert r["ok"]
        assert any("尾部文本" in x for x in r["repairs"])

    def test_text_both_sides(self):
        raw = '''翻译：
[{"type": "vlan", "translated_lines": ["vlan batch 10 20"], "original_lines": [""], "notes": "", "confidence": 0.9}]
请核查。'''
        r = validate_and_repair_llm_output(raw, "cisco", "huawei")
        assert r["ok"]
        assert any("前导文本" in x for x in r["repairs"])
        assert any("尾部文本" in x for x in r["repairs"])


# ═══════════════════════════════════════════════════════════════════
# Missing required fields
# ═══════════════════════════════════════════════════════════════════

class TestMissingFields:
    def test_missing_translated_lines(self):
        raw = '''[{"type": "interface", "original_lines": [""], "notes": "", "confidence": 0.9}]'''
        r = validate_and_repair_llm_output(raw, "cisco", "huawei")
        assert r["ok"]
        repairs = " ".join(r["repairs"])
        assert "missing" in repairs or "translated_lines" in repairs
        assert r["parsed"][0].get("translated_lines") == []

    def test_missing_confidence(self):
        raw = '''[{"type": "interface", "translated_lines": ["line"], "original_lines": [""], "notes": ""}]'''
        r = validate_and_repair_llm_output(raw, "cisco", "huawei")
        assert r["ok"]
        assert r["parsed"][0].get("confidence") == 0.5

    def test_missing_type(self):
        raw = '''[{"translated_lines": ["line"], "original_lines": [""], "notes": "", "confidence": 0.9}]'''
        r = validate_and_repair_llm_output(raw, "cisco", "huawei")
        assert r["ok"]
        assert r["parsed"][0].get("type") == "unknown"

    def test_empty_notes_with_empty_translation(self):
        raw = '''[{"type": "nat", "translated_lines": [], "original_lines": [""], "notes": "", "confidence": 0.9}]'''
        r = validate_and_repair_llm_output(raw, "cisco", "huawei")
        assert r["ok"]
        assert any("notes" in x for x in r["repairs"])


# ═══════════════════════════════════════════════════════════════════
# Type errors
# ═══════════════════════════════════════════════════════════════════

class TestTypeErrors:
    def test_translated_lines_not_list(self):
        raw = '''[{"type": "interface", "translated_lines": "interface GigabitEthernet0/0", "original_lines": [""], "notes": "", "confidence": 0.9}]'''
        r = validate_and_repair_llm_output(raw, "cisco", "huawei")
        assert r["ok"]
        assert r["parsed"][0]["translated_lines"] == []

    def test_confidence_not_numeric(self):
        raw = '''[{"type": "interface", "translated_lines": ["line"], "original_lines": [""], "notes": "", "confidence": "high"}]'''
        r = validate_and_repair_llm_output(raw, "cisco", "huawei")
        assert r["ok"]
        assert isinstance(r["parsed"][0]["confidence"], float)


# ═══════════════════════════════════════════════════════════════════
# Placeholder detection
# ═══════════════════════════════════════════════════════════════════

class TestPlaceholderDetection:
    def test_todo_placeholder(self):
        raw = '''[{"type": "interface", "translated_lines": ["interface GigabitEthernet0/0", "description TODO: configure"], "original_lines": [""], "notes": "", "confidence": 0.9}]'''
        r = validate_and_repair_llm_output(raw, "cisco", "huawei")
        assert not r["ok"]
        assert any("占位符" in e for e in r["errors"])

    def test_angle_bracket_placeholder(self):
        raw = '''[{"type": "interface", "translated_lines": ["interface <name>"], "original_lines": [""], "notes": "", "confidence": 0.9}]'''
        r = validate_and_repair_llm_output(raw, "cisco", "huawei")
        assert not r["ok"]
        assert any("占位符" in e for e in r["errors"])


# ═══════════════════════════════════════════════════════════════════
# Empty / null input
# ═══════════════════════════════════════════════════════════════════

class TestEmptyInput:
    def test_empty_string(self):
        r = validate_and_repair_llm_output("", "cisco", "huawei")
        assert not r["ok"]
        assert any("为空" in e for e in r["errors"])

    def test_whitespace_only(self):
        r = validate_and_repair_llm_output("   \n  ", "cisco", "huawei")
        assert not r["ok"]
        assert any("为空" in e for e in r["errors"])


# ═══════════════════════════════════════════════════════════════════
# Non-JSON / malformed
# ═══════════════════════════════════════════════════════════════════

class TestMalformed:
    def test_not_json_at_all(self):
        r = validate_and_repair_llm_output("这是一段普通文字", "cisco", "huawei")
        assert not r["ok"]

    def test_empty_array(self):
        r = validate_and_repair_llm_output("[]", "cisco", "huawei")
        assert not r["ok"]
        assert any("空数组" in e for e in r["errors"])

    def test_single_object_not_array(self):
        r = validate_and_repair_llm_output('{"type": "test", "translated_lines": []}', "cisco", "huawei")
        assert not r["ok"]
        assert any("不是数组" in e or "不是对象" in e for e in r["errors"])


# ═══════════════════════════════════════════════════════════════════
# Item is not dict
# ═══════════════════════════════════════════════════════════════════

class TestNonDictItem:
    def test_string_item(self):
        raw = '''["just a string"]'''
        r = validate_and_repair_llm_output(raw, "cisco", "huawei")
        assert not r["ok"]
        assert any("不是对象" in e for e in r["errors"])


# ═══════════════════════════════════════════════════════════════════
# Repairs metadata inserted
# ═══════════════════════════════════════════════════════════════════

class TestRepairsMetadata:
    def test_repairs_logged(self):
        raw = '''```json
[{"type": "vlan", "translated_lines": ["vlan 10"], "original_lines": [""], "notes": "", "confidence": 0.9}]
```'''
        r = validate_and_repair_llm_output(raw, "cisco", "huawei")
        assert r["ok"]
        assert any("代码围栏" in x for x in r["repairs"]), f"Expected fence repair, got: {r['repairs']}"


# ═══════════════════════════════════════════════════════════════════
# Source vendor residue detection
# ═══════════════════════════════════════════════════════════════════

class TestSourceVendorResidue:
    """P0-4: Step 7 residue detection in validate_and_repair_llm_output.

    Residue is non-fatal but must be observable in repairs list.
    """

    def test_cisco_residue_in_huawei_output(self):
        raw = '''[{"type": "interface", "translated_lines": ["interface GigabitEthernet0/0", "description See cisco reference"], "original_lines": [""], "notes": "", "confidence": 0.9}]'''
        r = validate_and_repair_llm_output(raw, "cisco", "huawei")
        assert r["ok"], f"Residue should be repair, not error: {r['errors']}"
        assert any("源厂商残留" in x for x in r["repairs"]), f"Expected residue repair, got: {r['repairs']}"

    def test_huawei_residue_in_cisco_output(self):
        raw = '''[{"type": "system", "translated_lines": ["hostname R1", "huawei command style"], "original_lines": [""], "notes": "", "confidence": 0.9}]'''
        r = validate_and_repair_llm_output(raw, "huawei", "cisco")
        assert r["ok"], f"Residue should be repair, not error: {r['errors']}"
        assert any("源厂商残留" in x for x in r["repairs"]), f"Expected residue repair, got: {r['repairs']}"

    def test_no_residue_clean_output(self):
        raw = '''[{"type": "interface", "translated_lines": ["interface GigabitEthernet0/0", "description To core"], "original_lines": [""], "notes": "", "confidence": 0.9}]'''
        r = validate_and_repair_llm_output(raw, "cisco", "huawei")
        assert r["ok"]
        assert not any("源厂商残留" in x for x in r["repairs"]), "Clean output flagged for residue"

    def test_h3c_residue_detected(self):
        raw = '''[{"type": "system", "translated_lines": ["system-view", "h3c style commands"], "original_lines": [""], "notes": "", "confidence": 0.9}]'''
        r = validate_and_repair_llm_output(raw, "h3c", "cisco")
        assert r["ok"]
        assert any("源厂商残留" in x for x in r["repairs"]), f"H3C residue not detected: {r['repairs']}"

    def test_manual_review_line_not_flagged(self):
        raw = '''[{"type": "nat", "translated_lines": ["MANUAL_REVIEW: Cisco command needs review"], "original_lines": [""], "notes": "", "confidence": 0.9}]'''
        r = validate_and_repair_llm_output(raw, "cisco", "huawei")
        assert r["ok"]
        assert not any("源厂商残留" in x for x in r["repairs"]), "MANUAL_REVIEW line should not be residue"
