import subprocess
import sys

from tools import ConfigParser, KnowledgeRetriever


def test_cli_starts_and_exits_cleanly():
    result = subprocess.run(
        [sys.executable, "run.py"],
        input="quit\n",
        text=True,
        capture_output=True,
        timeout=10,
    )

    assert result.returncode == 0
    assert "AttributeError" not in result.stderr


def test_config_parser_keeps_router_sections_out_of_interfaces():
    config = """hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
!
router ospf 1
 network 10.0.0.0 0.0.0.255 area 0
!
vlan 10
"""

    parsed = ConfigParser().parse(config)

    assert parsed.vendor == "cisco"
    assert [iface.name for iface in parsed.interfaces] == ["GigabitEthernet0/0"]
    assert parsed.interfaces[0].raw_lines == [
        "interface GigabitEthernet0/0",
        " ip address 10.0.0.1 255.255.255.0",
    ]
    assert parsed.ospf_configs == [
        "router ospf 1",
        " network 10.0.0.0 0.0.0.255 area 0",
    ]
    assert parsed.vlans == [10]


def test_knowledge_retriever_falls_back_to_markdown_knowledge_data():
    info = KnowledgeRetriever("knowledge_data").get_all_mapping_info("cisco", "huawei")

    assert "翻译方向: cisco → huawei" in info
    assert "port trunk allow-pass vlan" in info
