import pytest
from core.parser.shared import (
    parse_vlan_range, render_vlan_range,
    cidr_to_mask, mask_to_cidr,
    wildcard_to_mask, mask_to_wildcard,
    split_config_blocks, normalize_interface_name,
)


class TestParseVlanRange:
    def test_single(self):
        assert parse_vlan_range("10") == [10]

    def test_range_with_dash(self):
        assert parse_vlan_range("1-5") == [1, 2, 3, 4, 5]

    def test_space_separated(self):
        assert parse_vlan_range("1 3 5") == [1, 3, 5]

    def test_comma_separated(self):
        assert parse_vlan_range("1,3,5") == [1, 3, 5]

    def test_mixed(self):
        assert parse_vlan_range("1,3-5 7") == [1, 3, 4, 5, 7]

    def test_empty_string(self):
        assert parse_vlan_range("") == []

    def test_none_string(self):
        assert parse_vlan_range("none") == []

    def test_duplicates_deduped(self):
        assert parse_vlan_range("1,1,1") == [1]

    def test_to_keyword(self):
        assert parse_vlan_range("1 to 5") == [1, 2, 3, 4, 5]


class TestRenderVlanRange:
    def test_single(self):
        assert render_vlan_range([10]) == "10"

    def test_sequence(self):
        result = render_vlan_range([1, 2, 3, 5, 7, 8, 9])
        assert "1 to 3" in result
        assert "5" in result
        assert "7 to 9" in result

    def test_empty(self):
        assert render_vlan_range([]) == ""

    def test_duplicates(self):
        assert render_vlan_range([1, 1, 2]) == "1 to 2"


class TestCidrToMask:
    def test_24(self):
        assert cidr_to_mask(24) == "255.255.255.0"

    def test_32(self):
        assert cidr_to_mask(32) == "255.255.255.255"

    def test_0(self):
        assert cidr_to_mask(0) == "0.0.0.0"

    def test_16(self):
        assert cidr_to_mask(16) == "255.255.0.0"

    def test_30(self):
        assert cidr_to_mask(30) == "255.255.255.252"

    def test_invalid_negative(self):
        with pytest.raises(ValueError):
            cidr_to_mask(-1)

    def test_invalid_33(self):
        with pytest.raises(ValueError):
            cidr_to_mask(33)


class TestMaskToCidr:
    def test_255_255_255_0(self):
        assert mask_to_cidr("255.255.255.0") == 24

    def test_255_255_0_0(self):
        assert mask_to_cidr("255.255.0.0") == 16

    def test_255_0_0_0(self):
        assert mask_to_cidr("255.0.0.0") == 8

    def test_0_0_0_0(self):
        assert mask_to_cidr("0.0.0.0") == 0

    def test_255_255_255_255(self):
        assert mask_to_cidr("255.255.255.255") == 32


class TestWildcardToMask:
    def test_0_0_0_255(self):
        assert wildcard_to_mask("0.0.0.255") == "255.255.255.0"

    def test_0_0_255_255(self):
        assert wildcard_to_mask("0.0.255.255") == "255.255.0.0"


class TestMaskToWildcard:
    def test_255_255_255_0(self):
        assert mask_to_wildcard("255.255.255.0") == "0.0.0.255"

    def test_255_255_0_0(self):
        assert mask_to_wildcard("255.255.0.0") == "0.0.255.255"


class TestSplitConfigBlocks:
    def test_simple(self):
        text = "vlan 10\n port access vlan 10\nvlan 20"
        blocks = split_config_blocks(text)
        assert len(blocks) == 2
        assert blocks[0][0] == "vlan 10\nport access vlan 10"
        assert blocks[1][0] == "vlan 20"

    def test_empty(self):
        assert split_config_blocks("") == []

    def test_ignores_comments(self):
        text = "! this is a comment\nvlan 10\n! another comment\nvlan 20"
        blocks = split_config_blocks(text)
        assert len(blocks) == 2

    def test_single_line_blocks(self):
        text = "hostname SW01\nsnmp-server community public ro"
        blocks = split_config_blocks(text)
        assert len(blocks) == 2


class TestNormalizeInterfaceName:
    def test_vlan_interface_to_vlan(self):
        assert normalize_interface_name("Vlan-interface100") == "Vlan100"

    def test_vlanif_to_vlan(self):
        assert normalize_interface_name("Vlanif100") == "Vlan100"

    def test_bridge_aggregation_to_port_channel(self):
        assert normalize_interface_name("Bridge-Aggregation1") == "PortChannel1"

    def test_eth_trunk_to_port_channel(self):
        assert normalize_interface_name("Eth-Trunk1") == "PortChannel1"

    def test_port_channel(self):
        assert normalize_interface_name("Port-channel1") == "PortChannel1"

    def test_port_channel_lowercase(self):
        assert normalize_interface_name("port-channel1") == "PortChannel1"

    def test_loopback(self):
        assert normalize_interface_name("Loopback0") == "Loopback0"

    def test_tunnel(self):
        assert normalize_interface_name("Tunnel0") == "Tunnel0"

    def test_unchanged(self):
        assert normalize_interface_name("GigabitEthernet0/1") == "GigabitEthernet0/1"
