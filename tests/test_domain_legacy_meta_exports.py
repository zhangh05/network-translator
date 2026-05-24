
def test_core_domain_exports_legacy_meta_for_web_api():
    from core.domain import ALL_DOMAINS, ALL_VENDORS, DOMAIN_VENDORS, VENDOR_PLATFORMS

    assert "routing" in ALL_DOMAINS
    assert "switching" in ALL_DOMAINS
    assert "firewall" in ALL_DOMAINS
    assert {"cisco", "huawei", "h3c", "ruijie", "hillstone", "topsec", "dptech"}.issubset(set(ALL_VENDORS))
    assert "ruijie" in DOMAIN_VENDORS["switching"]
    assert "hillstone" in DOMAIN_VENDORS["firewall"]
    assert "usg" in VENDOR_PLATFORMS["huawei"]
