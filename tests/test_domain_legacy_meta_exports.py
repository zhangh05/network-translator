
def test_core_domain_exports_legacy_meta_for_web_api():
    from core.domain import ALL_DOMAINS, ALL_VENDORS, DOMAIN_VENDORS, VENDOR_PLATFORMS, get_all_features

    assert "routing" in ALL_DOMAINS
    assert "switching" in ALL_DOMAINS
    assert "firewall" in ALL_DOMAINS
    assert {"cisco", "huawei", "h3c", "ruijie", "hillstone", "topsec", "dptech"}.issubset(set(ALL_VENDORS))
    assert "ruijie" in DOMAIN_VENDORS["switching"]
    assert "hillstone" in DOMAIN_VENDORS["firewall"]
    assert "usg" in VENDOR_PLATFORMS["huawei"]
    assert "vlan" in get_all_features()


def test_domain_meta_api_returns_feature_list():
    from web_app import create_app

    app = create_app()
    with app.test_client() as client:
        resp = client.get("/api/domain/meta")

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert "vlan" in data["features"]
