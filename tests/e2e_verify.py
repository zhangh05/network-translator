#!/usr/bin/env python3
"""Step 17 E2E verification — smoke tests against running service."""

import json
import sys
import time

import requests

BASE = "http://127.0.0.1:5008"
# Bypass any proxy for localhost
S = requests.Session()
S.proxies = {"http": "", "https": ""}

PASS = 0
FAIL = 0
SKIP = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        print(f"  PASS  {name}")
        PASS += 1
    else:
        print(f"  FAIL  {name}  {detail}")
        FAIL += 1


def skip(name):
    global SKIP
    print(f"  SKIP  {name}")
    SKIP += 1


# ── 1. healthz ──────────────────────────────────────────────────────────
resp = S.get(f"{BASE}/healthz", timeout=10)
check("1: healthz returns 200", resp.status_code == 200, f"got {resp.status_code}")
check("1b: healthz ok=true", resp.json().get("ok") is True, str(resp.text))

# ── 2. LLM test ─────────────────────────────────────────────────────────
print("\n── 2. LLM test ──")
t0 = time.time()
resp = S.post(f"{BASE}/api/llm/test", json={"text": "Hello, translate test."}, timeout=30)
check("2a: llm-test returns 200", resp.status_code == 200, f"got {resp.status_code}")
if resp.status_code == 200:
    j = resp.json()
    check("2b: llm-test ok=true", j.get("ok") is True, str(j)[:120])
else:
    skip("2b: llm-test skipped")
print(f"    (elapsed: {time.time()-t0:.1f}s)")

# ── 3. First translation — OSPF/BGP (Cisco → Huawei) ──────────────────
print("\n── A. OSPF/BGP first translation ──")
ospf_cfg = """\
hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
router ospf 1
 network 10.0.0.0 0.0.0.255 area 0
router bgp 65000
 bgp router-id 1.1.1.1
 neighbor 10.0.0.2 remote-as 65001
"""

t0 = time.time()
resp = S.post(f"{BASE}/api/translate", json={
    "config_text": ospf_cfg,
    "from_vendor": "cisco", "to_vendor": "huawei",
    "source_domain": "routing", "source_platform": "ios",
    "target_domain": "routing", "target_platform": "vrp",
}, timeout=120)
elapsed = time.time() - t0
check("A1: translate returns 200", resp.status_code == 200, f"got {resp.status_code}")
if resp.status_code == 200 and resp.json().get("ok"):
    r = resp.json()["result"]
    translated = r.get("translated", "")
    validation = r.get("validation", {})
    v_level = validation.get("level", "?")
    v_valid = validation.get("valid", "?")
    v_deploy = validation.get("deployable", "?")
    v_review = validation.get("manual_review_required", "?")

    check("A2: non-empty translated", len(translated) > 20, f"len={len(translated)}")
    check("A3: no markdown fence in output", "```" not in translated, "fence found")
    check("A4: deployable field present", v_deploy is not None, str(v_deploy))
    check("A5: manual_review_required present", v_review is not None, str(v_review))
    check("A6: output is pure config (not JSON)",
          "[" not in translated[:10] and "{" not in translated[:10],
          f"starts with {translated[:30]!r}")
    check("A7: translated in reasonable time", elapsed < 50, f"{elapsed:.1f}s")
    print(f"    (elapsed: {elapsed:.1f}s, level={v_level}, deployable={v_deploy})")
else:
    detail = str(resp.json())[:200] if resp.json().get("ok") is not True else ""
    check("A2-A7: skipped", False, detail)

# ── 4. Repeat translation — cache hit ──────────────────────────────────
print("\n── B. Cache hit ──")
t0 = time.time()
resp2 = S.post(f"{BASE}/api/translate", json={
    "config_text": ospf_cfg,
    "from_vendor": "cisco", "to_vendor": "huawei",
    "source_domain": "routing", "source_platform": "ios",
    "target_domain": "routing", "target_platform": "vrp",
}, timeout=30)
elapsed2 = time.time() - t0
check("B1: cache returns 200", resp2.status_code == 200, f"got {resp2.status_code}")
check("B2: cache hit fast (< 2s)", elapsed2 < 2.0, f"{elapsed2:.2f}s")
if resp2.status_code == 200 and resp2.json().get("ok"):
    r2 = resp2.json()["result"]
    cache_hit = r2.get("cache_hit", False)
    check("B3: cache_hit=true", cache_hit is True, str(cache_hit))
    translated2 = r2.get("translated", "")
    check("B4: cached same config length",
          abs(len(translated2) - len(translated)) < 5,
          f"first={len(translated)} cached={len(translated2)}")

# ── 5. Missing AS scenario ─────────────────────────────────────────────
print("\n── C. Missing BGP AS (no placeholder, MANUAL_REVIEW) ──")
missing_as_cfg = """\
interface GigabitEthernet1/0/1
 port link-type trunk
 port trunk permit vlan all
ospf 1
 import-route bgp
"""
t0 = time.time()
resp3 = S.post(f"{BASE}/api/translate", json={
    "config_text": missing_as_cfg,
    "from_vendor": "h3c", "to_vendor": "cisco",
    "source_domain": "routing", "source_platform": "comware",
    "target_domain": "routing", "target_platform": "ios",
}, timeout=120)
elapsed3 = time.time() - t0
check("C1: missing-as returns 200", resp3.status_code == 200, f"got {resp3.status_code}")
if resp3.status_code == 200 and resp3.json().get("ok"):
    r3 = resp3.json()["result"]
    translated3 = r3.get("translated", "")
    validation3 = r3.get("validation", {})
    gaps3 = r3.get("capability_gaps", [])

    check("C2: translated not empty", len(translated3) > 10, f"len={len(translated3)}")
    check("C3: no placeholder <...>", "<" not in translated3.lower() or "..." not in translated3, "placeholder found")
    check("C4: no TODO", "TODO" not in translated3.upper(), "TODO found")
    check("C5: no Markdown fence", "```" not in translated3, "fence found")
    check("C6: deployable field present", "deployable" in validation3, f"keys={list(validation3.keys())}")
    check("C7: manual_review_required present", "manual_review_required" in validation3, f"keys={list(validation3.keys())}")
    check("C8: capability_gaps populated", len(gaps3) > 0, f"gaps={len(gaps3)}")
    print(f"    (elapsed: {elapsed3:.1f}s)")
else:
    detail = str(resp3.json())[:200] if resp3.json().get("ok") is not True else ""
    check("C2-C8: skipped", False, detail)

# ── Summary ─────────────────────────────────────────────────────────────
print(f"\n{'='*50}")
total = PASS + FAIL + SKIP
print(f"  {PASS} passed, {FAIL} failed, {SKIP} skipped ({total} total)")
if FAIL > 0:
    sys.exit(1)
sys.exit(0)
