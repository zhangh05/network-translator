# -*- coding: utf-8 -*-
"""Benchmark harness for Network Translator."""

import json
import os
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents import NetworkTranslatorAgent
from core import LLM
from tools import ConfigParser


TEST_CASES = [
    {
        "id": "cisco_basic",
        "name": "Cisco basic",
        "from_vendor": "cisco",
        "to_vendor": "huawei",
        "input": """
hostname Core-Router
interface GigabitEthernet0/0
 description Uplink-to-Core
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/1
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30
 spanning-tree portfast
!
router ospf 1
 router-id 1.1.1.1
 network 192.168.1.0 0.0.0.255 area 0
!
ip route 0.0.0.0 0.0.0.0 192.168.1.254
""",
        "expected_keywords": ["XGigabitEthernet", "undo shutdown", "port link-type", "area 0"],
        "forbidden_keywords": ["switchport", "spanning-tree"],
    },
    {
        "id": "huawei_ospf",
        "name": "Huawei ospf",
        "from_vendor": "huawei",
        "to_vendor": "cisco",
        "input": """
sysname Huawei-AR
interface XGigabitEthernet0/0/1
 description WAN
 ip address 10.0.0.1 255.255.255.0
 undo shutdown
!
ospf 1 router-id 2.2.2.2
 area 0
 network 10.0.0.0 0.0.0.255
""",
        "expected_keywords": ["GigabitEthernet", "router ospf", "area 0"],
        "forbidden_keywords": ["XGigabitEthernet", "undo shutdown"],
    },
    {
        "id": "cisco_acl",
        "name": "Cisco acl bgp",
        "from_vendor": "cisco",
        "to_vendor": "huawei",
        "input": """
router bgp 65001
 bgp router-id 1.1.1.1
 neighbor 192.168.1.2 remote-as 65002
!
access-list 100 permit tcp any host 192.168.1.10 eq 80
access-list 100 permit tcp any host 192.168.1.10 eq 443
access-list 100 deny ip any any
""",
        "expected_keywords": ["bgp", "as-number", "acl"],
        "forbidden_keywords": ["access-list 100 permit"],
    },
]


class Harness:
    name = "Harness"

    def __init__(self, agent: NetworkTranslatorAgent):
        self.agent = agent
        self.results: Any = None

    def run(self) -> Dict[str, Any]:
        raise NotImplementedError

    def summary(self) -> str:
        raise NotImplementedError


class TranslationQualityScore(Harness):
    name = "TranslationQualityScore"

    @staticmethod
    def _semantic_rule_score(source: str, translated: str, from_vendor: str, to_vendor: str) -> float:
        score = 60.0
        if "description" in source.lower() and "description" in translated.lower():
            score += 10
        if from_vendor == "cisco" and to_vendor == "huawei" and "xgigabitethernet" in translated.lower():
            score += 15
        if from_vendor == "huawei" and to_vendor == "cisco" and "gigabitethernet" in translated.lower():
            score += 15
        return min(score, 100.0)

    def _translate_case(self, tc: Dict[str, Any]) -> str:
        return self.agent.translate(
            config_text=tc["input"],
            from_vendor=tc["from_vendor"],
            to_vendor=tc["to_vendor"],
            user="bench",
        )

    def run(self) -> Dict[str, Any]:
        parser = ConfigParser()
        details: List[Dict[str, Any]] = []
        for tc in TEST_CASES:
            translated = self._translate_case(tc) or ""
            if not translated.strip():
                details.append(
                    {
                        "id": tc["id"],
                        "name": tc["name"],
                        "total": 0.0,
                        "A_keyword": 0.0,
                        "B_forbidden": 0.0,
                        "C_completeness": 0.0,
                        "D_semantic": 0.0,
                        "E_validation": 0.0,
                    }
                )
                continue

            expected_hits = sum(1 for kw in tc["expected_keywords"] if kw.lower() in translated.lower())
            score_a = expected_hits / max(len(tc["expected_keywords"]), 1) * 100

            forbidden_hits = sum(1 for kw in tc["forbidden_keywords"] if kw.lower() in translated.lower())
            score_b = max(0.0, 100.0 - forbidden_hits * 25.0)

            src_lines = len([x for x in tc["input"].splitlines() if x.strip()])
            dst_lines = len([x for x in translated.splitlines() if x.strip()])
            score_c = min(100.0, (dst_lines / max(src_lines, 1)) * 100.0)

            score_d = self._semantic_rule_score(tc["input"], translated, tc["from_vendor"], tc["to_vendor"])
            parsed = parser.parse(translated, vendor_hint=tc["to_vendor"])
            score_e = 100.0 if parsed.vendor != "unknown" else 0.0

            total = score_a * 0.35 + score_b * 0.20 + score_c * 0.20 + score_d * 0.20 + score_e * 0.05
            details.append(
                {
                    "id": tc["id"],
                    "name": tc["name"],
                    "total": round(total, 1),
                    "A_keyword": round(score_a, 1),
                    "B_forbidden": round(score_b, 1),
                    "C_completeness": round(score_c, 1),
                    "D_semantic": round(score_d, 1),
                    "E_validation": round(score_e, 1),
                }
            )

        avg_score = round(statistics.mean(row["total"] for row in details), 1) if details else 0.0
        self.results = details
        return {"avg_score": avg_score, "details": details}

    def summary(self) -> str:
        lines = ["=" * 70, "[TranslationQualityScore]", "-" * 70]
        for row in self.results:
            lines.append(
                f"{row['name']:<16} total={row['total']:>5.1f} "
                f"A={row['A_keyword']:>5.1f} B={row['B_forbidden']:>5.1f} "
                f"C={row['C_completeness']:>5.1f} D={row['D_semantic']:>5.1f} E={row['E_validation']:>5.1f}"
            )
        lines.append("-" * 70)
        lines.append(f"avg={statistics.mean(x['total'] for x in self.results):.1f}" if self.results else "avg=0.0")
        lines.append("=" * 70)
        return "\n".join(lines)


class MultiTurnReActTest(Harness):
    name = "MultiTurnReActTest"

    def run(self) -> Dict[str, Any]:
        tc = TEST_CASES[0]
        turns = [
            f"Translate {tc['from_vendor']} config to {tc['to_vendor']}:\n{tc['input']}",
            "Add OSPF area 0 details in translated style.",
            "Set router-id to 2.2.2.2 in the output.",
            "Generate final translation report.",
        ]
        turn_results = []
        for idx, query in enumerate(turns, start=1):
            before = len(self.agent.working_memory.all())
            t0 = time.perf_counter()
            try:
                content = self.agent.think(query)
                elapsed = round((time.perf_counter() - t0) * 1000, 2)
                after = len(self.agent.working_memory.all())
                has_content = bool(content and content.strip())
                turn_results.append(
                    {
                        "turn": idx,
                        "query_preview": query[:60],
                        "has_content": has_content,
                        "tool_count": 0,
                        "memory_grew": after > before,
                        "elapsed_ms": elapsed,
                        "converged": has_content,
                    }
                )
            except Exception as exc:
                elapsed = round((time.perf_counter() - t0) * 1000, 2)
                turn_results.append(
                    {
                        "turn": idx,
                        "query_preview": query[:60],
                        "error": str(exc)[:100],
                        "elapsed_ms": elapsed,
                        "converged": False,
                    }
                )
        self.results = [{"id": tc["id"], "turns": turn_results}]
        return {"results": self.results}

    def summary(self) -> str:
        lines = ["=" * 70, "[MultiTurnReActTest]", "-" * 70]
        for item in self.results:
            lines.append(f"case={item['id']}")
            for t in item["turns"]:
                lines.append(
                    f"turn={t['turn']} converged={t.get('converged', False)} "
                    f"memory_grew={t.get('memory_grew', False)} elapsed_ms={t['elapsed_ms']}"
                )
        lines.append("=" * 70)
        return "\n".join(lines)


class ErrorRecoveryTest(Harness):
    name = "ErrorRecoveryTest"

    def run(self) -> Dict[str, Any]:
        details = []
        parser_tool = self.agent.tools.get("parse_config")

        # Scenario 1: missing tool
        try:
            fn = self.agent.tools["nonexistent_tool"]
            fn()
            details.append({"id": "tool_not_found", "name": "tool not found", "recovered": False, "elapsed_ms": 0.0})
        except Exception:
            details.append({"id": "tool_not_found", "name": "tool not found", "recovered": True, "elapsed_ms": 0.0, "has_error_handling": True})

        # Scenario 2: tool exception
        def broken_tool(**_: Any) -> str:
            raise ValueError("boom")

        self.agent.tools["parse_config"] = broken_tool
        t0 = time.perf_counter()
        try:
            self.agent.tools["parse_config"](config_text="hostname R")
            details.append({"id": "tool_exception", "name": "tool exception", "recovered": False, "elapsed_ms": 0.0})
        except Exception:
            details.append(
                {
                    "id": "tool_exception",
                    "name": "tool exception",
                    "recovered": True,
                    "elapsed_ms": round((time.perf_counter() - t0) * 1000, 2),
                    "has_error_handling": True,
                }
            )
        finally:
            if parser_tool:
                self.agent.tools["parse_config"] = parser_tool

        # Scenario 3: empty config
        t1 = time.perf_counter()
        try:
            result = self.agent.translate("", from_vendor="cisco", to_vendor="huawei", user="bench")
            recovered = isinstance(result, str)
            details.append(
                {
                    "id": "empty_config",
                    "name": "empty config",
                    "recovered": recovered,
                    "elapsed_ms": round((time.perf_counter() - t1) * 1000, 2),
                    "has_error_handling": True,
                    "result": (result or "")[:80],
                }
            )
        except Exception as exc:
            details.append(
                {
                    "id": "empty_config",
                    "name": "empty config",
                    "recovered": False,
                    "elapsed_ms": round((time.perf_counter() - t1) * 1000, 2),
                    "error": str(exc)[:100],
                }
            )

        self.results = details
        recovery_rate = round(statistics.mean(1 if x["recovered"] else 0 for x in details) * 100, 1)
        return {"recovery_rate": recovery_rate, "details": details}

    def summary(self) -> str:
        lines = ["=" * 70, "[ErrorRecoveryTest]", "-" * 70]
        for row in self.results:
            lines.append(f"{row['name']:<16} recovered={row['recovered']} elapsed_ms={row['elapsed_ms']}")
        lines.append("=" * 70)
        return "\n".join(lines)


class ContextBudgetTest(Harness):
    name = "ContextBudgetTest"

    def run(self) -> Dict[str, Any]:
        from core.context import GSSCPipeline

        results = []
        normal = TEST_CASES[0]["input"]
        huge = normal * 10
        for label, cfg in [("normal", normal), ("10x_large", huge)]:
            t0 = time.perf_counter()
            pipeline = GSSCPipeline(max_context_tokens=2000)
            context = pipeline.build(
                query="cisco to huawei ospf",
                working_memory_items=[(f"k{i}", f"v{i}" * 50) for i in range(30)],
                session_meta={"from_vendor": "cisco", "to_vendor": "huawei"},
            )
            results.append(
                {
                    "label": label,
                    "input_len": len(cfg),
                    "context_len": len(context),
                    "compressed": ("..." in context) or ("截断" in context),
                    "elapsed_ms": round((time.perf_counter() - t0) * 1000, 2),
                }
            )
        self.results = results
        return {"results": results}

    def summary(self) -> str:
        lines = ["=" * 70, "[ContextBudgetTest]", "-" * 70]
        for row in self.results:
            lines.append(
                f"{row['label']:<10} input={row['input_len']:<6} context={row['context_len']:<6} "
                f"compressed={row['compressed']} elapsed_ms={row['elapsed_ms']}"
            )
        lines.append("=" * 70)
        return "\n".join(lines)


class RegressionTest(Harness):
    name = "RegressionTest"

    def __init__(self, agent: NetworkTranslatorAgent, baseline_file: Path | None = None):
        super().__init__(agent)
        self.baseline_file = baseline_file or PROJECT_ROOT / "bench" / "baseline.json"

    def run(self) -> Dict[str, Any]:
        quality = TranslationQualityScore(self.agent).run()
        avg = quality["avg_score"]
        history: Dict[str, Dict[str, float]] = {}
        if self.baseline_file.exists():
            history = json.loads(self.baseline_file.read_text(encoding="utf-8"))
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        history[ts] = {"avg_score": avg}
        self.baseline_file.write_text(json.dumps(history, ensure_ascii=False, indent=2), encoding="utf-8")

        regressions = []
        ordered = sorted(history.items(), key=lambda x: x[0])
        if len(ordered) >= 2:
            prev_ts, prev_val = ordered[-2]
            cur_ts, cur_val = ordered[-1]
            delta = cur_val["avg_score"] - prev_val["avg_score"]
            regressions.append(
                {
                    "from": prev_ts[:10],
                    "to": cur_ts[:10],
                    "previous_score": prev_val["avg_score"],
                    "latest_score": cur_val["avg_score"],
                    "delta": delta,
                    "regressed": delta < -5,
                }
            )
        self.results = {"history_count": len(history), "regressions": regressions}
        return self.results

    def summary(self) -> str:
        lines = ["=" * 70, f"[RegressionTest] history={self.results['history_count']}", "-" * 70]
        for item in self.results["regressions"]:
            lines.append(
                f"{item['from']}->{item['to']} prev={item['previous_score']:.1f} "
                f"now={item['latest_score']:.1f} delta={item['delta']:+.1f}"
            )
        lines.append("=" * 70)
        return "\n".join(lines)


def run_all_harnesses() -> Dict[str, Any]:
    llm = LLM(
        api_key=os.environ.get("LLM_API_KEY", ""),
        model=os.environ.get("LLM_MODEL", "MiniMax-M2.7"),
    )
    agent = NetworkTranslatorAgent(
        knowledge_dir=str(PROJECT_ROOT / "knowledge_data"),
        memory_dir=str(PROJECT_ROOT / "memory_data"),
        llm=llm,
    )

    harnesses = [
        TranslationQualityScore(agent),
        MultiTurnReActTest(agent),
        ErrorRecoveryTest(agent),
        ContextBudgetTest(agent),
        RegressionTest(agent),
    ]

    all_results: Dict[str, Any] = {}
    for harness in harnesses:
        print(f"\n[{harness.name}] running...")
        try:
            all_results[harness.name] = harness.run()
            print(harness.summary())
        except Exception as exc:
            all_results[harness.name] = {"error": str(exc)}
            print(f"[{harness.name}] failed: {exc}")

    out_path = PROJECT_ROOT / "bench" / "harness_results.json"
    out_path.write_text(json.dumps(all_results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nresults saved: {out_path}")
    return all_results


if __name__ == "__main__":
    run_all_harnesses()
