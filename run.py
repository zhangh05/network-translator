#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Translator - 入口文件
支持命令行交互和批量翻译
"""

import re
import sys
import os
from pathlib import Path

# 添加项目根目录
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.graph.agent import GraphAgent
from llm_settings import create_llm_from_settings
from tools import ConfigParser


def _parse_direction(user_input: str) -> tuple[str, str]:
    """Extract from_vendor/to_vendor from user input, fallback to auto."""
    from_v, to_v = "auto", "huawei"
    m = re.search(r"(?:从|from)\s*[:：]\s*(\S+)", user_input, re.IGNORECASE)
    if m:
        from_v = m.group(1).lower().strip()
    m = re.search(r"(?:到|to)\s*[:：]\s*(\S+)", user_input, re.IGNORECASE)
    if m:
        to_v = m.group(1).lower().strip()
    return from_v, to_v


def _extract_config(user_input: str) -> str:
    """Strip direction directives from input to get clean config text."""
    text = re.sub(r"(?:从|from)\s*[:：]\s*\S+", "", user_input, flags=re.IGNORECASE)
    text = re.sub(r"(?:到|to)\s*[:：]\s*\S+", "", text, flags=re.IGNORECASE)
    text = re.sub(r"^\s*翻译\s*[:：]", "", text)
    return text.strip() or user_input


def main():
    print("=" * 60)
    print("  网络配置翻译助手 (Graph Architecture)")
    print("  Network Configuration Translator - AI Powered")
    print("=" * 60)
    print()

    # 初始化 Agent
    agent = GraphAgent(
        knowledge_dir=str(project_root / "knowledge_data"),
        memory_dir=str(project_root / "memory_data"),
        llm=create_llm_from_settings(),
    )

    print(f"Agent: {agent.name}")
    print("Workflow: " + agent.visualize().splitlines()[0])
    print()
    print("输入 'help' 查看使用帮助，输入 'quit' 退出")
    print("-" * 60)

    while True:
        try:
            user_input = input("\n你: ").strip()
            if not user_input:
                continue

            if user_input.lower() in ["quit", "exit", "q"]:
                print("\n感谢使用！再见！")
                break

            if user_input.lower() == "help":
                print("""
# 帮助

## 支持的翻译方向
- Cisco → Huawei
- Huawei → Cisco
- Huawei ↔ H3C
- H3C v5 ↔ v7

## 使用方式

### 方式1：直接粘贴配置
```
请翻译这段 Cisco 配置到华为：
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
router ospf 1
 network 192.168.1.0 0.0.0.255 area 0
```

### 方式2：指定翻译方向
```
翻译: [配置内容]
从: cisco
到: huawei
```

### 方式3：查询历史
```
查看翻译历史
```
""")
                continue

            # 解析翻译方向
            from_vendor, to_vendor = _parse_direction(user_input)
            config_text = _extract_config(user_input)

            if from_vendor == "auto" and "interface" in config_text.lower():
                from_vendor = ConfigParser().detect_vendor(config_text)

            print(f"\n方向: {from_vendor} → {to_vendor}")

            # 执行翻译
            result = agent.run(
                config_text=config_text,
                from_vendor=from_vendor,
                to_vendor=to_vendor,
            )
            translated = result.get("translated", str(result))
            print("\n" + translated)

        except KeyboardInterrupt:
            print("\n\n已退出")
            break
        except Exception as e:
            print(f"\n错误: {e}")


if __name__ == "__main__":
    main()
