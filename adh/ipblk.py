#!/usr/bin/env python3
import sys
from pathlib import Path

def diff_rules(a_file: str, b_file: str, output_file: str = 'adh/ip-blocklist.txt'):
    """计算 a - b：a 中不在 b 中的规则，输出到 output_file"""
    b_rules = set()
    
    # 加载 b 到 set（去重，忽略空白/注释）
    print("Loading b rules into set...")
    with open(b_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith(('#', '!')):
                b_rules.add(line)
    print(f"Loaded {len(b_rules)} unique rules from b.")
    
    # 遍历 a，输出不在 b 中的行
    print("Processing a and writing diff...")
    unique_count = 0
    with open(a_file, 'r', encoding='utf-8', errors='ignore') as a_f, \
         open(output_file, 'w', encoding='utf-8') as out_f:
        for line in a_f:
            line = line.strip()
            if line and not line.startswith(('#', '!')) and line not in b_rules:
                out_f.write(line + '\n')
                unique_count += 1
    
    print(f"Output: {unique_count} unique rules from a - b to {output_file}")

if __name__ == "__main__":
    a_file = 'adh/blocklist.txt'
    b_file = 'adh/domain-blocklist.txt'
    diff_rules(a_file, b_file)
