#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import ipaddress
from pathlib import Path
import sys
from typing import List, Set, Dict, Any

# -----------------------------------------------------------------------------
# 核心功能：IP CIDR 合并
# -----------------------------------------------------------------------------
def merge_cidrs(cidrs_list: Set[str]) -> List[str]:
    """
    合并重叠和相邻的 IP CIDR。
    使用 ipaddress.collapse_addresses 来高效处理 IPv4 和 IPv6。
    """
    v4_nets = []
    v6_nets = []
    
    for cidr_str in cidrs_list:
        if not cidr_str:
            continue
        try:
            # 允许如 1.1.1.1 这种单个 IP
            net = ipaddress.ip_network(cidr_str.strip(), strict=False)
            if net.version == 4:
                v4_nets.append(net)
            else:
                v6_nets.append(net)
        except ValueError as e:
            print(f"  [警告] 忽略无效的 IP/CIDR: '{cidr_str}' ({e})", file=sys.stderr)

    # 分别合并 v4 和 v6
    merged_v4 = list(ipaddress.collapse_addresses(v4_nets))
    merged_v6 = list(ipaddress.collapse_addresses(v6_nets))

    # 排序以确保一致的输出
    merged_v4.sort(key=lambda n: (n.network_address, n.prefixlen))
    merged_v6.sort(key=lambda n: (n.network_address, n.prefixlen))

    # 转换回字符串列表
    return [str(n) for n in merged_v4] + [str(n) for n in merged_v6]

# -----------------------------------------------------------------------------
# 核心功能：“操作 A” - JSON 规范化
# -----------------------------------------------------------------------------
def process_json_file(file_path: Path):
    """
    执行“操作 A”：
    1. 合并所有 rules 对象。
    2. 检查并报告未知键。
    3. 规范化 domain 和 domain_suffix。
    4. 合并和规范化 ip_cidr。
    5. 移除空项并重写文件。
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"  [错误] 无法解析 JSON: {file_path.name} ({e})", file=sys.stderr)
        return
    except IOError as e:
        print(f"  [错误] 无法读取文件: {file_path.name} ({e})", file=sys.stderr)
        return

    if 'rules' not in data or not isinstance(data['rules'], list):
        print(f"  [警告] 格式无效，跳过: {file_path.name}", file=sys.stderr)
        return

    # 允许的 sing-box 规则键
    allowed_keys = {
        'domain', 
        'domain_suffix', 
        'domain_keyword', 
        'domain_regex', 
        'ip_cidr'
    }

    # 1. 合并所有 rules 对象
    all_domains = set()
    all_domain_suffixes = set()
    all_domain_keywords = set()
    all_domain_regex = set()
    all_ip_cidrs = set()

    for rule_obj in data.get('rules', []):
        if not isinstance(rule_obj, dict):
            continue
        
        # 2. 检查未知键
        unknown_keys = set(rule_obj.keys()) - allowed_keys
        if unknown_keys:
            print(f"[致命错误] 在 {file_path.name} 中发现未知的规则键: {unknown_keys}", file=sys.stderr)
            print("脚本已中止。请检查 JSON 格式或更新脚本中的 'allowed_keys'。", file=sys.stderr)
            sys.exit(1) # 按要求中止脚本

        all_domains.update(rule_obj.get('domain', []))
        all_domain_suffixes.update(rule_obj.get('domain_suffix', []))
        all_domain_keywords.update(rule_obj.get('domain_keyword', []))
        all_domain_regex.update(rule_obj.get('domain_regex', []))
        all_ip_cidrs.update(rule_obj.get('ip_cidr', []))

    # 3. 规范化 domain 和 domain_suffix
    final_domains = set()
    final_domain_suffixes = set()

    # 将 domain_suffix -> domain
    for s in all_domain_suffixes:
        if s:
            final_domains.add(s.lstrip('.'))
            final_domain_suffixes.add(f".{s.lstrip('.')}") # 确保自身格式正确

    # 将 domain -> domain_suffix
    for d in all_domains:
        if d:
            final_domains.add(d.lstrip('.')) # 确保自身格式正确
            final_domain_suffixes.add(f".{d.lstrip('.')}")

    # 排序和去重（通过 set 已完成去重）
    sorted_domains = sorted(list(final_domains))
    sorted_suffixes = sorted(list(final_domain_suffixes))
    sorted_keywords = sorted(list(all_domain_keywords))
    sorted_regex = sorted(list(all_domain_regex))

    # 4. 合并和规范化 ip_cidr
    sorted_ips = merge_cidrs(all_ip_cidrs)

    # 5. 重构 JSON 对象
    domain_rule_obj = {}
    ip_rule_obj = {}

    if sorted_domains:
        domain_rule_obj['domain'] = sorted_domains
    if sorted_suffixes:
        domain_rule_obj['domain_suffix'] = sorted_suffixes
    if sorted_keywords:
        domain_rule_obj['domain_keyword'] = sorted_keywords
    if sorted_regex:
        domain_rule_obj['domain_regex'] = sorted_regex
    
    if sorted_ips:
        ip_rule_obj['ip_cidr'] = sorted_ips

    new_rules = []
    if domain_rule_obj: # 仅当存在至少一个域规则时才添加
        new_rules.append(domain_rule_obj)
    if ip_rule_obj: # 仅当存在 IP 规则时才添加
        new_rules.append(ip_rule_obj)

    # 按照您的“已处理”示例格式化
    new_data = {"version": 1, "rules": new_rules}

    # 6. 写回文件
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(new_data, f, indent=2, ensure_ascii=False)
    except IOError as e:
        print(f"  [错误] 无法写入文件: {file_path.name} ({e})", file=sys.stderr)

# -----------------------------------------------------------------------------
# 核心功能：查找和移除 cn/!cn 之间的重复项
# -----------------------------------------------------------------------------
def find_and_remove_dupes(file_cn_path: Path, file_noncn_path: Path, save_path: Path):
    """
    对比 cn 和 non-cn 文件：
    1. 找到所有键中的共同项。
    2. 将共同项保存到 save_path。
    3. 从 cn 和 non-cn 文件中移除共同项并保存。
    4. 对 save_path 文件执行“操作 A”以简化。
    """
    
    def get_rule_data(file_path: Path) -> Dict[str, Dict[str, Any]]:
        """从已处理的文件加载域和 IP 规则对象。"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            domain_obj = {}
            ip_obj = {}
            for rule in data.get('rules', []):
                if 'ip_cidr' in rule:
                    ip_obj = rule
                else:
                    # 假设所有非 IP 规则都是域规则
                    domain_obj.update(rule)
            return {"domain": domain_obj, "ip": ip_obj}
        except Exception:
            return {"domain": {}, "ip": {}}

    data_cn = get_rule_data(file_cn_path)
    data_noncn = get_rule_data(file_noncn_path)

    common_domain_obj = {}
    common_ip_obj = {}

    # --- 对比域规则 ---
    domain_keys = ['domain', 'domain_suffix', 'domain_keyword', 'domain_regex']
    for key in domain_keys:
        set_cn = set(data_cn["domain"].get(key, []))
        set_noncn = set(data_noncn["domain"].get(key, []))
        
        common_items = set_cn.intersection(set_noncn)
        
        if common_items:
            common_domain_obj[key] = sorted(list(common_items))
            
            # 更新原始对象（移除共同项）
            remaining_cn = sorted(list(set_cn - common_items))
            remaining_noncn = sorted(list(set_noncn - common_items))
            
            if remaining_cn:
                data_cn["domain"][key] = remaining_cn
            else:
                data_cn["domain"].pop(key, None) # 移除空列表的键
                
            if remaining_noncn:
                data_noncn["domain"][key] = remaining_noncn
            else:
                data_noncn["domain"].pop(key, None) # 移除空列表的键

    # --- 对比 IP 规则 ---
    key = 'ip_cidr'
    set_cn = set(data_cn["ip"].get(key, []))
    set_noncn = set(data_noncn["ip"].get(key, []))
    common_items = set_cn.intersection(set_noncn)

    if common_items:
        common_ip_obj[key] = sorted(list(common_items))
        
        remaining_cn = sorted(list(set_cn - common_items))
        remaining_noncn = sorted(list(set_noncn - common_items))
        
        if remaining_cn:
            data_cn["ip"][key] = remaining_cn
        else:
            data_cn["ip"] = {} # 整个 IP 对象置空
            
        if remaining_noncn:
            data_noncn["ip"][key] = remaining_noncn
        else:
            data_noncn["ip"] = {} # 整个 IP 对象置空

    # --- 写回文件 ---
    
    # 1. 保存共同项
    common_rules = []
    if common_domain_obj:
        common_rules.append(common_domain_obj)
    if common_ip_obj:
        common_rules.append(common_ip_obj)
        
    if common_rules:
        common_data = {"version": 1, "rules": common_rules}
        save_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(save_path, 'w', encoding='utf-8') as f:
                json.dump(common_data, f, indent=2, ensure_ascii=False)
            
            # 按要求，对 'same' 文件也执行一次操作 A
            process_json_file(save_path)
            
        except IOError as e:
            print(f"  [错误] 无法写入 'same' 文件: {save_path.name} ({e})", file=sys.stderr)

    # 2. 保存更新后的 cn 文件
    new_rules_cn = []
    if data_cn["domain"]:
        new_rules_cn.append(data_cn["domain"])
    if data_cn["ip"]:
        new_rules_cn.append(data_cn["ip"])
    
    try:
        with open(file_cn_path, 'w', encoding='utf-8') as f:
            json.dump({"version": 1, "rules": new_rules_cn}, f, indent=2, ensure_ascii=False)
    except IOError as e:
         print(f"  [错误] 无法写回 'cn' 文件: {file_cn_path.name} ({e})", file=sys.stderr)

    # 3. 保存更新后的 non-cn 文件
    new_rules_noncn = []
    if data_noncn["domain"]:
        new_rules_noncn.append(data_noncn["domain"])
    if data_noncn["ip"]:
        new_rules_noncn.append(data_noncn["ip"])
        
    try:
        with open(file_noncn_path, 'w', encoding='utf-8') as f:
            json.dump({"version": 1, "rules": new_rules_noncn}, f, indent=2, ensure_ascii=False)
    except IOError as e:
         print(f"  [错误] 无法写回 'non-cn' 文件: {file_noncn_path.name} ({e})", file=sys.stderr)

# -----------------------------------------------------------------------------
# 主执行函数
# -----------------------------------------------------------------------------
def main():
    srs_json_dir = Path("srs/json")
    same_dir = srs_json_dir / "same"
    same_dir.mkdir(exist_ok=True) # 确保 srs/json/same 目录存在

    # --- 阶段 1: 对 srs/json/ 目录中的所有 .json 执行“操作 A” ---
    print("--- 阶段 1: 正在对 srs/json/*.json 执行“操作 A” (规范化) ---")
    
    # 排除 'same' 目录中的 json
    json_files = [f for f in srs_json_dir.glob("*.json") if f.is_file()]
    
    if not json_files:
        print("  [警告] 在 srs/json/ 中未找到 .json 文件。")
    
    for json_file in json_files:
        print(f"  正在处理: {json_file.name}")
        process_json_file(json_file)
    print("--- 阶段 1 完成 ---")


    # --- 阶段 2: 对比 cn/non-cn 对，查找并移除重复项 ---
    print("\n--- 阶段 2: 正在对比 cn/non-cn 对并移除重复项 ---")
    
    # 定义要对比的文件对
    pairs = [
        ("ai-cn", "ai-noncn", "ai-same"),
        ("games-cn", "games-noncn", "games-same"),
        ("network-cn", "network-noncn", "network-same")
    ]
    
    for cn_name, noncn_name, same_name in pairs:
        cn_path = srs_json_dir / f"{cn_name}.json"
        noncn_path = srs_json_dir / f"{noncn_name}.json"
        same_path = same_dir / f"{same_name}.json"
        
        if cn_path.exists() and noncn_path.exists():
            print(f"  正在对比: {cn_name}.json 和 {noncn_name}.json")
            find_and_remove_dupes(cn_path, noncn_path, same_path)
        else:
            print(f"  [跳过] 缺少文件对: {cn_name}.json / {noncn_name}.json")
            
    print("--- 阶段 2 完成 ---")
    print("\n所有 JSON 处理和去重操作已完成。")

if __name__ == "__main__":
    # 确保脚本在 srs/json 目录的父目录中运行
    if not Path("srs/json").is_dir():
        print("[错误] 未找到 'srs/json' 目录。", file=sys.stderr)
        print("请确保您在原始 Bash 脚本所在的根目录运行此脚本。", file=sys.stderr)
        sys.exit(1)
    
    main()
