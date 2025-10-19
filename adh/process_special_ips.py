#!/usr/bin/env python3
"""
处理特殊IP列表：Microsoft和Proxy
将P2P格式的IP范围转换为CIDR，并与CIDR格式的文件合并
"""

import ipaddress
import os
import re

def ip_to_int(ip):
    """IPv4字符串转整数"""
    return int(ipaddress.IPv4Address(ip))

def int_to_ip(n):
    """整数转IPv4字符串"""
    return str(ipaddress.IPv4Address(n))

def parse_p2p_line(line):
    """解析P2P格式的一行，提取IP范围"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    
    # 去掉冒号前的描述部分
    if ':' in line:
        # 找到最后一个冒号的位置（处理可能包含多个冒号的情况）
        last_colon_pos = line.rfind(':')
        ip_part = line[last_colon_pos + 1:].strip()
    else:
        ip_part = line
    
    # 提取IP范围
    if '-' in ip_part:
        try:
            start, end = ip_part.split('-')
            return ip_to_int(start.strip()), ip_to_int(end.strip())
        except Exception as e:
            print(f"⚠️ 解析IP范围失败: {line} - {e}")
            return None
    else:
        # 如果是单个IP，转换为范围
        try:
            ip_int = ip_to_int(ip_part.strip())
            return ip_int, ip_int
        except Exception as e:
            print(f"⚠️ 解析单个IP失败: {line} - {e}")
            return None

def merge_ranges(ranges):
    """合并重叠或连续区间"""
    if not ranges:
        return []
    
    ranges.sort()
    merged = [ranges[0]]
    
    for start, end in ranges[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end + 1:  # 有重叠或连续
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    
    return merged

def ranges_to_cidrs(merged):
    """区间转CIDR列表"""
    cidrs = []
    for start, end in merged:
        try:
            cidrs.extend(ipaddress.summarize_address_range(
                ipaddress.IPv4Address(start),
                ipaddress.IPv4Address(end)
            ))
        except Exception as e:
            print(f"⚠️ 转换CIDR失败: {start}-{end} - {e}")
    
    return [str(c) for c in cidrs]

def read_cidr_file(filepath):
    """读取CIDR文件，清理注释和空行"""
    cidrs = []
    if not os.path.exists(filepath):
        return cidrs
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # 提取CIDR部分（可能包含其他内容）
            parts = line.split()
            if parts:
                cidr_str = parts[0]
                try:
                    network = ipaddress.ip_network(cidr_str, strict=False)
                    cidrs.append(network)
                except Exception as e:
                    print(f"⚠️ 无效CIDR: {cidr_str} - {e}")
    
    return cidrs

def process_list(p2p_file, cidr_file, output_file):
    """处理单个列表（Microsoft或Proxy）"""
    print(f"🔧 处理 {output_file}...")
    
    # 读取并处理P2P文件
    ranges = []
    if os.path.exists(p2p_file):
        print(f"  读取P2P文件: {p2p_file}")
        with open(p2p_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                range_data = parse_p2p_line(line)
                if range_data:
                    ranges.append(range_data)
        
        print(f"  从P2P文件提取了 {len(ranges)} 个IP范围")
        
        # 合并范围并转换为CIDR
        merged = merge_ranges(ranges)
        p2p_cidrs = ranges_to_cidrs(merged)
        print(f"  转换为 {len(p2p_cidrs)} 个CIDR")
    else:
        p2p_cidrs = []
        print(f"  ⚠️ P2P文件不存在: {p2p_file}")
    
    # 读取CIDR文件
    cidr_networks = read_cidr_file(cidr_file)
    print(f"  从CIDR文件读取了 {len(cidr_networks)} 个网络")
    
    # 合并所有CIDR
    all_cidrs = []
    
    # 添加从P2P转换的CIDR
    for cidr_str in p2p_cidrs:
        try:
            all_cidrs.append(ipaddress.ip_network(cidr_str, strict=False))
        except Exception as e:
            print(f"⚠️ 无效的转换CIDR: {cidr_str} - {e}")
    
    # 添加原始CIDR文件中的网络
    all_cidrs.extend(cidr_networks)
    
    print(f"  合并后共有 {len(all_cidrs)} 个网络")
    
    # 合并重叠的网络
    if all_cidrs:
        try:
            merged_cidrs = list(ipaddress.collapse_addresses(all_cidrs))
            print(f"  合并重叠网络后: {len(merged_cidrs)} 个网络")
        except Exception as e:
            print(f"⚠️ 合并网络失败: {e}")
            merged_cidrs = all_cidrs
    else:
        merged_cidrs = []
    
    # 排序并写入输出文件
    merged_cidrs_sorted = sorted(merged_cidrs, key=lambda x: (int(x.network_address), x.prefixlen))
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for network in merged_cidrs_sorted:
            f.write(str(network) + '\n')
    
    print(f"✅ 完成 {output_file}: {len(merged_cidrs_sorted)} 个CIDR")
    return len(merged_cidrs_sorted)

def main():
    """主函数"""
    print("🚀 开始处理特殊IP列表...")
    
    # 处理Microsoft列表
    microsoft_count = process_list(
        "temp/microsoft-p2p.txt",
        "temp/microsoft-cidr.txt", 
        "adh/ip-microsoft.txt"
    )
    
    # 处理Proxy列表
    proxy_count = process_list(
        "temp/proxy-p2p.txt",
        "temp/proxy-cidr.txt",
        "adh/ip-ibkproxy.txt"
    )
    
    print(f"\n🎉 处理完成!")
    print(f"   - Microsoft IPs: {microsoft_count} 个CIDR")
    print(f"   - Proxy IPs: {proxy_count} 个CIDR")
    
    # 清理临时文件
    temp_files = [
        "temp/microsoft-p2p.txt", "temp/microsoft-cidr.txt",
        "temp/proxy-p2p.txt", "temp/proxy-cidr.txt"
    ]
    
    for temp_file in temp_files:
        if os.path.exists(temp_file):
            os.remove(temp_file)
    
    print("🧹 临时文件已清理")

if __name__ == "__main__":
    main()
