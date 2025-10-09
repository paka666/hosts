#!/usr/bin/env python3
import os
import re
import zipfile
import tempfile
import requests
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import radix
from pathlib import Path
import shutil

# 配置
SOURCES = [
    "https://codeload.github.com/firehol/blocklist-ipsets/zip/refs/heads/master",
    "https://github.com/bitwire-it/ipblocklist/raw/main/inbound.txt", 
    "https://github.com/bitwire-it/ipblocklist/raw/main/outbound.txt"
]

# 跳过规则 - 匹配这些模式的行将被忽略
SKIP_PATTERNS = [
    r'^\s*#',      # 注释行
    r'^\s*$',      # 空行
    r'^\s*//',     # 双斜杠注释
    r'^\s*;',      # 分号注释
    r'^\s*!',      # 感叹号注释
    r'^\[.*\]$',   # 方括号内容（通常是章节标题）
    r'^\s*Remarks:', # 备注
    r'^\s*Category:', # 分类
    r'^\s*Update:',   # 更新信息
    r'^\s*Version:',  # 版本信息
    r'^\s*Title:',    # 标题
    r'^Description:', # 描述
    r'^\s*Homepage:', # 主页
    r'^\s*License:',  # 许可证
    r'^\s*Author:',   # 作者
    r'^\s*Source:',   # 来源
    r'^\s*Maintainer:', # 维护者
    r'^\s*Generated:',  # 生成时间
    r'^\s*Expires:',    # 过期时间
    r'^#.*$',         # 任何以#开头的行
    r'^\s*-\s*',      # 以横线开头的行
    r'^\s*\*',        # 以星号开头的行
    r'^\s*@',         # 以@开头的行
    r'^\s*&',         # 以&开头的行
    r'^\s*~',         # 以~开头的行
    r'^\s*/',         # 以/开头的行
]

def should_skip_line(line):
    """检查是否应该跳过该行"""
    line = line.strip()
    if not line:
        return True
    
    for pattern in SKIP_PATTERNS:
        if re.match(pattern, line, re.IGNORECASE):
            return True
    
    # 额外的检查：如果行中包含非IP相关字符，跳过
    if re.search(r'[a-zA-Z]', line) and not re.search(r'[0-9]', line):
        return True
    
    return False

def download_file(url, output_path):
    """下载文件"""
    try:
        print(f"下载: {url}")
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, timeout=60, stream=True, headers=headers)
        response.raise_for_status()
        
        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        print(f"下载完成: {url} -> {output_path}")
        return True
    except Exception as e:
        print(f"下载失败 {url}: {e}")
        return False

def extract_and_clean_zip(zip_path, extract_to):
    """解压ZIP文件并清理不需要的文件"""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        print(f"解压完成: {zip_path} -> {extract_to}")
        
        # 递归删除不需要的文件
        extensions_to_remove = {'.md', '.gitignore', '.sh'}
        removed_count = 0
        
        for root, dirs, files in os.walk(extract_to):
            for file in files:
                file_path = os.path.join(root, file)
                if any(file.endswith(ext) for ext in extensions_to_remove):
                    os.remove(file_path)
                    removed_count += 1
                    print(f"删除文件: {file_path}")
        
        print(f"清理完成，删除了 {removed_count} 个不需要的文件")
        return True
    except Exception as e:
        print(f"解压失败 {zip_path}: {e}")
        return False

def parse_ip_line(line):
    """解析单行中的IP/CIDR - 严格模式"""
    line = line.strip()
    
    # 应用跳过规则
    if should_skip_line(line):
        return None
    
    # 移除行内的注释（#和;开头的内容）
    line = re.split(r'[#;]', line)[0].strip()
    if not line:
        return None
    
    # 移除行首的奇怪字符和空白
    line = re.sub(r'^[|\-*\s]+', '', line)
    
    # 跳过空行
    if not line:
        return None
    
    # 尝试直接解析为IP网络
    try:
        # 处理单个IP（自动转换为/32或/128）
        if '/' not in line:
            # 尝试解析为IPv4或IPv6地址
            ip_obj = ipaddress.ip_address(line)
            if ip_obj.version == 4:
                return str(ipaddress.ip_network(f"{line}/32", strict=False))
            else:
                return str(ipaddress.ip_network(f"{line}/128", strict=False))
        else:
            # 直接解析CIDR
            return str(ipaddress.ip_network(line, strict=False))
    except ValueError:
        pass
    
# 严格的IP/CIDR正则表达式模式
        IP_PATTERNS = [
        # IPv4 CIDR
        r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/\d{1,2}\b',
        # IPv4 地址
        r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        # IPv6 CIDR (完整格式)
        r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}/\d{1,3}\b',
        # IPv6 CIDR (压缩格式)
        r'\b(?:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4})*)?::(?:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4})*)?/\d{1,3}\b',
        # IPv6 地址 (完整格式)
        r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b',
        # IPv6 地址 (压缩格式)
        r'\b(?:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4})*)?::(?:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4})*)?\b'
    ]
    
    for pattern in ip_patterns:
        matches = re.findall(pattern, line)
        for match in matches:
            try:
                if '/' in match:
                    network = ipaddress.ip_network(match, strict=False)
                    return str(network)
                else:
                    # 单个IP地址
                    ip_obj = ipaddress.ip_address(match)
                    if ip_obj.version == 4:
                        return str(ipaddress.ip_network(f"{match}/32", strict=False))
                    else:
                        return str(ipaddress.ip_network(f"{match}/128", strict=False))
            except ValueError:
                continue
    
    return None

def process_single_file(file_path):
    """处理单个文件，提取所有有效的IP/CIDR"""
    ips = set()
    try:
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return ips
            
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                if should_skip_line(line):
                    skipped_lines += 1
                    continue

                network_str = parse_ip_line(line)
                if network_str:
                    ips.add(network_str)
                    processed_lines += 1
                else:
                    skipped_lines += 1

        if ips:
            print(f"从 {os.path.basename(file_path)} 提取了 {len(ips)} 个IP/CIDR") (跳过 {skipped_lines} 行)")
            
    except Exception as e:
        print(f"处理文件 {file_path} 时出错: {e}")
    
    return ips

def process_directory(directory):
    """处理目录中的所有IP相关文件"""
    all_ips = set()
    
    # 处理的文件扩展名
    ip_extensions = {'.ipset', '.netset', '.txt'}
    processed_files = 0
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if any(file.endswith(ext) for ext in ip_extensions):
                ips = process_single_file(file_path)
                all_ips.update(ips)
                processed_files += 1
    
    print(f"处理了 {processed_files} 个文件，总共提取 {len(all_ips)} 个唯一IP/CIDR")
    return all_ips

def consolidate_networks_with_radix(ip_set):
    """使用Radix树优化合并网络（去除被包含的子网）"""
    if not ip_set:
        return []
    
    print(f"开始网络合并优化，原始数量: {len(ip_set)}")
    rtree = radix.Radix()
    invalid_count = 0
    
    # 第一步：将所有有效的网络添加到Radix树
    for ip_str in ip_set:
        try:
            rtree.add(ip_str)
        except Exception as e:
            invalid_count += 1
    
    if invalid_count > 0:
        print(f"跳过 {invalid_count} 个无效的网络格式")
    
    # 获取所有前缀
    all_prefixes = rtree.prefixes()
    if not all_prefixes:
        return []
    
    # 第二步：识别并标记需要移除的子网
    prefixes_to_remove = set()
    
    for prefix_str in all_prefixes:
        # 查找被当前前缀覆盖的所有更具体的前缀
        covered_nodes = rtree.search_covered(prefix_str)
        if len(covered_nodes) > 1:
            for node in covered_nodes:
                if node.prefix != prefix_str:  # 不移除父前缀本身
                    prefixes_to_remove.add(node.prefix)
    
    # 第三步：构建最终列表（移除所有被包含的子网）
    consolidated = [p for p in all_prefixes if p not in prefixes_to_remove]
    
    print(f"合并完成: {len(ip_set)} -> {len(consolidated)}")
    return consolidated

def separate_and_sort_ips(ip_list):
    """分离IPv4和IPv6并分别排序"""
    ipv4_networks = []
    ipv6_networks = []
    
    for ip_str in ip_list:
        try:
            network = ipaddress.ip_network(ip_str, strict=False)
            if network.version == 4:
                ipv4_networks.append(network)
            else:
                ipv6_networks.append(network)
        except ValueError as e:
            print(f"无效的网络格式 {ip_str}: {e}")
            continue
    
    # 排序
    ipv4_networks.sort()
    ipv6_networks.sort()
    
    print(f"IPv4网络: {len(ipv4_networks)}, IPv6网络: {len(ipv6_networks)}")
    return ipv4_networks, ipv6_networks

def create_format(ipv4_list, ipv6_list):
    """创建格式"""
    all_networks = ipv4_list + ipv6_list
    formatted = []
    
    for network in all_networks:
        formatted.append(str(network))
    
    return formatted

def update_readme(ipv4_count, ipv6_count, total_count):
    """更新README文件"""
    from datetime import datetime
    
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    readme_content = f"""# IP Blocklists

脚本自动生成的IP黑名单

## 统计信息

- **总网络数**: {total_count}
- **IPv4网络**: {ipv4_count}
- **IPv6网络**: {ipv6_count}

## 文件说明

- `ip-blocklist.txt` - IPv4和IPv6网络列表
- `ipv4-list.txt` - IPv4网络列表  
- `ipv6-list.txt` - IPv6网络列表

## 数据来源

1. [firehol/blocklist-ipsets](https://github.com/firehol/blocklist-ipsets) - ZIP压缩包，包含多个.ipset/.netset文件
2. [bitwire-it/ipblocklist](https://github.com/bitwire-it/ipblocklist) - inbound.txt
3. [bitwire-it/ipblocklist](https://github.com/bitwire-it/ipblocklist) - outbound.txt

## 处理流程

1. 下载所有源数据
2. 解压并清理ZIP文件（移除.md/.gitignore/.sh文件）
3. 从所有.ipset/.netset/.txt文件中提取IP和CIDR
4. 严格过滤：跳过注释、文本描述、无效格式
5. 合并去重所有IP/CIDR
6. 使用Radix树进行网络优化（去除被包含的子网）
7. 分离IPv4和IPv6地址
8. 排序并生成最终文件

## 跳过规则

脚本会跳过以下内容：
- 所有注释行 (#, //, ;, ! 开头)
- 空行和空白行
- 章节标题 [section]
- 元信息 (Remarks, Category, Update, Version等)
- 其他无效格式

## 使用说明

适用于AD Home等需要纯IP/CIDR格式的系统，黑名单中添加URL。

## 更新频率

每天自动更新。

---

*最后更新: {current_time}*
"""
    
    with open('rules/ip/README.md', 'w', encoding='utf-8') as f:
        f.write(readme_content)

def main():
    print("=" * 50)
    print("开始处理IP黑名单")
    print("=" * 50)
    
    all_ips = set()
    
    # 创建临时目录
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # 处理每个数据源
        for i, url in enumerate(SOURCES):
            print(f"\n{'='*30}")
            print(f"处理源 {i+1}/{len(SOURCES)}: {url}")
            print(f"{'='*30}")
            
            if url.endswith('.zip'):
                # 处理ZIP文件
                zip_path = temp_path / f"source_{i}.zip"
                if download_file(url, zip_path):
                    extract_dir = temp_path / f"extracted_{i}"
                    if extract_and_clean_zip(zip_path, extract_dir):
                        ips = process_directory(extract_dir)
                        all_ips.update(ips)
                        print(f"✓ 从ZIP源提取了 {len(ips)} 个IP/CIDR")
            else:
                # 处理单个文本文件
                file_path = temp_path / f"source_{i}.txt"
                if download_file(url, file_path):
                    ips = process_single_file(file_path)
                    all_ips.update(ips)
                    print(f"✓ 从文本文件提取了 {len(ips)} 个IP/CIDR")
        
        print(f"\n{'='*50}")
        print(f"数据收集完成")
        print(f"{'='*50}")
        print(f"总共收集到 {len(all_ips)} 个唯一IP/CIDR")
        
        if not all_ips:
            print("错误: 没有提取到任何有效的IP/CIDR")
            return
        
        # 网络合并优化
        print(f"\n开始网络合并优化...")
        consolidated_ips = consolidate_networks_with_radix(all_ips)
        
        if not consolidated_ips:
            print("错误: 网络合并后没有剩余的有效IP")
            return
        
        # 分离IPv4和IPv6
        ipv4_networks, ipv6_networks = separate_and_sort_ips(consolidated_ips)
        
        # 生成列表
        all_list = create_format(ipv4_networks, ipv6_networks)
        
        # 写入输出文件
        print(f"\n生成输出文件...")

        # 确保输出目录存在
        os.makedirs('rules/ip', exist_ok=True)

        # 完整列表
        with open('rules/ip/ip-blocklist.txt', 'w', encoding='utf-8') as f:
            f.write("# IP Blocklist\n")
            f.write("# Generated automatically - DO NOT EDIT MANUALLY\n")
            f.write(f"# Total networks: {len(all_list)}\n")
            f.write(f"# IPv4: {len(ipv4_networks)}, IPv6: {len(ipv6_networks)}\n\n")
            for line in all_list:
                f.write(line + '\n')
        
        # IPv4专用列表
        with open('rules/ip/ipv4-list.txt', 'w', encoding='utf-8') as f:
            f.write("# IPv4 Blocklist\n")
            f.write(f"# Total: {len(ipv4_networks)}\n\n")
            for network in ipv4_networks:
                f.write(str(network) + '\n')
        
        # IPv6专用列表
        with open('rules/ip/ipv6-list.txt', 'w', encoding='utf-8') as f:
            f.write("# IPv6 Blocklist\n")
            f.write(f"# Total: {len(ipv6_networks)}\n\n")
            for network in ipv6_networks:
                f.write(str(network) + '\n')
        
        # 更新README
        update_readme(len(ipv4_networks), len(ipv6_networks), len(all_list))
        
        print(f"\n{'='*50}")
        print("处理完成!")
        print(f"生成文件:")
        print(f"  - ip-blocklist.txt ({len(all_list)} 个网络)")
        print(f"  - ipv4-list.txt ({len(ipv4_networks)} 个网络)")
        print(f"  - ipv6-list.txt ({len(ipv6_networks)} 个网络)")
        print(f"{'='*50}")

if __name__ == "__main__":
    main()
