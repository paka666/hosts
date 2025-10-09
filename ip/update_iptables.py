#!/usr/bin/env python3
import os
import re
import zipfile
import tempfile
import requests
import ipaddress
import radix
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import shutil
import time

# 配置
SOURCES = [
    "https://codeload.github.com/firehol/blocklist-ipsets/zip/refs/heads/master",
    "https://github.com/bitwire-it/ipblocklist/raw/main/inbound.txt", 
    "https://github.com/bitwire-it/ipblocklist/raw/main/outbound.txt"
]

# 严格的IP/CIDR正则表达式模式
IP_PATTERNS = [
    # IPv4 CIDR
    r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/\d{1,2}\b',
    # IPv4 地址
    r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    # IPv6 CIDR/地址 (全面覆盖压缩和完整格式)
    r'(?i)\b((?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:(?:(?::[0-9a-f]{1,4}){1,6})|:(?:(?::[0-9a-f]{1,4}){1,7}|:)|fe80:(?::[0-9a-f]{0,4}){0,4}%[0-9a-z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-f]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(?:/\d{1,3})?\b'
]

def should_skip_line(line):
    """检查是否应该跳过该行"""
    line = line.strip()
    
    # 空行或空白行
    if not line or line.isspace():
        return True
    
    # 注释行
    if re.match(r'^\s*[!#;]', line) or re.match(r'^\s*//', line):
        return True
    
    # 无.和:的行（既不是IPv4也不是IPv6格式）
    if '.' not in line and ':' not in line:
        return True
    
    return False

def download_file(url, output_path, max_retries=3):
    """下载文件，支持重试"""
    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=180, stream=True)
            response.raise_for_status()
            
            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            return True
        except Exception:
            if attempt == max_retries - 1:
                return False
            time.sleep(2 ** attempt)  # 指数退避

def extract_and_clean_zip(zip_path, extract_to):
    """解压ZIP文件并清理不需要的文件"""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        
        # 删除不需要的文件
        for root, dirs, files in os.walk(extract_to):
            for file in files:
                file_path = os.path.join(root, file)
                if any(file.endswith(ext) for ext in ['.md', '.gitignore', '.sh']):
                    os.remove(file_path)
        return True
    except Exception:
        return False

def extract_ips_from_line(line):
    """从单行中提取所有IP/CIDR"""
    ips_found = set()
    
    # 移除行内注释（#和;开头的内容）
    line = re.sub(r'[#;].*$', '', line).strip()
    
    # 跳过空行和空白字符行
    if not line or line.isspace():
        return ips_found
    
    # 使用正则表达式提取所有可能的IP/CIDR
    for pattern in IP_PATTERNS:
        matches = re.findall(pattern, line)
        for match in matches:
            try:
                if '/' in match:
                    # CIDR格式
                    network = ipaddress.ip_network(match, strict=False)
                    ips_found.add(network)
                else:
                    # 单个IP地址
                    ip_obj = ipaddress.ip_address(match)
                    if ip_obj.version == 4:
                        ips_found.add(ipaddress.ip_network(f"{match}/32", strict=False))
                    else:
                        ips_found.add(ipaddress.ip_network(f"{match}/128", strict=False))
            except ValueError:
                # 无效的IP格式，跳过
                continue
    
    return ips_found

def process_single_file(file_path):
    """处理单个文件，提取所有有效的IP/CIDR"""
    ips = set()
    
    try:
        if os.path.getsize(file_path) == 0:
            return ips
            
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # 应用跳过规则
                if should_skip_line(line):
                    continue
                    
                # 从行中提取IP/CIDR
                line_ips = extract_ips_from_line(line)
                ips.update(line_ips)
            
    except Exception:
        pass
    
    return ips

def process_directory(directory):
    """处理目录中的所有IP相关文件"""
    all_ips = set()
    
    # 处理的文件扩展名
    ip_extensions = {'.ipset', '.netset', '.txt'}
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if any(file.endswith(ext) for ext in ip_extensions):
                ips = process_single_file(file_path)
                all_ips.update(ips)
    
    return all_ips

def consolidate_networks(ip_list):
    """使用ipaddress.collapse_addresses全合并网络（合并相邻和重叠，移除子网）"""
    if not ip_list:
        return []
    
    # 分离IPv4和IPv6，因为collapse_addresses需要同类型
    ipv4_nets = [net for net in ip_list if net.version == 4]
    ipv6_nets = [net for net in ip_list if net.version == 6]
    
    # 合并IPv4
    consolidated_ipv4 = ipaddress.collapse_addresses(ipv4_nets)
    
    # 合并IPv6
    consolidated_ipv6 = ipaddress.collapse_addresses(ipv6_nets)
    
    # 合并结果
    consolidated = list(consolidated_ipv4) + list(consolidated_ipv6)
    
    return consolidated

def separate_and_sort_ips(ip_list):
    """分离IPv4和IPv6并分别排序"""
    ipv4_networks = []
    ipv6_networks = []
    
    for network in ip_list:
        if network.version == 4:
            ipv4_networks.append(network)
        else:
            ipv6_networks.append(network)
    
    # 排序
    ipv4_networks.sort()
    ipv6_networks.sort()
    
    return ipv4_networks, ipv6_networks

def main():
    all_ips = set()
    
    # 创建临时目录
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # 并行下载
        with ThreadPoolExecutor(max_workers=len(SOURCES)) as executor:
            future_to_url = {}
            for i, url in enumerate(SOURCES):
                file_path = temp_path / f"source_{i}.{'zip' if url.endswith('.zip') else 'txt'}"
                future = executor.submit(download_file, url, file_path)
                future_to_url[future] = (url, file_path, i)
            
            for future in as_completed(future_to_url):
                url, file_path, i = future_to_url[future]
                if future.result():
                    if url.endswith('.zip'):
                        # 处理ZIP文件
                        extract_dir = temp_path / f"extracted_{i}"
                        if extract_and_clean_zip(file_path, extract_dir):
                            ips = process_directory(extract_dir)
                            all_ips.update(ips)
                    else:
                        # 处理单个文本文件
                        ips = process_single_file(file_path)
                        all_ips.update(ips)
        
        if not all_ips:
            return
        
        # 网络合并优化
        consolidated_ips = consolidate_networks(all_ips)
        
        if not consolidated_ips:
            return
        
        # 分离IPv4和IPv6
        ipv4_networks, ipv6_networks = separate_and_sort_ips(consolidated_ips)
        
        # 确保输出目录存在
        os.makedirs('rules/ip', exist_ok=True)

        # 完整列表 - 纯IP/CIDR格式
        with open('rules/ip/ip-blocklist.txt', 'w', encoding='utf-8') as f:
            for network in ipv4_networks + ipv6_networks:
                f.write(str(network) + '\n')
        
        # IPv4专用列表 - 纯IP/CIDR格式
        with open('rules/ip/ipv4-list.txt', 'w', encoding='utf-8') as f:
            for network in ipv4_networks:
                f.write(str(network) + '\n')
        
        # IPv6专用列表 - 纯IP/CIDR格式
        with open('rules/ip/ipv6-list.txt', 'w', encoding='utf-8') as f:
            for network in ipv6_networks:
                f.write(str(network) + '\n')

if __name__ == "__main__":
    main()