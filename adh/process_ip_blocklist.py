#!/usr/bin/env python3
import os
import re
import zipfile
import tempfile
import requests
import ipaddress
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

SOURCES = [
    "https://codeload.github.com/firehol/blocklist-ipsets/zip/refs/heads/master",
    "https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/inbound.txt",
    "https://raw.githubusercontent.com/bitwire-it/ipbloucklist/main/outbound.txt",
    "https://raw.githubusercontent.com/paka666/rules/main/adh/intranet.txt"
]

def download_file(url: str, output_path: Path) -> bool:
    """下载文件，超时 180s，无重试"""
    try:
        response = requests.get(url, timeout=180, stream=True)
        response.raise_for_status()
        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    except requests.RequestException:
        print(f"Failed to download {url}")
        return False

def extract_and_clean_zip(zip_path: Path, extract_to: Path) -> bool:
    """解压 ZIP，移除 .md, .gitignore, .sh 文件"""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        for root, _, files in os.walk(extract_to):
            for file in files:
                file_path = Path(root) / file
                if file.endswith(('.md', '.gitignore', '.sh')):
                    file_path.unlink(missing_ok=True)
        return True
    except zipfile.BadZipFile:
        print(f"Invalid ZIP file: {zip_path}")
        return False

def diff_rules(a_file: str, b_file: str, output_file: str = 'adh/ip-blocklist.txt') -> int:
    """从 a_file 减去 b_file 的规则，输出 IP 规则到 output_file，去除 || 和 ^"""
    b_rules = set()
    a_file, b_file = Path(a_file), Path(b_file)

    if not a_file.exists() or not b_file.exists():
        print(f"Error: Missing input file(s) {a_file} or {b_file}")
        return 0
    
    # 加载 b_file 到 set，忽略注释和空白
    with open(b_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith(('#', '!')):
                b_rules.add(line)

    # 遍历 a_file，输出不在 b_file 的行
    ip_count = 0
    with open(a_file, 'r', encoding='utf-8', errors='ignore') as a_f, \
         open(output_file, 'w', encoding='utf-8') as out_f:
        for line in a_f:
            line = line.strip()
            if line and not line.startswith(('#', '!')) and line not in b_rules:
                cleaned_line = line
                if cleaned_line.startswith('||'):
                    cleaned_line = cleaned_line[2:]
                if cleaned_line.endswith('^'):
                    cleaned_line = cleaned_line[:-1]
                if cleaned_line:  # 确保非空
                    out_f.write(cleaned_line + '\n')
                    ip_count += 1
    print(f"Generated {output_file} with {ip_count} IP rules")
    return ip_count

def extract_ips_from_line(line: str) -> set:
    """提取单行中的 IP 或 CIDR，忽略注释和空白"""
    line = line.strip()
    if not line or line.startswith(('#', '!')):
        return set()
    
    # 去除行内所有空白字符
    line = ''.join(line.split())
    
    # 移除 IPv6 zone ID（如 %eth0）
    line = line.split('%')[0]
    
    try:
        if '/' in line:
            network = ipaddress.ip_network(line, strict=False)
            return {network}
        else:
            ip_obj = ipaddress.ip_address(line)
            return {ip_obj}
    except ValueError:
        # 尝试处理可能的格式问题
        if ':' in line and '/' not in line:
            # 可能是IPv6地址
            try:
                ip_obj = ipaddress.ip_address(line)
                return {ip_obj}
            except ValueError:
                pass
        return set()

def process_single_file(file_path: Path) -> set:
    """处理单个文件，提取所有有效 IP/CIDR"""
    ips = set()
    if not file_path.exists() or file_path.stat().st_size == 0:
        return ips
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line_ips = extract_ips_from_line(line)
                ips.update(line_ips)
                
                # 进度显示（针对大文件）
                if line_num % 100000 == 0:
                    print(f"  Processed {line_num} lines from {file_path.name}")
                    
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
    return ips

def process_directory(directory: Path) -> set:
    """处理目录中的所有 .ipset/.netset/.txt 文件"""
    ips = set()
    file_count = 0
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.ipset', '.netset', '.txt')) or not Path(file).suffix:
                file_path = Path(root) / file
                file_ips = process_single_file(file_path)
                ips.update(file_ips)
                file_count += 1
                if file_count % 100 == 0:
                    print(f"  Processed {file_count} files from directory")
    return ips

def consolidate_networks(ip_list: set) -> list:
    """合并重叠和相邻网段 - 修复版"""
    if not ip_list:
        return []
    
    print(f"开始合并网络，原始数量: {len(ip_list)}")
    
    # 分离IP对象和网络对象
    ip_objects = {obj for obj in ip_list if isinstance(obj, (ipaddress.IPv4Address, ipaddress.IPv6Address))}
    network_objects = {obj for obj in ip_list if isinstance(obj, (ipaddress.IPv4Network, ipaddress.IPv6Network))}
    
    print(f"IP对象数量: {len(ip_objects)}, 网络对象数量: {len(network_objects)}")
    
    # 将IP对象转换为网络对象
    for ip_obj in ip_objects:
        if ip_obj.version == 4:
            network_objects.add(ipaddress.ip_network(f"{ip_obj}/32", strict=False))
        else:
            network_objects.add(ipaddress.ip_network(f"{ip_obj}/128", strict=False))
    
    # 分离IPv4和IPv6网络
    ipv4_nets = [net for net in network_objects if net.version == 4]
    ipv6_nets = [net for net in network_objects if net.version == 6]
    
    print(f"IPv4网络数量: {len(ipv4_nets)}, IPv6网络数量: {len(ipv6_nets)}")
    
    # 合并网络 - 关键修复：确保正确处理所有网络
    try:
        collapsed_v4 = list(ipaddress.collapse_addresses(ipv4_nets))
        collapsed_v6 = list(ipaddress.collapse_addresses(ipv6_nets))
        
        print(f"合并后 IPv4: {len(collapsed_v4)}, IPv6: {len(collapsed_v6)}")
        
        return collapsed_v4 + collapsed_v6
    except Exception as e:
        print(f"合并网络时出错: {e}")
        # 如果合并失败，返回原始网络
        return list(network_objects)

def separate_and_sort_ips(ip_list: list) -> tuple:
    """分离 IPv4 和 IPv6 并排序"""
    ipv4 = sorted([n for n in ip_list if n.version == 4])
    ipv6 = sorted([n for n in ip_list if n.version == 6])
    return ipv4, ipv6

def write_output_file(filepath: Path, networks: list, is_ipv4: bool):
    """写入输出文件，单 IP 不显示 /32 或 /128"""
    with open(filepath, 'w', encoding='utf-8') as f:
        for network in networks:
            if is_ipv4 and network.prefixlen == 32:
                f.write(str(network.network_address) + '\n')
            elif not is_ipv4 and network.prefixlen == 128:
                f.write(str(network.network_address) + '\n')
            else:
                f.write(str(network) + '\n')

def main():
    """主函数：处理 diff_rules 和 SOURCES，输出 IPv4/IPv6"""
    # 确保输出目录存在
    output_dir = Path('adh')
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 先运行 diff_rules，生成 adh/ip-blocklist.txt
    a_file = 'adh/blocklist.txt'
    b_file = 'adh/domain-blocklist.txt'
    ip_blocklist = 'adh/ip-blocklist.txt'

    # 确保输入文件存在
    if not Path(a_file).exists() or not Path(b_file).exists():
        print(f"Error: Missing input file(s) {a_file} or {b_file}")
        return

    ip_count = diff_rules(a_file, b_file, ip_blocklist)
    if ip_count == 0:
        print("No IP rules generated from diff_rules")
        return

    # 处理所有源文件
    all_ips = set()
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        print("开始处理下载源...")
        with ThreadPoolExecutor(max_workers=min(len(SOURCES), 4)) as executor:  # 限制并发数
            future_to_url = {}
            for i, url in enumerate(SOURCES):
                file_path = temp_path / f"source_{i}.{'zip' if '.zip' in url else 'txt'}"
                future = executor.submit(download_file, url, file_path)
                future_to_url[future] = (url, file_path, i)

            # 处理下载的 SOURCES
            for future in as_completed(future_to_url):
                url, file_path, i = future_to_url[future]
                if future.result():
                    print(f"成功下载: {url}")
                    if '.zip' in url:
                        extract_dir = temp_path / f"extracted_{i}"
                        if extract_and_clean_zip(file_path, extract_dir):
                            dir_ips = process_directory(extract_dir)
                            all_ips.update(dir_ips)
                            print(f"处理ZIP完成: {url} -> {len(dir_ips)} IPs")
                    else:
                        file_ips = process_single_file(file_path)
                        all_ips.update(file_ips)
                        print(f"处理文本完成: {url} -> {len(file_ips)} IPs")
                else:
                    print(f"下载失败: {url}")

        # 添加本地 ip-blocklist.txt
        print("处理本地生成的 ip-blocklist.txt...")
        local_ips = process_single_file(Path(ip_blocklist))
        all_ips.update(local_ips)
        print(f"本地文件处理完成: {len(local_ips)} IPs")

    if not all_ips:
        print("No IPs collected")
        return

    print(f"总共收集到 {len(all_ips)} 个IP/CIDR")

    # 合并网段，分离 IPv4/IPv6，输出
    consolidated = consolidate_networks(all_ips)
    ipv4, ipv6 = separate_and_sort_ips(consolidated)

    output_dir = Path('adh')
    output_dir.mkdir(parents=True, exist_ok=True)
    write_output_file(output_dir / 'ipv4.txt', ipv4, True)
    write_output_file(output_dir / 'ipv6.txt', ipv6, False)
    print(f"最终输出: IPv4: {len(ipv4)} 条目, IPv6: {len(ipv6)} 条目")

if __name__ == "__main__":
    main()
