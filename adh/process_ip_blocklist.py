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
    "https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/outbound.txt",
    "https://raw.githubusercontent.com/paka666/rules/main/adh/intranet2.txt"
]

def download_file(url: str, output_path: Path) -> bool:
    try:
        response = requests.get(url, timeout=180, stream=True)
        response.raise_for_status()
        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    except:
        return False

def extract_and_clean_zip(zip_path: Path, extract_to: Path) -> bool:
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        for root, _, files in os.walk(extract_to):
            for file in files:
                file_path = Path(root) / file
                if file.endswith(('.md', '.gitignore', '.sh')):
                    file_path.unlink(missing_ok=True)
        return True
    except:
        return False

def diff_rules(a_file: str, b_file: str, output_file: str = 'adh/ip-blocklist.txt'):
    """计算 a - b：从 blocklist.txt 减去 domain-blocklist.txt，输出 IP 规则，去除 || 和 ^"""
    b_rules = set()
    # 加载 domain-blocklist.txt 到 set
    with open(b_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith(('#', '!')):
                b_rules.add(line)
    
    # 遍历 blocklist.txt，输出不在 domain-blocklist.txt 的行
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
                out_f.write(cleaned_line + '\n')
                ip_count += 1
    return ip_count

def extract_ips_from_line(line: str) -> set:
    line = line.strip()
    if not line or line.startswith(('#', '!')):
        return set()
    line = ''.join(line.split())  # 去除所有空白字符
    try:
        if '/' in line:
            network = ipaddress.ip_network(line, strict=False)
            return {network}
        else:
            ip_obj = ipaddress.ip_address(line)
            return {ip_obj}
    except ValueError:
        return set()

def process_single_file(file_path: Path) -> set:
    ips = set()
    if not file_path.exists() or file_path.stat().st_size == 0:
        return ips
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line_ips = extract_ips_from_line(line)
            ips.update(line_ips)
    return ips

def process_directory(directory: Path) -> set:
    ips = set()
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.ipset', '.netset', '.txt')) or not Path(file).suffix:
                file_path = Path(root) / file
                ips.update(process_single_file(file_path))
    return ips

def consolidate_networks(ip_list: set) -> list:
    if not ip_list:
        return []
    ip_objects = {obj for obj in ip_list if isinstance(obj, (ipaddress.IPv4Address, ipaddress.IPv6Address))}
    network_objects = {obj for obj in ip_list if isinstance(obj, (ipaddress.IPv4Network, ipaddress.IPv6Network))}
    for ip_obj in ip_objects:
        if ip_obj.version == 4:
            network_objects.add(ipaddress.ip_network(f"{ip_obj}/32", strict=False))
        else:
            network_objects.add(ipaddress.ip_network(f"{ip_obj}/128", strict=False))
    ipv4_nets = [net for net in network_objects if net.version == 4]
    ipv6_nets = [net for net in network_objects if net.version == 6]
    return list(ipaddress.collapse_addresses(ipv4_nets)) + list(ipaddress.collapse_addresses(ipv6_nets))

def separate_and_sort_ips(ip_list: list) -> tuple:
    ipv4 = sorted([n for n in ip_list if n.version == 4])
    ipv6 = sorted([n for n in ip_list if n.version == 6])
    return ipv4, ipv6

def write_output_file(filepath: Path, networks: list, is_ipv4: bool):
    with open(filepath, 'w', encoding='utf-8') as f:
        for network in networks:
            if is_ipv4 and network.prefixlen == 32:
                f.write(str(network.network_address) + '\n')
            elif not is_ipv4 and network.prefixlen == 128:
                f.write(str(network.network_address) + '\n')
            else:
                f.write(str(network) + '\n')

def main():
    # 先运行 diff_rules，生成 adh/ip-blocklist.txt
    a_file = 'adh/blocklist.txt'
    b_file = 'adh/domain-blocklist.txt'
    ip_blocklist = 'adh/ip-blocklist.txt'
    
    # 确保输入文件存在
    if not Path(a_file).exists() or not Path(b_file).exists():
        print(f"Error: Missing input file(s) {a_file} or {b_file}")
        return
    
    ip_count = diff_rules(a_file, b_file, ip_blocklist)
    print(f"Generated {ip_blocklist} with {ip_count} IP rules")
    
    # 将生成的 ip-blocklist.txt 加入 SOURCES
    all_ips = set()
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        with ThreadPoolExecutor(max_workers=len(SOURCES)) as executor:
            future_to_url = {}
            for i, url in enumerate(SOURCES):
                file_path = temp_path / f"source_{i}.{'zip' if '.zip' in url else 'txt'}"
                future = executor.submit(download_file, url, file_path)
                future_to_url[future] = (url, file_path, i)
            
            # 处理下载的 SOURCES
            for future in as_completed(future_to_url):
                url, file_path, i = future_to_url[future]
                if future.result():
                    if '.zip' in url:
                        extract_dir = temp_path / f"extracted_{i}"
                        if extract_and_clean_zip(file_path, extract_dir):
                            all_ips.update(process_directory(extract_dir))
                    else:
                        all_ips.update(process_single_file(file_path))
    
        # 处理本地生成的 ip-blocklist.txt
        all_ips.update(process_single_file(Path(ip_blocklist)))
    
    if not all_ips:
        print("No IPs collected")
        return
    
    # 合并网段
    consolidated = consolidate_networks(all_ips)
    ipv4, ipv6 = separate_and_sort_ips(consolidated)
    
    # 输出到 adh/ip/
    output_dir = Path('adh/ip')
    output_dir.mkdir(parents=True, exist_ok=True)
    write_output_file(output_dir / 'ipv4.txt', ipv4, True)
    write_output_file(output_dir / 'ipv6.txt', ipv6, False)
    print(f"Output IPv4: {len(ipv4)} entries, IPv6: {len(ipv6)} entries")

if __name__ == "__main__":
    main()
