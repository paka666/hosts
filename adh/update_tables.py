#!/usr/bin/env python3
import os
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

def extract_ips_from_line(line: str) -> set:
    # 去除首尾空白字符
    line = line.strip()
    
    # 跳过空行和以#或!开头的注释行
    if not line or line.startswith('#') or line.startswith('!'):
        return set()
    
    # 去除行内所有空白字符
    line = ''.join(line.split())
    
    # 尝试解析整行内容
    try:
        if '/' in line:
            # 处理CIDR格式
            network = ipaddress.ip_network(line, strict=False)
            return {network}
        else:
            # 处理单个IP地址
            ip_obj = ipaddress.ip_address(line)
            return {ip_obj}
    except ValueError:
        return set()

def process_single_file(file_path: Path) -> set:
    ips = set()
    if not file_path.exists() or file_path.stat().st_size == 0:
        return ips
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line_ips = extract_ips_from_line(line)
                ips.update(line_ips)
    except:
        pass
    
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
    
    # 分离IP对象和网络对象
    ip_objects = {obj for obj in ip_list if isinstance(obj, (ipaddress.IPv4Address, ipaddress.IPv6Address))}
    network_objects = {obj for obj in ip_list if isinstance(obj, (ipaddress.IPv4Network, ipaddress.IPv6Network))}
    
    # 将IP对象转换为网络对象
    for ip_obj in ip_objects:
        if ip_obj.version == 4:
            network_objects.add(ipaddress.ip_network(f"{ip_obj}/32", strict=False))
        else:
            network_objects.add(ipaddress.ip_network(f"{ip_obj}/128", strict=False))
    
    # 合并网络
    ipv4_nets = [net for net in network_objects if net.version == 4]
    ipv6_nets = [net for net in network_objects if net.version == 6]
    
    # 使用collapse_addresses合并重叠和相邻的网络
    collapsed_v4 = list(ipaddress.collapse_addresses(ipv4_nets))
    collapsed_v6 = list(ipaddress.collapse_addresses(ipv6_nets))
    
    return collapsed_v4 + collapsed_v6

def separate_and_sort_ips(ip_list: list) -> tuple:
    ipv4 = sorted([n for n in ip_list if n.version == 4])
    ipv6 = sorted([n for n in ip_list if n.version == 6])
    return ipv4, ipv6

def write_output_file(filepath: Path, networks: list, is_ipv4: bool):
    with open(filepath, 'w', encoding='utf-8') as f:
        for network in networks:
            if is_ipv4 and network.prefixlen == 32:
                # IPv4单个地址不显示/32
                f.write(str(network.network_address) + '\n')
            elif not is_ipv4 and network.prefixlen == 128:
                # IPv6单个地址不显示/128
                f.write(str(network.network_address) + '\n')
            else:
                # CIDR格式
                f.write(str(network) + '\n')

def main():
    all_ips = set()
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        with ThreadPoolExecutor(max_workers=len(SOURCES)) as executor:
            future_to_url = {}
            for i, url in enumerate(SOURCES):
                file_path = temp_path / f"source_{i}.{'zip' if '.zip' in url else 'txt'}"
                future = executor.submit(download_file, url, file_path)
                future_to_url[future] = (url, file_path, i)
            
            for future in as_completed(future_to_url):
                url, file_path, i = future_to_url[future]
                if future.result():
                    if '.zip' in url:
                        extract_dir = temp_path / f"extracted_{i}"
                        if extract_and_clean_zip(file_path, extract_dir):
                            all_ips.update(process_directory(extract_dir))
                    else:
                        all_ips.update(process_single_file(file_path))
    
    if not all_ips:
        return
    
    consolidated = consolidate_networks(all_ips)
    ipv4, ipv6 = separate_and_sort_ips(consolidated)
    
    output_dir = Path('adh/ip')
    output_dir.mkdir(parents=True, exist_ok=True)
    write_output_file(output_dir / 'ipv4.txt', ipv4, True)
    write_output_file(output_dir / 'ipv6.txt', ipv6, False)

if __name__ == "__main__":
    main()
