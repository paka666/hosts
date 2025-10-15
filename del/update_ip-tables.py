#!/usr/bin/env python3
import os
import re
import zipfile
import tempfile
import requests
import ipaddress
import math
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from typing import Set, List, Tuple

# 配置
SOURCES = [
    "https://codeload.github.com/firehol/blocklist-ipsets/zip/refs/heads/master",
    "https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/inbound.txt", 
    "https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/outbound.txt"
]

# 入站关键词 (inbound: 主要用于阻挡 incoming attacks)
INBOUND_KEYWORDS = [
    'attack', 'brute', 'abuse', 'dshield', 'blocklist_de', 'spamhaus_drop', 'spamhaus_edrop', 
    'ciarmy', 'greensnow', 'talos', 'threatfox', 'stopforumspam', 'bruteforce', 'darklist', 
    'ddos', 'honeypot', 'maltrail', 'myip', 'probe', 'riper', 'spam', 'urlvir', 'sblam', 
    'ssh', 'mail', 'ftp', 'sip', 'voip', 'botscout', 'exploit', 'level1', 'level2', 
    'fullbogons', 'asn', 'geolite', 'country', 'inbound', 'input', 'ingress'
]

# 出站关键词 (outbound: 主要用于阻挡 outgoing to malware/C2)
OUTBOUND_KEYWORDS = [
    'malware', 'botnet', 'c2', 'command_and_control', 'ransomware', 'bambenek', 'coinblocker', 
    'feodo', 'zeus', 'palevo', 'spyware', 'trickbot', 'emotet', 'qakbot', 'torrentlocker', 
    'locky', 'cerber', 'teslacrypt', 'dga', 'banjori', 'cryptowall', 'dyndns', 'goz', 
    'ramnit', 'tinba', 'virut', 'symmi', 'necurs', 'mirai', 'ghe', 'ramdo', 'nymaim', 
    'conficker', 'pykspa', 'suppobox', 'simda', 'fobber', 'rovnix', 'tempedreve', 
    'vawtrak', 'bedep', 'andromeda', 'sisron', 'qhost', 'dnschanger', 'ruag', 'shiotob', 
    'urlhaus', 'threatfox_malware', 'webclient', 'level3', 'level4', 'proxy', 'anon', 
    'tor', 'hphosts_hjk', 'hphosts_psh', 'hphosts_pua', 'iblocklist_proxies', 'proxylists', 
    'proxz', 'socks_proxy', 'sslproxies', 'xroxy', 'outbound', 'output', 'egress'
]

def remove_inline_comments(line: str) -> str:
    """安全地移除行内注释，避免误删IPv6中的特殊字符"""
    comment_chars = ['#', ';', '!', '//', '--']
    for char in comment_chars:
        if char in line:
            parts = line.split(char, 1)
            before = parts[0].rstrip()
            # 如果#前以IP字符结束，可能不是注释
            if re.search(r'[0-9a-fA-F:.]$', before):
                continue
            line = before
    return line.strip()

def should_skip_line(line: str) -> bool:
    """检查是否应该跳过该行"""
    line = line.strip()
    if not line:
        return True
    comment_starts = ['#', ';', '!', '//', '--', '*', 'rem ']
    return any(line.startswith(start) for start in comment_starts)

def is_private_ip(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """检查IP是否为内网/私有/特殊用途，使用ipaddress内置属性"""
    return (
        network.is_private or
        network.is_loopback or
        network.is_multicast or
        network.is_reserved or
        network.is_unspecified or
        network.is_link_local or
        any(str(network).startswith(prefix) for prefix in [
            '192.0.2.0/', '198.51.100.0/', '203.0.113.0/', '233.252.0.0/',  # IPv4 测试/多播测试
            '100::/', '2001:db8::/', '2002::/', '3fff::/', '64:ff9b::/', '64:ff9b:1::/'  # IPv6 文档/NAT64 等
        ])
    )

def filter_private_ips(networks: List) -> List:
    """过滤掉内网IP"""
    filtered_networks = []
    for network in networks:
        if not is_private_ip(network):
            filtered_networks.append(network)
    return filtered_networks

def split_large_file(file_path: Path, lines_per_file: int = 65000, output_dir: Path = None):
    """将大文件分割成多个小文件，保留原始头"""
    if not file_path.exists():
        return
    
    if output_dir is None:
        output_dir = file_path.parent / "ip"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    header_lines = [line for line in lines if line.startswith('#')]
    content_lines = [line for line in lines if not line.startswith('#')]
    
    total_lines = len(content_lines)
    if total_lines <= lines_per_file:
        return
    
    num_files = math.ceil(total_lines / lines_per_file)
    file_stem = file_path.stem
    file_suffix = file_path.suffix
    
    for i in range(num_files):
        start_idx = i * lines_per_file
        end_idx = min((i + 1) * lines_per_file, total_lines)
        
        output_file = output_dir / f"{file_stem}_part{i+1:03d}{file_suffix}"
        with open(output_file, 'w', encoding='utf-8') as f:
            # 写入原始头 + 分割信息
            f.writelines(header_lines)
            f.write(f"# 分割部分: {i+1}/{num_files}\n")
            f.write(f"# 本部分行数: {end_idx - start_idx}\n")
            f.write("#\n")
            f.writelines(content_lines[start_idx:end_idx])

def download_file(url: str, output_path: Path, max_retries: int = 3) -> bool:
    """下载文件，支持重试"""
    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=180, stream=True, verify=True)
            response.raise_for_status()
            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            return True
        except requests.exceptions.RequestException as e:
            if attempt == max_retries - 1:
                return False
            time.sleep(2 ** attempt)
    return False

def extract_and_clean_zip(zip_path: Path, extract_to: Path) -> bool:
    """解压ZIP文件并清理不需要的文件"""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            if zip_ref.testzip() is not None:
                return False
            zip_ref.extractall(extract_to)
        
        for root, dirs, files in os.walk(extract_to):
            for file in files:
                file_path = Path(root) / file
                if any(file.endswith(ext) for ext in ['.md', '.gitignore', '.sh', '.yml', '.yaml', '.json']):
                    file_path.unlink(missing_ok=True)
        return True
    except Exception:
        return False

def classify_by_filename(filename: str) -> str:
    """根据文件名关键词精确分类文件类型"""
    name_lower = filename.lower()
    inbound_score = sum(1 for kw in INBOUND_KEYWORDS if kw in name_lower)
    outbound_score = sum(1 for kw in OUTBOUND_KEYWORDS if kw in name_lower)
    if outbound_score > inbound_score:
        return "outbound"
    elif inbound_score > outbound_score:
        return "inbound"
    else:
        if any(x in name_lower for x in ['inbound', 'input', 'ingress']):
            return "inbound"
        elif any(x in name_lower for x in ['outbound', 'output', 'egress']):
            return "outbound"
        return "inbound"  # 默认

def extract_ips_from_line(line: str) -> Set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """从单行中提取所有有效的IP/CIDR，使用ipaddress解析"""
    ips_found = set()
    line = remove_inline_comments(line)
    if not line:
        return ips_found
    
    # 粗提取潜在IP字符串
    potential_ips = re.findall(r'[\d.:a-fA-F/%]+', line)
    for pot in potential_ips:
        pot = pot.strip('%')  # 移除zone ID
        try:
            network = ipaddress.ip_network(pot, strict=False)
            ips_found.add(network)
        except ValueError:
            pass
    return ips_found

def process_single_file(file_path: Path) -> Set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """处理单个文件，提取所有有效的IP/CIDR"""
    ips = set()
    if not file_path.exists() or file_path.stat().st_size == 0:
        return ips
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if should_skip_line(line):
                continue
            line_ips = extract_ips_from_line(line)
            ips.update(line_ips)
    return ips

def process_directory(directory: Path) -> Tuple[Set, Set]:
    """处理目录中的所有IP相关文件，智能区分入站和出站"""
    inbound_ips = set()
    outbound_ips = set()
    ip_extensions = {'.ipset', '.netset', '.txt', '.list'}
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = Path(root) / file
            if file_path.suffix.lower() in ip_extensions or not file_path.suffix:
                ips = process_single_file(file_path)
                classification = classify_by_filename(file)
                if classification == "outbound":
                    outbound_ips.update(ips)
                else:
                    inbound_ips.update(ips)
    return inbound_ips, outbound_ips

def consolidate_networks(ip_list: Set) -> List:
    """使用ipaddress.collapse_addresses合并网络"""
    if not ip_list:
        return []
    
    ipv4_nets = [net for net in ip_list if net.version == 4]
    ipv6_nets = [net for net in ip_list if net.version == 6]
    
    consolidated_ipv4 = list(ipaddress.collapse_addresses(ipv4_nets))
    consolidated_ipv6 = list(ipaddress.collapse_addresses(ipv6_nets))
    
    return consolidated_ipv4 + consolidated_ipv6

def separate_and_sort_ips(ip_list: List) -> Tuple[List, List]:
    """分离IPv4和IPv6并分别排序"""
    ipv4_networks = sorted([n for n in ip_list if n.version == 4])
    ipv6_networks = sorted([n for n in ip_list if n.version == 6])
    return ipv4_networks, ipv6_networks

def write_output_file(filepath: Path, networks: List, description: str = ""):
    """写入输出文件并添加文件头信息"""
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(f"# {description}\n")
        f.write(f"# 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# 总条目数: {len(networks)}\n")
        f.write("# \n")
        for network in networks:
            f.write(str(network) + '\n')

def main():
    inbound_ips = set()
    outbound_ips = set()
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        with ThreadPoolExecutor(max_workers=min(len(SOURCES), 4)) as executor:
            future_to_url = {}
            for i, url in enumerate(SOURCES):
                file_path = temp_path / f"source_{i}.{'zip' if url.endswith('.zip') else 'txt'}"
                future = executor.submit(download_file, url, file_path)
                future_to_url[future] = (url, file_path, i)
            
            for future in as_completed(future_to_url):
                url, file_path, i = future_to_url[future]
                try:
                    success = future.result()
                    if success:
                        if url.endswith('.zip'):
                            extract_dir = temp_path / f"extracted_{i}"
                            if extract_and_clean_zip(file_path, extract_dir):
                                fh_inbound, fh_outbound = process_directory(extract_dir)
                                inbound_ips.update(fh_inbound)
                                outbound_ips.update(fh_outbound)
                        else:
                            ips = process_single_file(file_path)
                            if "inbound" in url.lower():
                                inbound_ips.update(ips)
                            elif "outbound" in url.lower():
                                outbound_ips.update(ips)
                            else:
                                inbound_ips.update(ips)
                except Exception:
                    pass
        
        if not inbound_ips and not outbound_ips:
            return
        
        consolidated_inbound = consolidate_networks(inbound_ips)
        consolidated_outbound = consolidate_networks(outbound_ips)
        
        filtered_inbound = filter_private_ips(consolidated_inbound)
        filtered_outbound = filter_private_ips(consolidated_outbound)
        
        if not filtered_inbound and not filtered_outbound:
            return
        
        inbound_ipv4, inbound_ipv6 = separate_and_sort_ips(filtered_inbound)
        outbound_ipv4, outbound_ipv6 = separate_and_sort_ips(filtered_outbound)
        
        output_dir = Path('adh')
        output_dir.mkdir(exist_ok=True)
        
        write_output_file(
            output_dir / 'inbound-blocklist.txt',
            inbound_ipv4 + inbound_ipv6,
            "入站威胁拦截列表 (Inbound Threat Blocklist) - 合并的IPv4和IPv6 - 已过滤内网IP"
        )
        write_output_file(
            output_dir / 'inbound-ipv4-list.txt', 
            inbound_ipv4,
            "入站威胁IPv4拦截列表 (Inbound Threat IPv4 Blocklist) - 已过滤内网IP"
        )
        write_output_file(
            output_dir / 'inbound-ipv6-list.txt',
            inbound_ipv6,
            "入站威胁IPv6拦截列表 (Inbound Threat IPv6 Blocklist) - 已过滤内网IP"
        )
        write_output_file(
            output_dir / 'outbound-blocklist.txt',
            outbound_ipv4 + outbound_ipv6,
            "出站威胁拦截列表 (Outbound Threat Blocklist) - 合并的IPv4和IPv6 - 已过滤内网IP"
        )
        write_output_file(
            output_dir / 'outbound-ipv4-list.txt',
            outbound_ipv4,
            "出站威胁IPv4拦截列表 (Outbound Threat IPv4 Blocklist) - 已过滤内网IP"
        )
        write_output_file(
            output_dir / 'outbound-ipv6-list.txt',
            outbound_ipv6,
            "出站威胁IPv6拦截列表 (Outbound Threat IPv6 Blocklist) - 已过滤内网IP"
        )
        
        split_large_file(output_dir / 'inbound-blocklist.txt', 65000, output_dir / 'ip')
        split_large_file(output_dir / 'outbound-blocklist.txt', 65000, output_dir / 'ip')

if __name__ == "__main__":
    main()
    
