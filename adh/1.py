#!/usr/bin/env python3
import os
import re
import zipfile
import tempfile
import requests
import ipaddress
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

def download_file(url: str, output_path: Path, max_retries: int = 3) -> bool:
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
            time.sleep(2 ** attempt)
    return False

def extract_and_clean_zip(zip_path: Path, extract_to: Path) -> bool:
    """解压ZIP文件并清理不需要的文件"""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        
        # 删除不需要的文件
        for root, dirs, files in os.walk(extract_to):
            for file in files:
                file_path = Path(root) / file
                if any(file.endswith(ext) for ext in ['.md', '.gitignore', '.sh', '.yml', '.yaml', '.json']):
                    try:
                        file_path.unlink()
                    except Exception:
                        pass
        return True
    except Exception:
        return False

def classify_by_filename(filename: str) -> str:
    """根据文件名关键词分类文件类型"""
    name_lower = filename.lower()
    
    # 计算关键词匹配得分
    inbound_score = sum(1 for kw in INBOUND_KEYWORDS if kw in name_lower)
    outbound_score = sum(1 for kw in OUTBOUND_KEYWORDS if kw in name_lower)
    
    if outbound_score > inbound_score:
        return "outbound"
    elif inbound_score > outbound_score:
        return "inbound"
    else:
        # 平局时使用更明确的关键词
        if any(x in name_lower for x in ['inbound', 'input', 'ingress']):
            return "inbound"
        elif any(x in name_lower for x in ['outbound', 'output', 'egress']):
            return "outbound"
        else:
            return "inbound"

def clean_and_extract_ips(line: str) -> Set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """清理行并提取有效的IP/CIDR"""
    ips_found = set()
    
    # 移除行内注释（#和!开头的内容）
    line = re.sub(r'[#!].*$', '', line).strip()
    
    # 移除空白字符
    line = re.sub(r'\s+', '', line)
    
    # 跳过空行
    if not line:
        return ips_found
    
    # 尝试解析为IP/CIDR
    try:
        if '/' in line:
            network = ipaddress.ip_network(line, strict=False)
            ips_found.add(network)
        else:
            ip_obj = ipaddress.ip_address(line)
            if ip_obj.version == 4:
                ips_found.add(ipaddress.ip_network(f"{line}/32", strict=False))
            else:
                ips_found.add(ipaddress.ip_network(f"{line}/128", strict=False))
    except (ValueError, ipaddress.AddressValueError):
        pass
    
    return ips_found

def process_single_file(file_path: Path) -> Set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """处理单个文件，提取所有有效的IP/CIDR"""
    ips = set()
    
    try:
        if not file_path.exists() or file_path.stat().st_size == 0:
            return ips
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                # 跳过注释行和空行
                if not line or line.startswith('#') or line.startswith('!'):
                    continue
                    
                line_ips = clean_and_extract_ips(line)
                ips.update(line_ips)
            
    except Exception:
        pass
    
    return ips

def process_directory(directory: Path) -> Tuple[Set, Set]:
    """处理目录中的所有IP相关文件，区分入站和出站"""
    inbound_ips = set()
    outbound_ips = set()
    
    # 处理的文件扩展名
    ip_extensions = {'.ipset', '.netset', '.txt', '.list'}
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = Path(root) / file
            file_ext = file_path.suffix.lower()
            
            if file_ext in ip_extensions or file_ext == '':
                # 智能分类
                classification = classify_by_filename(file)
                ips = process_single_file(file_path)
                
                if classification == "outbound":
                    outbound_ips.update(ips)
                else:
                    inbound_ips.update(ips)
    
    return inbound_ips, outbound_ips

def consolidate_networks(ip_list: Set) -> List:
    """使用ipaddress.collapse_addresses合并网络"""
    if not ip_list:
        return []
    
    # 分离IPv4和IPv6
    ipv4_nets = [net for net in ip_list if net.version == 4]
    ipv6_nets = [net for net in ip_list if net.version == 6]
    
    # 合并IPv4
    consolidated_ipv4 = list(ipaddress.collapse_addresses(ipv4_nets))
    
    # 合并IPv6
    consolidated_ipv6 = list(ipaddress.collapse_addresses(ipv6_nets))
    
    # 合并结果
    return consolidated_ipv4 + consolidated_ipv6

def separate_and_sort_ips(ip_list: List) -> Tuple[List, List]:
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

def write_output_file(filepath: Path, networks: List):
    """写入输出文件"""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            for network in networks:
                f.write(str(network) + '\n')
    except Exception:
        pass

def main():
    """主处理函数"""
    inbound_ips = set()
    outbound_ips = set()
    
    # 创建临时目录
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # 并行下载
        with ThreadPoolExecutor(max_workers=min(len(SOURCES), 4)) as executor:
            future_to_url = {}
            for i, url in enumerate(SOURCES):
                file_path = temp_path / f"source_{i}.{'zip' if url.endswith('.zip') else 'txt'}"
                future = executor.submit(download_file, url, file_path)
                future_to_url[future] = (url, file_path, i)
            
            for future in as_completed(future_to_url):
                url, file_path, i = future_to_url[future]
                if future.result():
                    if url.endswith('.zip'):
                        # 处理FireHOL ZIP文件，区分入站出站
                        extract_dir = temp_path / f"extracted_{i}"
                        if extract_and_clean_zip(file_path, extract_dir):
                            fh_inbound, fh_outbound = process_directory(extract_dir)
                            inbound_ips.update(fh_inbound)
                            outbound_ips.update(fh_outbound)
                    else:
                        # 处理bitwire单个文本文件
                        ips = process_single_file(file_path)
                        if "inbound" in url:
                            inbound_ips.update(ips)
                        elif "outbound" in url:
                            outbound_ips.update(ips)
        
        if not inbound_ips and not outbound_ips:
            return
        
        # 网络合并优化
        consolidated_inbound = consolidate_networks(inbound_ips)
        consolidated_outbound = consolidate_networks(outbound_ips)
        
        if not consolidated_inbound and not consolidated_outbound:
            return
        
        # 分离IPv4和IPv6
        inbound_ipv4, inbound_ipv6 = separate_and_sort_ips(consolidated_inbound)
        outbound_ipv4, outbound_ipv6 = separate_and_sort_ips(consolidated_outbound)
        
        # 确保输出目录存在
        output_dir = Path('adh/ip')
        output_dir.mkdir(parents=True, exist_ok=True)

        # 写入输出文件
        write_output_file(output_dir / 'inbound-ipv4-list.txt', inbound_ipv4)
        write_output_file(output_dir / 'inbound-ipv6-list.txt', inbound_ipv6)
        write_output_file(output_dir / 'outbound-ipv4-list.txt', outbound_ipv4)
        write_output_file(output_dir / 'outbound-ipv6-list.txt', outbound_ipv6)

if __name__ == "__main__":
    main()
