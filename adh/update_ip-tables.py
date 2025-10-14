#!/usr/bin/env python3
import os
import re
import zipfile
import tempfile
import requests
import ipaddress
import logging
import math
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from typing import Set, List, Tuple

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('ip_processing.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

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

# 严格的IP/CIDR正则表达式模式
IP_PATTERNS = [
    # IPv4 CIDR - 严格匹配
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]|[12][0-9]|3[0-2])\b',
    # IPv4 地址 - 严格匹配
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    # IPv6 CIDR/地址 (全面覆盖压缩和完整格式)
    r'(?i)\b((?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:(?:(?::[0-9a-f]{1,4}){1,6})|:(?:(?::[0-9a-f]{1,4}){1,7}|:)|fe80:(?::[0-9a-f]{0,4}){0,4}%[0-9a-z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-f]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(?:/\d{1,3})?\b'
]

# 内网IP正则表达式模式
PRIVATE_IP_PATTERNS = [
    # IPv4 私有地址和特殊用途地址
    r'^0\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})$',
    r'^10\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})$',
    r'^100\.(?:6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\.(?:\d{1,3})\.(?:\d{1,3})$',
    r'^127\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})$',
    r'^169\.254\.(?:\d{1,3})\.(?:\d{1,3})$',
    r'^172\.(?:1[6-9]|2\d|3[0-1])\.(?:\d{1,3})\.(?:\d{1,3})$',
    r'^192\.0\.0\.(?:\d{1,3})$',
    r'^192\.0\.2\.(?:\d{1,3})$',
    r'^192\.88\.99\.(?:\d{1,3})$',
    r'^192\.168\.(?:\d{1,3})\.(?:\d{1,3})$',
    r'^198\.1[89]\.(?:\d{1,3})\.(?:\d{1,3})$',
    r'^198\.51\.100\.(?:\d{1,3})$',
    r'^203\.0\.113\.(?:\d{1,3})$',
    r'^22[4-9]\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})$',
    r'^23[0-9]\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})$',
    r'^233\.252\.0\.(?:\d{1,3})$',
    r'^24[0-9]\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})$',
    r'^25[0-5]\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})$',
    r'^255\.255\.255\.255$',
    
    # IPv6 私有地址和特殊用途地址
    r'^::$',
    r'^::1$',
    r'^::ffff:(?:\d{1,3}\.){3}\d{1,3}$',
    r'^64:ff9b(?::[0-9a-f]{0,4}){0,4}:',
    r'^64:ff9b:1:',
    r'^100::',
    r'^100:0:0:1::',
    r'^2001::',
    r'^2001:([0-9a-f]{1,4}):',
    r'^2001:1::[1-3]$',
    r'^2001:2:',
    r'^2001:db8:',
    r'^2002:',
    r'^3fff:',
    r'^fc[0-9a-f]{2}:',
    r'^fd[0-9a-f]{2}:',
    r'^fe[89ab][0-9a-f]:',
    r'^fe80:(?::[0-9a-f]{0,4}){0,6}%[0-9a-z]+$',
    r'^ff[0-9a-f]{2}:',
    
    # 本地域名
    r'^([a-z0-9\-]+\.)?(localhost|test|example|invalid|localdomain|ip6-localhost)$',
    r'^([a-z0-9\-]+\.)?local$',
    r'^([a-z0-9\-]+\.)?home\.arpa$',
    r'^([a-z0-9\-]+\.)?example\.(com|net|org)$'
]

def remove_inline_comments(line: str) -> str:
    """安全地移除行内注释，避免误删IPv6中的特殊字符"""
    original_line = line
    
    # 处理 # 注释 - 但避免匹配IPv6中的#
    if '#' in line:
        parts = line.split('#', 1)
        # 检查#前是否有IPv6特征字符，如果没有则认为是注释
        if not re.search(r'[\[\]:a-fA-F0-9]$', parts[0].strip()):
            line = parts[0]
    
    # 处理 ; 注释
    if ';' in line:
        parts = line.split(';', 1)
        line = parts[0]
        
    # 处理 ! 注释（有些格式使用!作为注释）
    if '!' in line and not line.strip().startswith('!'):
        parts = line.split('!', 1)
        # 检查!前是否有合法IP字符
        if not re.search(r'[0-9./:]$', parts[0].strip()):
            line = parts[0]
    
    # 处理 // 注释
    if '//' in line:
        parts = line.split('//', 1)
        line = parts[0]
    
    # 处理 -- 注释
    if '--' in line and line.strip().startswith('--'):
        parts = line.split('--', 1)
        line = parts[0]
    
    return line.strip()

def should_skip_line(line: str) -> bool:
    """检查是否应该跳过该行"""
    line = line.strip()
    
    # 空行或空白行
    if not line or line.isspace():
        return True
    
    # 扩展注释检测模式
    comment_patterns = [
        r'^\s*[!#;]',      # ! # ; 开头
        r'^\s*//',         # // 开头  
        r'^\s*--',         # -- 开头
        r'^\s*\*',         # * 开头（某些格式）
        r'^\s*rem\s',      # rem 开头（批处理）
        r'^\s*#\s',        # # 加空格开头
        r'^\s*;',          # ; 开头
    ]
    
    for pattern in comment_patterns:
        if re.match(pattern, line, re.IGNORECASE):
            return True
    
    # 无.和:的行（既不是IPv4也不是IPv6格式）且不包含数字
    if '.' not in line and ':' not in line and not any(c.isdigit() for c in line):
        return True
    
    return False

def is_private_ip(ip_str: str) -> bool:
    """检查IP是否为内网IP"""
    for pattern in PRIVATE_IP_PATTERNS:
        if re.match(pattern, ip_str, re.IGNORECASE):
            return True
    return False

def filter_private_ips(networks: List) -> List:
    """过滤掉内网IP"""
    filtered_networks = []
    private_count = 0
    
    for network in networks:
        network_str = str(network)
        if not is_private_ip(network_str):
            filtered_networks.append(network)
        else:
            private_count += 1
    
    logger.info(f"过滤内网IP: 共 {len(networks)} 个网络，过滤掉 {private_count} 个内网IP，剩余 {len(filtered_networks)} 个")
    return filtered_networks

def split_large_file(file_path: Path, lines_per_file: int = 65000, output_dir: Path = None):
    """将大文件分割成多个小文件"""
    if not file_path.exists():
        logger.warning(f"要分割的文件不存在: {file_path}")
        return
    
    if output_dir is None:
        output_dir = file_path.parent / "ip"
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    file_stem = file_path.stem
    file_suffix = file_path.suffix
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # 跳过文件头（以#开头的行）
        content_lines = [line for line in lines if not line.strip().startswith('#')]
        
        total_lines = len(content_lines)
        if total_lines <= lines_per_file:
            logger.info(f"文件 {file_path} 无需分割，只有 {total_lines} 行")
            return
        
        num_files = math.ceil(total_lines / lines_per_file)
        logger.info(f"开始分割文件 {file_path}: {total_lines} 行 -> {num_files} 个文件")
        
        for i in range(num_files):
            start_idx = i * lines_per_file
            end_idx = min((i + 1) * lines_per_file, total_lines)
            
            part_num = i + 1
            output_file = output_dir / f"{file_stem}_part{part_num:03d}{file_suffix}"
            
            with open(output_file, 'w', encoding='utf-8') as f:
                # 写入文件头
                f.write(f"# {file_stem} Part {part_num}/{num_files}\n")
                f.write(f"# 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# 本文件行数: {end_idx - start_idx}\n")
                f.write(f"# 总文件数: {num_files}\n")
                f.write("# \n")
                
                # 写入内容
                for line in content_lines[start_idx:end_idx]:
                    f.write(line)
            
            logger.info(f"生成分割文件: {output_file} ({end_idx - start_idx} 行)")
        
        logger.info(f"文件分割完成: {file_path} -> {num_files} 个文件在 {output_dir}")
        
    except Exception as e:
        logger.error(f"分割文件失败 {file_path}: {e}")

def download_file(url: str, output_path: Path, max_retries: int = 3) -> bool:
    """下载文件，支持重试"""
    logger.info(f"开始下载: {url}")
    
    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=180, stream=True)
            response.raise_for_status()
            
            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            
            file_size = output_path.stat().st_size
            logger.info(f"下载成功: {url} -> {output_path} ({file_size} bytes)")
            return True
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"下载失败 (尝试 {attempt + 1}/{max_retries}): {url} - {e}")
            if attempt == max_retries - 1:
                logger.error(f"最终下载失败: {url}")
                return False
            time.sleep(2 ** attempt)  # 指数退避
        except Exception as e:
            logger.error(f"下载异常: {url} - {e}")
            return False
    
    return False

def extract_and_clean_zip(zip_path: Path, extract_to: Path) -> bool:
    """解压ZIP文件并清理不需要的文件"""
    try:
        logger.info(f"解压文件: {zip_path}")
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        
        # 删除不需要的文件
        removed_count = 0
        for root, dirs, files in os.walk(extract_to):
            for file in files:
                file_path = Path(root) / file
                if any(file.endswith(ext) for ext in ['.md', '.gitignore', '.sh', '.yml', '.yaml', '.json']):
                    try:
                        file_path.unlink()
                        removed_count += 1
                    except Exception as e:
                        logger.warning(f"无法删除文件 {file_path}: {e}")
        
        logger.info(f"解压完成: {zip_path} -> {extract_to}, 删除了 {removed_count} 个文件")
        return True
        
    except Exception as e:
        logger.error(f"解压失败 {zip_path}: {e}")
        return False

def classify_by_filename(filename: str) -> str:
    """根据文件名关键词精确分类文件类型"""
    name_lower = filename.lower()
    
    # 计算关键词匹配得分
    inbound_score = sum(1 for kw in INBOUND_KEYWORDS if kw in name_lower)
    outbound_score = sum(1 for kw in OUTBOUND_KEYWORDS if kw in name_lower)
    
    logger.debug(f"文件分类: {filename} -> 入站得分: {inbound_score}, 出站得分: {outbound_score}")
    
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
            # 保守默认：无法确定时归为入站
            return "inbound"

def extract_ips_from_line(line: str) -> Set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """从单行中提取所有有效的IP/CIDR"""
    ips_found = set()
    
    # 安全移除行内注释
    line = remove_inline_comments(line)
    
    # 跳过处理后的空行
    if not line:
        return ips_found
    
    # 使用正则表达式提取所有可能的IP/CIDR
    for pattern in IP_PATTERNS:
        matches = re.findall(pattern, line)
        for match in matches:
            try:
                # 验证并规范化IP/CIDR
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
                        
            except (ValueError, ipaddress.AddressValueError) as e:
                # 记录无效IP格式但不中断处理
                logger.debug(f"无效IP格式 '{match}' 在行中: {line[:100]}... - {e}")
                continue
    
    return ips_found

def process_single_file(file_path: Path) -> Set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """处理单个文件，提取所有有效的IP/CIDR"""
    ips = set()
    
    try:
        if not file_path.exists():
            logger.warning(f"文件不存在: {file_path}")
            return ips
            
        file_size = file_path.stat().st_size
        if file_size == 0:
            logger.debug(f"空文件: {file_path}")
            return ips
        
        logger.info(f"处理文件: {file_path} ({file_size} bytes)")
        processed_lines = 0
        valid_ips_found = 0
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                # 应用跳过规则
                if should_skip_line(line):
                    continue
                    
                processed_lines += 1
                
                # 从行中提取IP/CIDR
                line_ips = extract_ips_from_line(line)
                if line_ips:
                    valid_ips_found += len(line_ips)
                    ips.update(line_ips)
        
        logger.info(f"文件处理完成: {file_path} -> 处理行数: {processed_lines}, 找到IP: {valid_ips_found}")
            
    except Exception as e:
        logger.error(f"处理文件失败 {file_path}: {e}")
    
    return ips

def process_directory(directory: Path) -> Tuple[Set, Set]:
    """处理目录中的所有IP相关文件，智能区分入站和出站"""
    inbound_ips = set()
    outbound_ips = set()
    
    # 处理的文件扩展名
    ip_extensions = {'.ipset', '.netset', '.txt', '.list'}
    
    files_processed = 0
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = Path(root) / file
            file_ext = file_path.suffix.lower()
            
            if file_ext in ip_extensions or file_ext == '':
                files_processed += 1
                
                # 智能分类
                classification = classify_by_filename(file)
                ips = process_single_file(file_path)
                
                if classification == "outbound":
                    outbound_ips.update(ips)
                    logger.debug(f"分类为出站: {file} -> {len(ips)} IPs")
                else:
                    inbound_ips.update(ips)
                    logger.debug(f"分类为入站: {file} -> {len(ips)} IPs")
    
    logger.info(f"目录处理完成: {directory} -> 处理文件: {files_processed}, 入站IP: {len(inbound_ips)}, 出站IP: {len(outbound_ips)}")
    return inbound_ips, outbound_ips

def consolidate_networks(ip_list: Set) -> List:
    """使用ipaddress.collapse_addresses合并网络（合并相邻和重叠，移除子网）"""
    if not ip_list:
        return []
    
    logger.info(f"开始网络合并: {len(ip_list)} 个网络")
    
    # 分离IPv4和IPv6，因为collapse_addresses需要同类型
    ipv4_nets = [net for net in ip_list if net.version == 4]
    ipv6_nets = [net for net in ip_list if net.version == 6]
    
    logger.info(f"IPv4网络: {len(ipv4_nets)}, IPv6网络: {len(ipv6_nets)}")
    
    # 合并IPv4
    consolidated_ipv4 = list(ipaddress.collapse_addresses(ipv4_nets))
    
    # 合并IPv6
    consolidated_ipv6 = list(ipaddress.collapse_addresses(ipv6_nets))
    
    # 合并结果
    consolidated = consolidated_ipv4 + consolidated_ipv6
    
    logger.info(f"网络合并完成: {len(ip_list)} -> {len(consolidated)} (减少 {len(ip_list) - len(consolidated)})")
    
    return consolidated

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
    
    logger.info(f"IP分离排序完成: IPv4: {len(ipv4_networks)}, IPv6: {len(ipv6_networks)}")
    
    return ipv4_networks, ipv6_networks

def write_output_file(filepath: Path, networks: List, description: str = ""):
    """写入输出文件并添加文件头信息"""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            # 写入文件头
            f.write(f"# {description}\n")
            f.write(f"# 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# 总条目数: {len(networks)}\n")
            f.write(f"# IPv4条目: {len([n for n in networks if n.version == 4])}\n")
            f.write(f"# IPv6条目: {len([n for n in networks if n.version == 6])}\n")
            f.write("# \n")
            
            # 写入网络条目
            for network in networks:
                f.write(str(network) + '\n')
        
        logger.info(f"输出文件已生成: {filepath} ({len(networks)} 条目)")
        
    except Exception as e:
        logger.error(f"写入文件失败 {filepath}: {e}")

def main():
    """主处理函数"""
    start_time = time.time()
    logger.info("开始IP列表处理流程")
    
    inbound_ips = set()
    outbound_ips = set()
    
    # 创建临时目录
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        logger.info(f"创建临时目录: {temp_path}")
        
        # 并行下载和处理
        with ThreadPoolExecutor(max_workers=min(len(SOURCES), 4)) as executor:
            future_to_url = {}
            for i, url in enumerate(SOURCES):
                file_path = temp_path / f"source_{i}.{'zip' if url.endswith('.zip') else 'txt'}"
                future = executor.submit(download_file, url, file_path)
                future_to_url[future] = (url, file_path, i)
            
            download_success_count = 0
            for future in as_completed(future_to_url):
                url, file_path, i = future_to_url[future]
                success = future.result()
                
                if success:
                    download_success_count += 1
                    if url.endswith('.zip'):
                        # 处理FireHOL ZIP文件
                        extract_dir = temp_path / f"extracted_{i}"
                        if extract_and_clean_zip(file_path, extract_dir):
                            fh_inbound, fh_outbound = process_directory(extract_dir)
                            inbound_ips.update(fh_inbound)
                            outbound_ips.update(fh_outbound)
                    else:
                        # 处理单个文本文件
                        ips = process_single_file(file_path)
                        if "inbound" in url:
                            inbound_ips.update(ips)
                            logger.info(f"URL分类为入站: {url} -> {len(ips)} IPs")
                        elif "outbound" in url:
                            outbound_ips.update(ips)
                            logger.info(f"URL分类为出站: {url} -> {len(ips)} IPs")
                        else:
                            # 无法从URL判断时，根据内容推测
                            inbound_ips.update(ips)
                            logger.info(f"URL无法分类，默认入站: {url} -> {len(ips)} IPs")
                else:
                    logger.error(f"下载处理失败: {url}")
        
        logger.info(f"下载完成: {download_success_count}/{len(SOURCES)} 个源成功")
        
        if not inbound_ips and not outbound_ips:
            logger.error("没有成功提取到任何IP地址，流程终止")
            return
        
        # 统计初步结果
        total_ips = len(inbound_ips) + len(outbound_ips)
        logger.info(f"初步提取结果: 总IP数: {total_ips}, 入站: {len(inbound_ips)}, 出站: {len(outbound_ips)}")
        
        # 网络合并优化
        logger.info("开始网络合并...")
        consolidated_inbound = consolidate_networks(inbound_ips)
        consolidated_outbound = consolidate_networks(outbound_ips)
        
        if not consolidated_inbound and not consolidated_outbound:
            logger.error("网络合并后没有剩余IP地址，流程终止")
            return
        
        # 过滤内网IP
        logger.info("开始过滤内网IP...")
        filtered_inbound = filter_private_ips(consolidated_inbound)
        filtered_outbound = filter_private_ips(consolidated_outbound)
        
        if not filtered_inbound and not filtered_outbound:
            logger.error("过滤内网IP后没有剩余IP地址，流程终止")
            return
        
        # 分离IPv4和IPv6
        inbound_ipv4, inbound_ipv6 = separate_and_sort_ips(filtered_inbound)
        outbound_ipv4, outbound_ipv6 = separate_and_sort_ips(filtered_outbound)
        
        # 确保输出目录存在
        output_dir = Path('adh')
        output_dir.mkdir(exist_ok=True)
        logger.info(f"输出目录: {output_dir.absolute()}")
        
        # 生成输出文件
        logger.info("生成输出文件...")
        
        # 入站完整列表
        inbound_full_path = output_dir / 'inbound-blocklist.txt'
        write_output_file(
            inbound_full_path,
            inbound_ipv4 + inbound_ipv6,
            "入站威胁拦截列表 (Inbound Threat Blocklist) - 合并的IPv4和IPv6 - 已过滤内网IP"
        )
        
        # 入站IPv4
        write_output_file(
            output_dir / 'inbound-ipv4-list.txt', 
            inbound_ipv4,
            "入站威胁IPv4拦截列表 (Inbound Threat IPv4 Blocklist) - 已过滤内网IP"
        )
        
        # 入站IPv6
        write_output_file(
            output_dir / 'inbound-ipv6-list.txt',
            inbound_ipv6,
            "入站威胁IPv6拦截列表 (Inbound Threat IPv6 Blocklist) - 已过滤内网IP"
        )
        
        # 出站完整列表
        outbound_full_path = output_dir / 'outbound-blocklist.txt'
        write_output_file(
            outbound_full_path,
            outbound_ipv4 + outbound_ipv6,
            "出站威胁拦截列表 (Outbound Threat Blocklist) - 合并的IPv4和IPv6 - 已过滤内网IP"
        )
        
        # 出站IPv4
        write_output_file(
            output_dir / 'outbound-ipv4-list.txt',
            outbound_ipv4,
            "出站威胁IPv4拦截列表 (Outbound Threat IPv4 Blocklist) - 已过滤内网IP"
        )
        
        # 出站IPv6
        write_output_file(
            output_dir / 'outbound-ipv6-list.txt',
            outbound_ipv6,
            "出站威胁IPv6拦截列表 (Outbound Threat IPv6 Blocklist) - 已过滤内网IP"
        )
        
        # 分割大文件
        logger.info("开始分割大文件...")
        split_large_file(inbound_full_path, 65000, output_dir / 'ip')
        split_large_file(outbound_full_path, 65000, output_dir / 'ip')
    
    # 计算总耗时和统计
    end_time = time.time()
    processing_time = end_time - start_time
    
    # 最终统计
    total_final = (len(inbound_ipv4) + len(inbound_ipv6) + 
                  len(outbound_ipv4) + len(outbound_ipv6))
    
    logger.info("=" * 50)
    logger.info("处理完成!")
    logger.info(f"总耗时: {processing_time:.2f} 秒")
    logger.info(f"最终统计:")
    logger.info(f"  - 入站IPv4: {len(inbound_ipv4)} 个网络")
    logger.info(f"  - 入站IPv6: {len(inbound_ipv6)} 个网络")
    logger.info(f"  - 出站IPv4: {len(outbound_ipv4)} 个网络")
    logger.info(f"  - 出站IPv6: {len(outbound_ipv6)} 个网络")
    logger.info(f"  - 总计: {total_final} 个网络")
    logger.info(f"输出文件位置: {output_dir.absolute()}")
    logger.info("分割文件位置: adh/ip/")
    logger.info("=" * 50)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("用户中断执行")
    except Exception as e:
        logger.error(f"程序执行异常: {e}", exc_info=True)
      
