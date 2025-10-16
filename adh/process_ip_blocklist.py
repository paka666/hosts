#!/usr/bin/env python3
"""
IP列表处理脚本 - 优化合并版
修复批次合并问题，提高合并效率
"""

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
    "https://raw.githubusercontent.com/paka666/rules/main/adh/intranet.txt"
]

def download_file(url: str, output_path: Path) -> bool:
    """下载文件"""
    try:
        response = requests.get(url, timeout=180, stream=True)
        response.raise_for_status()
        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    except Exception as e:
        print(f"下载失败 {url}: {e}")
        return False

def extract_and_clean_zip(zip_path: Path, extract_to: Path) -> bool:
    """解压ZIP文件并清理非必要文件"""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        
        # 清理非必要文件
        for root, _, files in os.walk(extract_to):
            for file in files:
                file_path = Path(root) / file
                if file.endswith(('.md', '.gitignore', '.sh')):
                    file_path.unlink(missing_ok=True)
        return True
    except Exception as e:
        print(f"解压失败 {zip_path}: {e}")
        return False

def diff_rules(a_file: str, b_file: str, output_file: str = 'adh/ip-blocklist.txt') -> int:
    """从blocklist.txt减去domain-blocklist.txt，输出IP规则"""
    b_rules = set()
    a_file, b_file = Path(a_file), Path(b_file)

    if not a_file.exists() or not b_file.exists():
        print(f"错误: 缺少输入文件 {a_file} 或 {b_file}")
        return 0
    
    # 加载domain-blocklist.txt
    with open(b_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith(('#', '!')):
                b_rules.add(line)

    # 遍历blocklist.txt，输出不在domain-blocklist.txt的行
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
                if cleaned_line:
                    out_f.write(cleaned_line + '\n')
                    ip_count += 1
    
    print(f"生成 {output_file}，包含 {ip_count} 条IP规则")
    return ip_count

def extract_ips_from_line(line: str) -> set:
    """提取单行中的IP或CIDR"""
    line = line.strip()
    if not line or line.startswith(('#', '!')):
        return set()
    
    # 去除行内所有空白字符
    line = ''.join(line.split())
    
    # 移除IPv6 zone ID
    line = line.split('%')[0]
    
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
    """处理单个文件，提取有效IP/CIDR"""
    ips = set()
    if not file_path.exists() or file_path.stat().st_size == 0:
        return ips
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line_ips = extract_ips_from_line(line)
                ips.update(line_ips)
        return ips
    except Exception as e:
        print(f"处理文件 {file_path} 时出错: {e}")
        return set()

def process_directory(directory: Path) -> set:
    """处理目录中的所有.ipset/.netset/.txt文件"""
    ips = set()
    file_count = 0
    
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.ipset', '.netset', '.txt')) or not Path(file).suffix:
                file_path = Path(root) / file
                file_ips = process_single_file(file_path)
                ips.update(file_ips)
                file_count += 1
    
    print(f"目录处理完成: {file_count} 个文件 -> {len(ips)} 个IP")
    return ips

def is_zip_url(url: str) -> bool:
    """判断URL是否为ZIP文件"""
    return '.zip' in url or ('codeload.github.com' in url and '/zip/' in url)

def optimized_collapse(networks: list, network_type: str = "IPv4") -> list:
    """
    优化的网络合并算法
    使用渐进式合并策略，避免内存溢出同时保证合并效果
    """
    if not networks:
        return []
    
    print(f"开始优化合并 {network_type} 网络，原始数量: {len(networks)}")
    
    # 过滤全范围网络
    filtered_networks = []
    for net in networks:
        if net.prefixlen == 0:
            print(f"跳过全范围网络: {net}")
            continue
        filtered_networks.append(net)
    
    if not filtered_networks:
        return []
    
    print(f"过滤后 {network_type} 网络数量: {len(filtered_networks)}")
    
    # 第一步：按网络地址排序
    sorted_networks = sorted(filtered_networks, key=lambda x: (int(x.network_address), x.prefixlen))
    
    # 第二步：渐进式合并策略
    # 先处理大网段，再处理小网段，避免过度合并
    def progressive_collapse(network_list, max_batch_size=200000):
        if len(network_list) <= max_batch_size:
            # 小规模直接合并
            return list(ipaddress.collapse_addresses(network_list))
        
        # 大规模网络：先按前缀长度分组处理
        prefix_groups = {}
        for net in network_list:
            prefix = net.prefixlen
            if prefix not in prefix_groups:
                prefix_groups[prefix] = []
            prefix_groups[prefix].append(net)
        
        # 从大网段到小网段逐步合并
        collapsed_result = []
        for prefix in sorted(prefix_groups.keys()):
            group_networks = prefix_groups[prefix]
            if len(group_networks) > max_batch_size:
                # 大组内部分批合并
                batches = [group_networks[i:i + max_batch_size] 
                          for i in range(0, len(group_networks), max_batch_size)]
                for batch in batches:
                    collapsed_batch = list(ipaddress.collapse_addresses(batch))
                    collapsed_result.extend(collapsed_batch)
            else:
                collapsed_group = list(ipaddress.collapse_addresses(group_networks))
                collapsed_result.extend(collapsed_group)
        
        return collapsed_result
    
    # 第三步：迭代合并直到稳定
    previous_count = len(sorted_networks)
    current_networks = sorted_networks
    max_iterations = 5
    iteration = 0
    
    while iteration < max_iterations:
        iteration += 1
        print(f"  第 {iteration} 轮合并...")
        
        collapsed = progressive_collapse(current_networks)
        current_count = len(collapsed)
        
        print(f"    合并后: {previous_count} -> {current_count}")
        
        if current_count == previous_count:
            break  # 达到稳定状态
        
        previous_count = current_count
        current_networks = sorted(collapsed, key=lambda x: (int(x.network_address), x.prefixlen))
    
    final_count = len(current_networks)
    reduction_ratio = (len(filtered_networks) - final_count) / len(filtered_networks) * 100
    
    print(f"{network_type} 优化合并完成: {len(filtered_networks)} -> {final_count} (减少 {reduction_ratio:.2f}%)")
    
    return current_networks

def consolidate_networks(ip_list: set) -> list:
    """合并重叠和相邻网段 - 优化版"""
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
    
    try:
        # 对IPv4和IPv6分别进行优化合并
        collapsed_v4 = optimized_collapse(ipv4_nets, "IPv4")
        collapsed_v6 = optimized_collapse(ipv6_nets, "IPv6")
        
        print(f"最终合并结果: IPv4: {len(collapsed_v4)}, IPv6: {len(collapsed_v6)}")
        return collapsed_v4 + collapsed_v6
        
    except Exception as e:
        print(f"合并网络时发生严重错误: {e}")
        print("返回未合并的网络列表")
        return list(network_objects)

def separate_and_sort_ips(ip_list: list) -> tuple:
    """分离IPv4和IPv6并排序"""
    ipv4 = sorted([n for n in ip_list if n.version == 4])
    ipv6 = sorted([n for n in ip_list if n.version == 6])
    return ipv4, ipv6

def write_output_file(filepath: Path, networks: list, is_ipv4: bool):
    """写入输出文件，单IP不显示/32或/128"""
    with open(filepath, 'w', encoding='utf-8') as f:
        for network in networks:
            if is_ipv4 and network.prefixlen == 32:
                f.write(str(network.network_address) + '\n')
            elif not is_ipv4 and network.prefixlen == 128:
                f.write(str(network.network_address) + '\n')
            else:
                f.write(str(network) + '\n')

def validate_merge_result(original: set, merged: list):
    """验证合并结果，确保没有遗漏"""
    print("验证合并结果...")
    
    # 将合并后的网络转换为集合用于验证
    merged_set = set(merged)
    
    # 检查是否有网络被过度合并
    ipv4_merged = [n for n in merged if n.version == 4]
    ipv6_merged = [n for n in merged if n.version == 6]
    
    print(f"验证: 原始IPv4数量: {len([n for n in original if isinstance(n, (ipaddress.IPv4Address, ipaddress.IPv4Network))])}")
    print(f"验证: 合并后IPv4数量: {len(ipv4_merged)}")
    print(f"验证: 原始IPv6数量: {len([n for n in original if isinstance(n, (ipaddress.IPv6Address, ipaddress.IPv6Network))])}")
    print(f"验证: 合并后IPv6数量: {len(ipv6_merged)}")

def main():
    """主函数"""
    # 确保输出目录存在
    output_dir = Path('adh')
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 先运行diff_rules
    a_file = 'adh/blocklist.txt'
    b_file = 'adh/domain-blocklist.txt'
    ip_blocklist = 'adh/ip-blocklist.txt'

    if not Path(a_file).exists() or not Path(b_file).exists():
        print(f"错误: 缺少输入文件 {a_file} 或 {b_file}")
        return

    ip_count = diff_rules(a_file, b_file, ip_blocklist)
    if ip_count == 0:
        print("diff_rules未生成IP规则")
        return

    # 处理所有源文件
    all_ips = set()
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        print("开始处理下载源...")
        with ThreadPoolExecutor(max_workers=min(len(SOURCES), 4)) as executor:
            future_to_url = {}
            for i, url in enumerate(SOURCES):
                is_zip = is_zip_url(url)
                file_extension = 'zip' if is_zip else 'txt'
                file_path = temp_path / f"source_{i}.{file_extension}"
                
                future = executor.submit(download_file, url, file_path)
                future_to_url[future] = (url, file_path, i, is_zip)

            # 处理下载的源
            for future in as_completed(future_to_url):
                url, file_path, i, is_zip = future_to_url[future]
                if future.result():
                    print(f"成功下载: {url}")
                    
                    if is_zip:
                        extract_dir = temp_path / f"extracted_{i}"
                        extract_dir.mkdir(exist_ok=True)
                        
                        if extract_and_clean_zip(file_path, extract_dir):
                            # 查找blocklist-ipsets-master目录
                            master_dir = None
                            for item in extract_dir.iterdir():
                                if item.is_dir() and 'blocklist-ipsets' in item.name:
                                    master_dir = item
                                    break
                            
                            if master_dir:
                                dir_ips = process_directory(master_dir)
                                all_ips.update(dir_ips)
                                print(f"处理FireHOL完成: {len(dir_ips)} IPs")
                            else:
                                print(f"警告: 在 {extract_dir} 中未找到blocklist-ipsets目录")
                                dir_ips = process_directory(extract_dir)
                                all_ips.update(dir_ips)
                                print(f"处理ZIP完成: {len(dir_ips)} IPs")
                    else:
                        file_ips = process_single_file(file_path)
                        all_ips.update(file_ips)
                        print(f"处理文本完成: {len(file_ips)} IPs")
                else:
                    print(f"下载失败: {url}")

        # 添加本地生成的ip-blocklist.txt
        print("处理本地生成的ip-blocklist.txt...")
        local_ips = process_single_file(Path(ip_blocklist))
        all_ips.update(local_ips)
        print(f"本地文件处理完成: {len(local_ips)} IPs")

    if not all_ips:
        print("未收集到任何IP")
        return

    print(f"总共收集到 {len(all_ips)} 个IP/CIDR")

    # 合并网段，分离IPv4/IPv6，输出
    consolidated = consolidate_networks(all_ips)
    
    # 验证合并结果
    validate_merge_result(all_ips, consolidated)
    
    ipv4, ipv6 = separate_and_sort_ips(consolidated)

    output_dir = Path('adh')
    output_dir.mkdir(parents=True, exist_ok=True)
    write_output_file(output_dir / 'ipv4.txt', ipv4, True)
    write_output_file(output_dir / 'ipv6.txt', ipv6, False)
    
    # 计算文件大小
    ipv4_size = (output_dir / 'ipv4.txt').stat().st_size / 1024 / 1024
    ipv6_size = (output_dir / 'ipv6.txt').stat().st_size / 1024 / 1024
    
    print(f"最终输出: IPv4: {len(ipv4)} 条目 ({ipv4_size:.2f} MB), IPv6: {len(ipv6)} 条目 ({ipv6_size:.2f} MB)")

if __name__ == "__main__":
    main()
