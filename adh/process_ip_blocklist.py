#!/usr/bin/env python3
"""
IP列表处理脚本 - 最终修复版
修复了网络合并后的重复条目问题
"""

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
        line_count = 0
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line_count += 1
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
    zip_indicators = [
        '.zip' in url,
        'codeload.github.com' in url and '/zip/' in url,
        url.endswith('.zip')
    ]
    return any(zip_indicators)

def consolidate_networks(ip_list: set) -> list:
    """合并重叠和相邻网段 - 最终修复版"""
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
    
    def optimized_collapse_networks(networks, network_type="IPv4"):
        """优化合并网络：改进的合并算法"""
        if not networks:
            return []
        
        print(f"开始优化合并 {network_type} 网络...")
        
        # 第一步：全局去重
        unique_nets = set(networks)
        duplicate_count = len(networks) - len(unique_nets)
        if duplicate_count > 0:
            print(f"全局去重: 移除 {duplicate_count} 个重复网络")
        
        # 第二步：过滤全范围网络
        filtered_nets = []
        for net in unique_nets:
            if network_type == "IPv4" and net.prefixlen == 0:
                continue  # 跳过0.0.0.0/0
            elif network_type == "IPv6" and net.prefixlen == 0:
                continue  # 跳过::/0
            filtered_nets.append(net)
        
        print(f"过滤全范围网络后 {network_type}: {len(filtered_nets)}")
        
        if not filtered_nets:
            return []
        
        # 第三步：全局排序（按网络地址和前缀长度）
        print(f"全局排序 {network_type} 网络...")
        sorted_nets = sorted(filtered_nets, key=lambda x: (int(x.network_address), x.prefixlen))
        
        # 第四步：改进的分批合并策略
        batch_size = 100000
        total_batches = (len(sorted_nets) - 1) // batch_size + 1
        
        if total_batches > 1:
            print(f"分 {total_batches} 批处理 {network_type} 网络...")
            all_collapsed = []
            
            for i in range(0, len(sorted_nets), batch_size):
                batch = sorted_nets[i:i + batch_size]
                batch_num = i // batch_size + 1
                
                print(f"处理批次 {batch_num}/{total_batches}: {len(batch)} 个网络")
                
                try:
                    # 对批次进行合并
                    collapsed_batch = list(ipaddress.collapse_addresses(batch))
                    all_collapsed.extend(collapsed_batch)
                    print(f"  批次合并后: {len(collapsed_batch)} 个网络")
                except Exception as e:
                    print(f"  批次合并失败，使用原始网络: {e}")
                    all_collapsed.extend(batch)
            
            # 第五步：改进的最终合并 - 确保彻底合并
            print("进行最终合并...")
            
            # 先对最终结果进行排序
            all_collapsed_sorted = sorted(all_collapsed, key=lambda x: (int(x.network_address), x.prefixlen))
            
            # 使用更小的批次进行最终合并，确保质量
            final_batch_size = 50000
            final_result = []
            
            for i in range(0, len(all_collapsed_sorted), final_batch_size):
                final_batch = all_collapsed_sorted[i:i + final_batch_size]
                try:
                    collapsed_final = list(ipaddress.collapse_addresses(final_batch))
                    final_result.extend(collapsed_final)
                except Exception as e:
                    print(f"最终批次合并失败: {e}")
                    final_result.extend(final_batch)
            
            # 最后对最终结果进行一次全面合并
            try:
                fully_collapsed = list(ipaddress.collapse_addresses(final_result))
                print(f"全面合并后 {network_type}: {len(fully_collapsed)} 个网络")
                return fully_collapsed
            except Exception as e:
                print(f"全面合并失败，使用最终批次结果: {e}")
                return final_result
        else:
            # 单批次直接合并
            print(f"单批次合并 {network_type} 网络...")
            try:
                collapsed = list(ipaddress.collapse_addresses(sorted_nets))
                print(f"合并后 {network_type}: {len(collapsed)} 个网络")
                return collapsed
            except Exception as e:
                print(f"合并失败，使用原始网络: {e}")
                return sorted_nets
    
    try:
        # 对IPv4和IPv6分别进行优化合并
        collapsed_v4 = optimized_collapse_networks(ipv4_nets, "IPv4")
        collapsed_v6 = optimized_collapse_networks(ipv6_nets, "IPv6")
        
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
