#!/usr/bin/env python3
"""
Tracker列表规范化脚本 - 健壮版本
处理多URL源和本地trackers-back.txt，规范化格式并自动备份
"""

import requests
from urllib.parse import urlparse, urlunparse
import re
import os
import time
import glob
import shutil
from ipaddress import IPv6Address, IPv4Address, AddressValueError

# URL源列表
TRACKER_URLS = [
    "http://github.itzmx.com/1265578519/OpenTracker/master/tracker.txt",
    "https://cf.trackerslist.com/all.txt",
    "https://cf.trackerslist.com/best.txt",
    "https://cf.trackerslist.com/http.txt",
    "https://cf.trackerslist.com/nohttp.txt",
    "https://github.itzmx.com/1265578519/OpenTracker/master/tracker.txt",
    "https://newtrackon.com/api/10",
    "https://newtrackon.com/api/all",
    "https://newtrackon.com/api/http",
    "https://newtrackon.com/api/live",
    "https://newtrackon.com/api/stable",
    "https://newtrackon.com/api/udp",
    "https://raw.githubusercontent.com/DeSireFire/animeTrackerList/master/AT_all.txt",
    "https://raw.githubusercontent.com/DeSireFire/animeTrackerList/master/AT_all_http.txt",
    "https://raw.githubusercontent.com/DeSireFire/animeTrackerList/master/AT_all_https.txt",
    "https://raw.githubusercontent.com/DeSireFire/animeTrackerList/master/AT_all_ip.txt",
    "https://raw.githubusercontent.com/DeSireFire/animeTrackerList/master/AT_all_udp.txt",
    "https://raw.githubusercontent.com/DeSireFire/animeTrackerList/master/AT_all_ws.txt",
    "https://raw.githubusercontent.com/DeSireFire/animeTrackerList/master/AT_bad.txt",
    "https://raw.githubusercontent.com/DeSireFire/animeTrackerList/master/AT_best.txt",
    "https://raw.githubusercontent.com/DeSireFire/animeTrackerList/master/AT_best_ip.txt",
    "https://raw.githubusercontent.com/XIU2/TrackersListCollection/master/all.txt",
    "https://raw.githubusercontent.com/XIU2/TrackersListCollection/master/best.txt",
    "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all.txt",
    "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_http.txt",
    "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_https.txt",
    "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_i2p.txt",
    "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_ip.txt",
    "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_udp.txt",
    "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_ws.txt",
    "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best.txt",
    "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best_ip.txt",
    "https://torrends.to/torrent-tracker-list/?download=latest",
    "https://trackerslist.com/all.txt",
    "https://trackerslist.com/best.txt",
    "https://trackerslist.com/http.txt"
]

# 配置常量
LOCAL_TRACKER_FILE = "trackers/trackers-back.txt"
BACKUP_KEEP_COUNT = 3
REQUEST_TIMEOUT = 15

# 支持的协议
SUPPORTED_SCHEMES = {"http", "https", "udp", "ws", "wss"}

# 默认端口映射
DEFAULT_PORTS = {
    "http": 80,
    "https": 443, 
    "ws": 80,
    "wss": 443
}

def fetch_all_sources():
    """从所有URL源和本地文件获取tracker数据"""
    print("📡 获取tracker数据...")
    contents = []
    
    # 从URL获取
    for url in TRACKER_URLS:
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            contents.append(response.text)
            print(f"✅ 成功获取: {url}")
        except Exception as e:
            print(f"❌ 获取失败 {url}: {e}")
    
    # 从本地文件获取
    if os.path.exists(LOCAL_TRACKER_FILE):
        try:
            with open(LOCAL_TRACKER_FILE, "r", encoding="utf-8") as f:
                contents.append(f.read())
            print(f"✅ 成功读取本地文件: {LOCAL_TRACKER_FILE}")
        except Exception as e:
            print(f"❌ 读取本地文件失败: {e}")
    
    return "\n".join(contents)

def clean_and_split_text(text):
    """清理文本：去除注释、空白字符、分割成独立tracker"""
    print("🧹 清理和分割数据...")
    lines = text.splitlines()
    cleaned = []
    
    for line in lines:
        # 去除注释 (# ! ;)
        line = re.split(r"[#!;]", line)[0].strip()
        if not line:
            continue
            
        # 分割逗号、分号、空白字符
        parts = [part.strip() for part in re.split(r"[ ,;]+", line) if part.strip()]
        cleaned.extend(parts)
    
    print(f"📊 初始清理后: {len(cleaned)} 个tracker")
    return cleaned

def fix_protocol_format(trackers):
    """修复协议格式错误"""
    print("🔧 修复协议格式...")
    fixed = []
    
    protocol_fixes = {
        "http:/": "http://",
        "https:/": "https://", 
        "udp:/": "udp://",
        "ws:/": "ws://",
        "wss:/": "wss://"
    }
    
    for tracker in trackers:
        # 修复缺失双斜杠的协议
        for wrong, correct in protocol_fixes.items():
            if tracker.startswith(wrong):
                tracker = correct + tracker[len(wrong):]
                break
        fixed.append(tracker)
    
    return fixed

def split_concatenated_trackers(trackers):
    """分离粘连的tracker"""
    print("🔀 分离粘连tracker...")
    split_trackers = []
    
    # 协议模式
    protocol_pattern = r"(https?://|udp://|ws://|wss://)"
    
    for tracker in trackers:
        # 查找所有协议开始位置
        matches = list(re.finditer(protocol_pattern, tracker, re.IGNORECASE))
        
        if len(matches) <= 1:
            split_trackers.append(tracker)
            continue
            
        # 分离多个tracker
        for i, match in enumerate(matches):
            start_pos = match.start()
            if i + 1 < len(matches):
                end_pos = matches[i + 1].start()
            else:
                end_pos = len(tracker)
            
            single_tracker = tracker[start_pos:end_pos].strip()
            if single_tracker and not single_tracker.endswith('://'):
                split_trackers.append(single_tracker)
    
    print(f"📊 分离后: {len(split_trackers)} 个tracker")
    return split_trackers

def handle_protocol_prefix_concatenation(trackers):
    """处理协议前缀粘连 (如 udp://http://wss://...)"""
    print("🔄 处理协议前缀粘连...")
    processed = []
    
    for tracker in trackers:
        # 匹配多个协议前缀
        match = re.match(r'^((?:https?|udp|ws|wss)://?)+(.+)$', tracker, re.IGNORECASE)
        if match:
            protocols_part = match.group(1)
            suffix = match.group(2)
            
            # 提取所有协议
            found_protocols = set(re.findall(r'(https?|udp|ws|wss)', protocols_part, re.IGNORECASE))
            
            # 为每个协议创建tracker
            for protocol in found_protocols:
                processed.append(f"{protocol.lower()}://{suffix}")
        else:
            processed.append(tracker)
    
    return processed

def is_valid_hostname(hostname):
    """验证主机名是否有效"""
    if not hostname:
        return False
        
    # localhost 是有效的
    if hostname.lower() == 'localhost':
        return True
    
    # 检查IPv4
    try:
        IPv4Address(hostname)
        return True
    except AddressValueError:
        pass
    
    # 检查IPv6 (可能带方括号)
    host_to_check = hostname
    if host_to_check.startswith('[') and host_to_check.endswith(']'):
        host_to_check = host_to_check[1:-1]
    
    try:
        IPv6Address(host_to_check)
        return True
    except AddressValueError:
        pass
    
    # 检查域名：只要包含点就认为是有效域名
    # 这过滤掉类似 'ipv4announce' 的无点主机名
    if '.' in hostname:
        return True
        
    return False

def normalize_tracker_url(tracker):
    """规范化单个tracker URL"""
    try:
        # 基础清理
        tracker = tracker.strip()
        if not tracker:
            return None
        
        # 解析URL
        parsed = urlparse(tracker)
        
        # 验证协议
        if not parsed.scheme or parsed.scheme.lower() not in SUPPORTED_SCHEMES:
            return None
            
        # 验证netloc
        if not parsed.netloc:
            return None
        
        # 提取主机名和端口
        hostname = parsed.hostname
        port = parsed.port
        
        # 验证主机名
        if not is_valid_hostname(hostname):
            return None
        
        # 处理方括号（IPv6和错误使用）
        netloc = parsed.netloc
        if '[' in netloc and ']' in netloc:
            # 提取方括号内内容
            bracket_content = re.search(r'\[([^]]+)\]', netloc)
            if bracket_content:
                inside = bracket_content.group(1)
                try:
                    # 如果是合法IPv6，保留方括号
                    IPv6Address(inside)
                    # 保持原样
                except AddressValueError:
                    # 不是IPv6，移除方括号
                    netloc = netloc.replace(f'[{inside}]', inside)
                    # 重新解析
                    parsed = urlparse(parsed._replace(netloc=netloc).geturl())
        
        # 修复粘连端口 (如 .com80 -> .com:80)
        if not port:
            port_match = re.match(r'^(.+?[a-zA-Z.-])(\d+)$', parsed.netloc)
            if port_match:
                base_host, port_str = port_match.groups()
                if port_str.isdigit() and 1 <= int(port_str) <= 65535:
                    if is_valid_hostname(base_host.rstrip('.')):
                        new_netloc = f"{base_host.rstrip('.')}:{port_str}"
                        parsed = parsed._replace(netloc=new_netloc)
        
        # 处理路径
        path = parsed.path
        
        # 修复双斜杠
        path = re.sub(r'//+', '/', path)
        
        # 修复announce路径问题
        path = path.replace('//announce', '/announce')
        path = re.sub(r'/announce(\+\d*|"|\+)?$', '/announce', path)
        
        # 检查是否需要添加/announce
        valid_suffixes = [
            r'\.i2p(:\d+)?/a',
            r'/announce(\.php)?(\?(passkey|authkey)=[^/?&]+)?',
            r'/announce(\.php)?/[^/?]+$',
            r'/a$'  # I2P tracker
        ]
        
        has_valid_suffix = any(re.search(pattern, path, re.IGNORECASE) for pattern in valid_suffixes)
        
        if not has_valid_suffix:
            if not path or path == '/':
                path = '/announce'
            elif not path.endswith('/announce'):
                # 避免重复添加
                if not re.search(r'/announce([/?]|$)', path):
                    path = path.rstrip('/') + '/announce'
        
        # 重建URL
        normalized_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
        
        # 移除默认端口
        if port and parsed.scheme in DEFAULT_PORTS and port == DEFAULT_PORTS[parsed.scheme]:
            # 重建netloc，移除端口
            new_netloc = parsed.hostname
            if parsed.username:
                auth = parsed.username
                if parsed.password:
                    auth += f":{parsed.password}"
                new_netloc = f"{auth}@{new_netloc}"
            
            normalized_url = urlunparse((
                parsed.scheme,
                new_netloc,
                path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))
        
        return normalized_url
        
    except Exception as e:
        print(f"⚠️ 处理tracker失败 {tracker}: {e}")
        return None

def backup_and_save(trackers):
    """备份旧文件并保存新tracker列表"""
    print("💾 备份和保存文件...")
    
    # 确保目录存在
    os.makedirs(os.path.dirname(LOCAL_TRACKER_FILE), exist_ok=True)
    
    # 备份现有文件
    if os.path.exists(LOCAL_TRACKER_FILE):
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(os.path.dirname(LOCAL_TRACKER_FILE), f"{timestamp}-trackers-back.txt")
        shutil.copy2(LOCAL_TRACKER_FILE, backup_file)
        print(f"✅ 备份创建: {backup_file}")
    
    # 保存新文件
    try:
        with open(LOCAL_TRACKER_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(trackers) + "\n")
        print(f"✅ 成功保存: {LOCAL_TRACKER_FILE}")
    except Exception as e:
        print(f"❌ 保存文件失败: {e}")
        return False
    
    # 清理旧备份
    try:
        backups = glob.glob(os.path.join(os.path.dirname(LOCAL_TRACKER_FILE), "*-trackers-back.txt"))
        backups.sort(key=os.path.getmtime, reverse=True)
        
        if len(backups) > BACKUP_KEEP_COUNT:
            for old_backup in backups[BACKUP_KEEP_COUNT:]:
                os.remove(old_backup)
                print(f"🗑️ 删除旧备份: {old_backup}")
    except Exception as e:
        print(f"⚠️ 清理备份失败: {e}")
    
    return True

def main():
    """主处理函数"""
    print("🚀 开始处理tracker列表...")
    
    # 1. 获取数据
    all_text = fetch_all_sources()
    if not all_text.strip():
        print("❌ 没有获取到任何数据")
        return
    
    # 2. 初始清理
    trackers = clean_and_split_text(all_text)
    
    # 3. 修复协议格式
    trackers = fix_protocol_format(trackers)
    
    # 4. 处理协议前缀粘连
    trackers = handle_protocol_prefix_concatenation(trackers)
    
    # 5. 分离粘连tracker
    trackers = split_concatenated_trackers(trackers)
    
    # 6. 规范化每个tracker
    print("⚙️ 规范化tracker URL...")
    normalized_trackers = []
    for tracker in trackers:
        normalized = normalize_tracker_url(tracker)
        if normalized:
            normalized_trackers.append(normalized)
    
    print(f"📊 规范化后: {len(normalized_trackers)} 个tracker")
    
    # 7. 去重排序
    unique_trackers = sorted(set(normalized_trackers))
    print(f"🎯 最终去重后: {len(unique_trackers)} 个唯一tracker")
    
    # 8. 保存结果
    if backup_and_save(unique_trackers):
        print(f"✅ 处理完成! 共 {len(unique_trackers)} 个tracker")
        
        # 显示前10个作为示例
        print("\n📋 前10个tracker示例:")
        for i, tracker in enumerate(unique_trackers[:10]):
            print(f"  {i+1}. {tracker}")
    else:
        print("❌ 处理失败")

if __name__ == "__main__":
    main()
