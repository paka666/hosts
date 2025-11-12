#!/usr/bin/env python3
import os
import requests
import re
from urllib.parse import urlparse
from datetime import datetime

# Trackers 下载源
TRACKERS_URLS = [
    "http://github.itzmx.com/1265578519/OpenTracker/master/tracker.txt",
    "https://cf.trackerslist.com/all.txt",
    "https://cf.trackerslist.com/best.txt",
    "https://cf.trackerslist.com/http.txt",
    "https://cf.trackerslist.com/nohttp.txt",
    "https://github.itzmx.com/1265578519/OpenTracker/master/tracker.txt",
    "https://newtrackon.com/api/all",
    "https://newtrackon.com/api/live",
    "https://newtrackon.com/api/10",
    "https://newtrackon.com/api/http",
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

# 输出文件路径
OUTPUT_FILE = "trackers/trackers-back.txt"
BACKUP_FILE = "trackers/trackers-back.bak"

def is_valid_tracker(tracker):
    """验证 tracker 地址是否有效"""
    if not tracker or not tracker.strip():
        return False
    
    tracker = tracker.strip()
    
    # 过滤注释和空行
    if tracker.startswith('#') or tracker == '':
        return False
    
    # 验证 URL 格式
    try:
        parsed = urlparse(tracker)
        if not parsed.scheme or not parsed.netloc:
            return False
        
        # 支持的协议
        valid_schemes = ['udp', 'http', 'https', 'wss', 'ws']
        if parsed.scheme not in valid_schemes:
            return False
            
        return True
    except:
        return False

def download_trackers(url):
    """从 URL 下载 trackers"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"下载失败 {url}: {e}")
        return ""

def parse_trackers_content(content):
    """解析 trackers 内容"""
    trackers = set()
    
    if not content:
        return trackers
    
    # 按行分割
    lines = content.split('\n')
    
    for line in lines:
        line = line.strip()
        
        # 处理逗号分隔的 trackers
        if ',' in line and not line.startswith('#'):
            for tracker in line.split(','):
                tracker = tracker.strip()
                if is_valid_tracker(tracker):
                    trackers.add(tracker)
        # 处理单行 tracker
        elif is_valid_tracker(line):
            trackers.add(line)
    
    return trackers

def load_existing_trackers():
    """加载现有的 trackers"""
    existing_trackers = set()
    
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if is_valid_tracker(line):
                        existing_trackers.add(line)
            print(f"从 {OUTPUT_FILE} 加载了 {len(existing_trackers)} 个现有 tracker")
        except Exception as e:
            print(f"读取现有 trackers 失败: {e}")
    
    return existing_trackers

def backup_existing_file():
    """备份现有文件"""
    if os.path.exists(OUTPUT_FILE):
        import shutil
        shutil.copy2(OUTPUT_FILE, BACKUP_FILE)
        print(f"已备份现有文件到 {BACKUP_FILE}")

def save_trackers(trackers):
    """保存 trackers 到文件"""
    # 确保目录存在
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    
    # 排序 trackers
    sorted_trackers = sorted(trackers)
    
    # 写入文件
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        # 写入文件头
        f.write(f"# Trackers 列表\n")
        f.write(f"# 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# 总数: {len(sorted_trackers)}\n")
        f.write(f"# 来源: {', '.join(TRACKERS_URLS[:3])}...\n")
        f.write("# ==============================================\n\n")
        
        # 写入 trackers
        for tracker in sorted_trackers:
            f.write(f"{tracker}\n")
    
    print(f"成功保存 {len(sorted_trackers)} 个 trackers 到 {OUTPUT_FILE}")

def main():
    print("开始更新 trackers...")
    
    # 备份现有文件
    backup_existing_file()
    
    # 加载现有 trackers
    all_trackers = load_existing_trackers()
    initial_count = len(all_trackers)
    
    # 从各个 URL 下载并合并 trackers
    for i, url in enumerate(TRACKERS_URLS, 1):
        print(f"[{i}/{len(TRACKERS_URLS)}] 正在处理: {url}")
        
        content = download_trackers(url)
        if content:
            new_trackers = parse_trackers_content(content)
            before_count = len(all_trackers)
            all_trackers.update(new_trackers)
            added_count = len(all_trackers) - before_count
            print(f"  从该源添加了 {added_count} 个新 tracker")
        else:
            print(f"  跳过该源（下载失败）")
    
    # 统计信息
    total_added = len(all_trackers) - initial_count
    print(f"\n更新完成!")
    print(f"初始数量: {initial_count}")
    print(f"新增数量: {total_added}")
    print(f"最终总数: {len(all_trackers)}")
    
    # 保存结果
    save_trackers(all_trackers)

if __name__ == "__main__":
    main()
