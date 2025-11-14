import requests
from urllib.parse import urlparse
import re
from ipaddress import IPv6Address, IPv4Address, AddressValueError
import os
import time
import glob
import shutil

# List of URLs
urls = [
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

# --- 1. 获取数据 ---
contents = []
for url in urls:
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        contents.append(r.text)
    except Exception as e:
        print(f"Failed to fetch {url}: {e}")

# Read local file if exists
local_file = "trackers/trackers-back.txt"
if os.path.exists(local_file):
    try:
        with open(local_file, "r", encoding="utf-8") as f:
            contents.append(f.read())
    except Exception as e:
        print(f"Failed to read {local_file}: {e}")

# Combine all contents
all_text = "\n".join(contents)

# --- 2. 初始清理 ---
lines = all_text.splitlines()
cleaned = []
for line in lines:
    # 去 # ! ; 注释
    line = re.split(r"[#!;]", line)[0].strip()
    if not line:
        continue
    # 去空格和分隔符
    parts = [p.strip() for p in re.split(r"[ ,;]", line) if p.strip()]
    cleaned.extend(parts)

# --- 3. 步骤 A (扩展) ---
# 定义协议和修复
protocols_map = {
    "http:/": "http://",
    "https:/": "https://",
    "udp:/": "udp://",
    "ws:/": "ws://",
    "wss:/": "wss://",
    "http://": "http://",
    "https://": "https://",
    "udp://": "udp://",
    "ws://": "ws://",
    "wss://": "wss://",
}

# A: 处理多协议粘连情况
new_cleaned = []
for t in cleaned:
    match = re.match(r'^((?:https|http|udp|ws|wss)://?)+(.+?)$', t, re.IGNORECASE)
    if match:
        protos_part = match.group(1)
        suffix = match.group(2)
        proto_matches = re.finditer(r'(https|http|udp|ws|wss)', protos_part, re.IGNORECASE)
        found_protos = {pm.group(1).lower() for pm in proto_matches}
        for proto in found_protos:
            new_cleaned.append(f"{proto}://{suffix}")
    else:
        new_cleaned.append(t)
cleaned = new_cleaned

# --- 4. 步骤 B: 补充 /announce ---
# 检查是否需要补充 /announce
suffix_pattern = re.compile(r"(\.i2p(:\d+)?/a|/announce(\.php)?(\?(passkey|authkey)=[^?&]+(&[^?&]+)*)?|/announce(\.php)?/[^/]+)$", re.IGNORECASE)
for i in range(len(cleaned)):
    if not suffix_pattern.search(cleaned[i]):
        cleaned[i] += "/announce"

# --- 5. 步骤 C/D: 修复格式问题 ---
# 清理不合规的域名和端口问题
valid_trackers = []
for t in cleaned:
    try:
        parsed = urlparse(t)
        if not parsed.scheme or not parsed.netloc:
            continue
        host = parsed.hostname
        port = parsed.port

        # 检查协议头
        if not parsed.scheme in protocols_map:
            continue

        # 检查主机名是否有效
        if not host or not host.strip():
            continue

        # 修复 IPv6 地址的方括号问题
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]

        # 合法的 tracker，添加到有效列表
        valid_trackers.append(parsed.geturl())

    except Exception as e:
        continue

cleaned = valid_trackers

# --- 6. 去重排序 ---
# 去除重复项并排序
unique = sorted(set(cleaned))

# --- 7. 最终写入文件 ---
output_file = "trackers/trackers-back.txt"
os.makedirs(os.path.dirname(output_file), exist_ok=True)
with open(output_file, "w", encoding="utf-8") as f:
    f.write("\n".join(unique))

print(f"Processing complete. Updated {output_file} with {len(unique)} trackers.")
