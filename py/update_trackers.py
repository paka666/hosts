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

print("Fetching trackers from URLs...")
contents = []
for url in urls:
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        contents.append(r.text)
        # print(f"Successfully fetched {url}")
    except Exception as e:
        print(f"Failed to fetch {url}: {e}")

# Read local file if exists
local_file = "trackers/trackers-back.txt"
if os.path.exists(local_file):
    try:
        with open(local_file, "r", encoding="utf-8") as f:
            contents.append(f.read())
        print(f"Successfully read local file: {local_file}")
    except Exception as e:
        print(f"Failed to read {local_file}: {e}")

# Combine all contents
all_text = "\n".join(contents)

# --- 2. 初始清理 ---

print("Cleaning trackers...")
lines = all_text.splitlines()
cleaned = []
for line in lines:
    # 去# ! ;注释
    line = re.split(r"[#!;]", line)[0].strip()
    if not line:
        continue
    # 去, ; 空白字符(包括行首尾 行内)
    parts = [p.strip() for p in re.split(r"[ ,;]", line) if p.strip()]
    cleaned.extend(parts)

# 定义协议和修复 (包括了带//和不带/的)
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
# 用于查找的协议列表
proto_find_list = sorted(protocols_map.keys(), key=len, reverse=True)

# C: 预先修复行首的 :/
for i in range(len(cleaned)):
    for proto, fixed in protocols_map.items():
        if cleaned[i].startswith(proto):
            cleaned[i] = fixed + cleaned[i][len(proto):]
            break

# --- 3. 步骤 A (扩展) ---

print("Processing Step A (concatenated protocols)...")
# A (新): 处理 udp://http://wss://... 这种粘连协议头
new_cleaned = []
for t in cleaned:
    # 匹配一个或多个协议头
    match = re.match(r'^((?:https|http|udp|ws|wss)://?)+(.+?)$', t, re.IGNORECASE)
    if match:
        protos_part = match.group(1)
        suffix = match.group(2)
        # 提取所有粘连的协议
        proto_matches = re.finditer(r'(https|http|udp|ws|wss)', protos_part, re.IGNORECASE)
        found_protos = {pm.group(1).lower() for pm in proto_matches}
        for proto in found_protos:
            new_cleaned.append(f"{proto}://{suffix}")
    else:
        new_cleaned.append(t)
cleaned = new_cleaned

# A (原): 拆分 wss://...http:/... 这种粘连tracker
new_cleaned = []
for t in cleaned:
    current = t
    while True:
        first_split_pos = len(current)
        first_split_proto = None

        # 查找最早出现的协议头 (从第2个字符开始)
        for proto in proto_find_list:
            pos = current.find(proto, 1)
            if 0 < pos < first_split_pos:
                first_split_pos = pos
                first_split_proto = proto
        
        if first_split_proto:
            # 发现粘连, 拆分
            first_part = current[:first_split_pos]
            rest_part = protocols_map[first_split_proto] + current[first_split_pos + len(first_split_proto):]
            
            new_cleaned.append(first_part)
            current = rest_part
        else:
            # 没有粘连, 添加剩余部分并跳出
            new_cleaned.append(current)
            break
cleaned = [t for t in new_cleaned if t] # 去除拆分产生的空行

# --- 4. 步骤 C (部分) 和 修复后的主机验证 ---

print("Processing Step C (endings) and D (host/port fix)...")

# C: 修复 //announce 和 /announce+... 等结尾
for i in range(len(cleaned)):
    cleaned[i] = cleaned[i].replace("//announce", "/announce")
    # 修复 /announce+108, /announce+, /announce"
    cleaned[i] = re.sub(r"/announce(\+\d*|\"|\+)?$", "/announce", cleaned[i])

def is_valid_host(host):
    """
    检查是否为有效的 IP、localhost 或带TLD的域名。
    这会过滤掉 "ipv4announce" 这样的无效主机。
    """
    if not host:
        return False
    if host.lower() == 'localhost':
        return True
    try:
        IPv4Address(host)
        return True
    except AddressValueError:
        pass
    
    # 
    # *** BUG 修复 ***
    # 检查IPv6时, 必须先移除方括号, 
    # 因为 `hostname` 属性会是 "[::1]"
    #
    if host.startswith("[") and host.endswith("]"):
        host_unbracketed = host[1:-1]
    else:
        host_unbracketed = host

    try:
        IPv6Address(host_unbracketed)
        return True
    except AddressValueError:
        pass
    
    # 检查TLD-less名称 (如 'ipv4announce')
    # 我们假设任何带点的(.)主机都是有效的 (如 'tracker.com', 'tracker.local', 'tracker.i2p')
    # 注意: 这里使用 host_unbracketed 来正确处理 [domain.com] 的情况
    if "." in host_unbracketed:
        return True
    
    # No dot, not an IP, not localhost. Filter it.
    return False

# --- 5. 步骤 C (剩余) 和 D (Bug修复) ---

# C & D: 修复 [], 粘连端口, 并过滤无效 TLD
valid_trackers = []
for t in cleaned:
    try:
        parsed = urlparse(t)
        if not parsed.scheme or not parsed.netloc:
            continue

        host = parsed.hostname # e.g., "tracker.com", "1.2.3.4", "[::1]", "[domain.com]"
        port = parsed.port

        # C: 修复 [domain] 或 [domain:port]
        if host and host.startswith("[") and host.endswith("]"):
            inside_host = host[1:-1] # e.g., "::1" or "domain.com"
            try:
                IPv6Address(inside_host)
                # 是合法的IPv6, 'host' 变量 ("[::1]") 保持不变,
                # is_valid_host() 会处理它
            except AddressValueError:
                # 不是IPv6, 认为是 [domain], 移除 []
                host = inside_host # 'host' 变为 "domain.com"
                # 重建 netloc
                new_netloc = host
                if port:
                    new_netloc = f"{host}:{port}"
                if parsed.username:
                    auth = parsed.username
                    if parsed.password:
                        auth += ":" + parsed.password
                    new_netloc = f"{auth}@{new_netloc}"
                
                parsed = parsed._replace(netloc=new_netloc)
                # 重新解析
                host = parsed.hostname
                port = parsed.port


        # D: 修复粘连的端口 (如 .net80, .i2p6969)
        if port is None:
            # 仅在 urlparse 没找到端口时检查
            match = re.match(r"^(.+?)(\d+)$", parsed.netloc)
            if match:
                base = match.group(1)
                port_str = match.group(2)
                try:
                    # 使用新的 is_valid_host 检查
                    if 1 <= int(port_str) <= 65535 and is_valid_host(base):
                        new_netloc = base + ":" + port_str
                        parsed = parsed._replace(netloc=new_netloc)
                        host = parsed.hostname # 重新解析
                except (ValueError, TypeError):
                    pass
        
        # 最终主机有效性检查 (过滤 ipv4announce)
        if not is_valid_host(host):
            # print(f"Filtered invalid host: {host}")
            continue

        valid_trackers.append(parsed.geturl())

    except Exception as e:
        # print(f"Error processing tracker {t}: {e}") # 可选: 开启以调试
        continue # 保证单个tracker的错误不影响全局

cleaned = valid_trackers

# --- 6. 步骤 B, E, F ---

# B: 检查 Suffix, 不匹配则补 /announce
print("Processing Step B (suffix)...")
suffix_pattern = re.compile(r"(\.i2p(:\d+)?/a|/announce(\.php)?(\?(passkey|authkey)=[^?&]+(&[^?&]+)*)?|/announce(\.php)?/[^/]+)$", re.IGNORECASE)
for i in range(len(cleaned)):
    if not suffix_pattern.search(cleaned[i]):
        cleaned[i] += "/announce"

# E: 移除默认端口 (http:80, https:443, ws:80, wss:443)
print("Processing Step E (default ports)...")
default_ports = {
    "http": 80,
    "https://": 443,
    "ws": 80,
    "wss": 443,
}
new_cleaned = []
for t in cleaned:
    try:
        parsed = urlparse(t)
        # 修复: default_ports 的 key 应为 scheme
        if parsed.scheme in default_ports and parsed.port == default_ports[parsed.scheme]:
            # 重建 netloc, 去掉端口
            new_netloc = parsed.hostname
            if parsed.username:
                auth = parsed.username
                if parsed.password:
                    auth += ":" + parsed.password
                new_netloc = auth + "@" + new_netloc
            t = parsed._replace(netloc=new_netloc).geturl()
        new_cleaned.append(t)
    except Exception as e:
        # print(f"Error removing default port from {t}: {e}")
        continue # 丢弃端口处理失败的
cleaned = new_cleaned

# --- 7. 最终处理和备份 ---

print("Deduplicating, sorting, and writing file...")
# 合并去重排序
unique = sorted(list(set(cleaned)))

# F: 备份和更新, 保留最近3次备份
dir_path = "trackers"
os.makedirs(dir_path, exist_ok=True)
local = os.path.join(dir_path, "trackers-back.txt")

try:
    if os.path.exists(local):
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        backup = os.path.join(dir_path, f"{timestamp}-trackers-back.txt")
        shutil.copy(local, backup)
        print(f"Backup created: {backup}")

    with open(local, "w", encoding="utf-8") as f:
        f.write("\n".join(unique) + "\n")

    # 清理旧备份
    backups = glob.glob(os.path.join(dir_path, "*-trackers-back.txt"))
    backups.sort(key=os.path.getmtime, reverse=True)
    if len(backups) > 3:
        for old_backup in backups[3:]:
            os.remove(old_backup)
            print(f"Removed old backup: {old_backup}")

    print(f"Processing complete. Updated {local} with {len(unique)} trackers.")

except Exception as e:
    print(f"Error during file backup/write: {e}")
