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

# Fetch contents from URLs
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

# Split into lines and clean
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

# --- 4. 步骤 C (部分) 和 TLD 准备 ---

# C: 修复 //announce 和 /announce+... 等结尾
for i in range(len(cleaned)):
    cleaned[i] = cleaned[i].replace("//announce", "/announce")
    # 修复 /announce+108, /announce+, /announce"
    cleaned[i] = re.sub(r"/announce(\+\d*|\"|\+)?$", "/announce", cleaned[i])

# 获取 TLD 列表, 带后备
try:
    tld_text = requests.get("https://data.iana.org/TLD/tlds-alpha-by-domain.txt", timeout=10).text
    tlds = {line.lower() for line in tld_text.splitlines() if line and not line.startswith("#")}
except Exception:
    print("Failed to fetch TLD list, using fallback common TLDs.")
    tlds = set([
        'com', 'net', 'org', 'info', 'biz', 'uk', 'de', 'eu', 'ru', 'br', 'in', 'cn', 'fr', 'it', 'es', 'nl', 
        'pl', 'ca', 'jp', 'au', 'se', 'ch', 'no', 'dk', 'at', 'be', 'mx', 'tr', 'fi', 'pt', 'cz', 'hu', 'ar', 
        'gr', 'cl', 'ie', 'nz', 'za', 'ir', 'ua', 'tw', 'ro', 'th', 'il', 'ph', 'sk', 'hk', 'sg', 'my', 'lt', 
        'lv', 'ee', 'si', 'hr', 'rs', 'md', 'by', 'bg', 'mk', 'cy', 'pk', 'id', 'us', 'cc', 'io', 'me', 'to', 
        'pro', 'tv', 'ws', 'mobi', 'asia', 'name', 'today', 'club', 'top', 'xyz'
    ])
tlds.add("i2p") # 添加 i2p

def is_valid_host(host, tlds_set):
    """检查是否为有效的 IP 或 TLD 域名"""
    if not host:
        return False
    try:
        IPv4Address(host)
        return True
    except AddressValueError:
        pass
    try:
        IPv6Address(host)
        return True
    except AddressValueError:
        pass
    if "." in host:
        tld = host.rsplit(".", 1)[-1].lower()
        if tld in tlds_set:
            return True
    return False

# --- 5. 步骤 C (剩余) 和 D (Bug修复) ---

# C & D: 修复 [], 粘连端口, 并过滤无效 TLD
valid_trackers = []
for t in cleaned:
    try:
        parsed = urlparse(t)
        if not parsed.scheme or not parsed.netloc:
            continue

        netloc = parsed.netloc
        host = parsed.hostname
        port = parsed.port

        # C: 修复 [domain] 或 [domain:port]
        if netloc.startswith("[") and netloc.endswith("]"):
            inside = netloc[1:-1]
            try:
                # 检查方括号内是否为合法IPv6
                test_host = inside.rsplit("]:", 1)[0] if "]:" in netloc else inside
                IPv6Address(test_host)
                # 是合法IPv6, host 和 port 已经是正确的
            except AddressValueError:
                # 不是合法IPv6, 视为 [domain] or [domain:port], 移除[]
                parsed = parsed._replace(netloc=inside)
                host = parsed.hostname # 重新解析
                port = parsed.port

        # D: 修复粘连的端口 (如 .net80, .i2p6969)
        if port is None:
            # 仅在 urlparse 没找到端口时检查
            # 使用修复 C 步骤后的 netloc
            match = re.match(r"^(.+?)(\d+)$", parsed.netloc)
            if match:
                base = match.group(1)
                port_str = match.group(2)
                try:
                    if 1 <= int(port_str) <= 65535 and is_valid_host(base, tlds):
                        new_netloc = base + ":" + port_str
                        parsed = parsed._replace(netloc=new_netloc)
                        host = parsed.hostname # 重新解析
                        port = parsed.port
                except ValueError:
                    pass

        # C: 验证主机 (过滤 ipv4announce 和处理 unbracketed-ipv6)
        if host is None:
            # host 为 None 可能是无方括号的IPv6, 尝试修复
            if ":" in netloc:
                try:
                    IPv6Address(netloc) # e.g., 2001:db8::1
                    host = netloc
                except AddressValueError:
                    try:
                        # e.g., 2001:db8::1:8080
                        h, p = netloc.rsplit(":", 1)
                        IPv6Address(h)
                        host = h
                    except (ValueError, AddressValueError):
                        continue # 无法解析, 丢弃
            else:
                continue # host 为 None 且不含 ':', 丢弃
        
        # 最终主机有效性检查
        if not is_valid_host(host, tlds):
            continue

        valid_trackers.append(parsed.geturl())

    except Exception:
        # print(f"Error processing tracker {t}: {e}") # 可选: 开启以调试
        continue # 保证单个tracker的错误不影响全局

cleaned = valid_trackers

# --- 6. 步骤 B, E, F ---

# B: 检查 Suffix, 不匹配则补 /announce
suffix_pattern = re.compile(r"(\.i2p(:\d+)?/a|/announce(\.php)?(\?(passkey|authkey)=[^?&]+(&[^?&]+)*)?|/announce(\.php)?/[^/]+)$", re.IGNORECASE)
for i in range(len(cleaned)):
    if not suffix_pattern.search(cleaned[i]):
        cleaned[i] += "/announce"

# E: 移除默认端口 (http:80, https:443, ws:80, wss:443)
default_ports = {
    "http": 80,
    "https": 443,
    "ws": 80,
    "wss": 443,
}
new_cleaned = []
for t in cleaned:
    try:
        parsed = urlparse(t)
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
    except Exception:
        # print(f"Error removing default port from {t}: {e}")
        continue # 丢弃端口处理失败的
cleaned = new_cleaned

# --- 7. 最终处理和备份 ---

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
