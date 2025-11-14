#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import shutil
import glob
from datetime import datetime
import requests

# --- 配置区域 ---

# 步骤1: 定义url源和本地源
# 在此处添加您需要抓取的URL源列表
URL_SOURCES = [
    # "https://example.com/trackerlist1.txt",
    # "https://example.com/trackerlist2.txt",
    # "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all.txt"
]

# 本地文件的路径
TRACKERS_DIR = "trackers"
LOCAL_FILE = os.path.join(TRACKERS_DIR, "trackers-back.txt")
ERROR_FILE = os.path.join(TRACKERS_DIR, "error.txt")
BACKUP_KEEP = 3  # 保留最近3次备份

# 步骤2: 最后的正则 (不区分大小写)
# 注意：这是一个非常长的单行字符串
MAIN_REGEX_STR = r'^(?:(?:http|https|udp|ws|wss)://)(?:(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}))(?::(?:[1-9]|[1-5]?[0-9]{2,4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?/(?:[^/]+/)*announce(?:\.php)?(?:\?(?:passkey|authkey)=[^&#]+|/[^/&#]+)?|(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.i2p)(?::(?:[1-9]|[1-5]?[0-9]{2,4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?/(?:[^/]+/)*a|(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})(?::(?:[1-9]|[1-5]?[0-9]{2,4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?/(?:[^/]+/)*announce(?:\.php)?(?:\?(?:passkey|authkey)=[^&#]+|/[^/&#]+)?|\[((?:(?:[0-9A-Fa-f]{1,4}:){7}(?:[0-9A-Fa-f]{1,4}|:))|(?:(?:[0-9A-Fa-f]{1,4}:){6}(?::[0-9A-Fa-f]{1,4}|(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(?:(?:[0-9A-Fa-f]{1,4}:){5}(?:(?::[0-9A-Fa-f]{1,4}){1,2}|:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(?:(?:[0-9A-Fa-f]{1,4}:){4}(?:(?::[0-9A-Fa-f]{1,4}){1,3}|(?::[0-9A-Fa-f]{1,4})?:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(?:(?:[0-9A-Fa-f]{1,4}:){3}(?:(?::[0-9A-Fa-f]{1,4}){1,4}|(?::[0-9A-Fa-f]{1,4}){0,2}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(?:(?:[0-9A-Fa-f]{1,4}:){2}(?:(?::[0-9A-Fa-f]{1,4}){1,5}|(?::[0-9A-Fa-f]{1,4}){0,3}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(?:(?:[0-9A-Fa-f]{1,4}:){1}(?:(?::[0-9A-Fa-f]{1,4}){1,6}|(?::[0-9A-Fa-f]{1,4}){0,4}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(?::(?:(?::[0-9A-Fa-f]{1,4}){1,7}|(?::[0-9A-Fa-f]{1,4}){0,5}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:)))\](?::(?:[1-9]|[1-5]?[0-9]{2,4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?/(?:[^/]+/)*announce(?:\.php)?(?:\?(?:passkey|authkey)=[^&#]+|/[^/&#]+)?)$'

# 编译主正则
try:
    MAIN_REGEX = re.compile(MAIN_REGEX_STR, re.IGNORECASE)
except re.error as e:
    print(f"主正则表达式编译失败: {e}")
    exit(1)

# --- 辅助函数 ---

def fetch_url(url):
    """从URL获取文本内容"""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # 如果请求失败则引发异常
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"抓取失败 {url}: {e}")
        return ""

def read_file(filepath):
    """读取文件内容"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        print(f"未找到本地文件: {filepath} (将跳过)")
        return ""
    except Exception as e:
        print(f"读取文件失败 {filepath}: {e}")
        return ""

def write_file(filepath, content_set):
    """将set内容排序后写入文件，每行一个"""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("\n".join(sorted(list(content_set))))
        print(f"已写入 {len(content_set)} 条到 {filepath}")
    except Exception as e:
        print(f"写入文件失败 {filepath}: {e}")

def manage_backups(file_to_backup, backup_dir, keep=3):
    """备份文件并清理旧备份"""
    if not os.path.exists(file_to_backup):
        print(f"备份源文件 {file_to_backup} 不存在，跳过备份。")
        return

    # 1. 创建备份
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    base_name = os.path.basename(file_to_backup)
    backup_name = f"{timestamp}_{base_name}.bak"
    backup_path = os.path.join(backup_dir, backup_name)
    
    try:
        shutil.copy2(file_to_backup, backup_path)
        print(f"已备份 {file_to_backup} 到 {backup_path}")
    except Exception as e:
        print(f"备份文件失败: {e}")
        return

    # 2. 清理历史备份
    backup_pattern = os.path.join(backup_dir, f"*_{base_name}.bak")
    existing_backups = glob.glob(backup_pattern)
    
    if len(existing_backups) > keep:
        existing_backups.sort()  # 按时间戳（文件名）排序
        backups_to_remove = existing_backups[:-keep] # 保留最新的 'keep' 个
        
        print(f"找到 {len(existing_backups)} 个备份，保留 {keep} 个。")
        for old_backup in backups_to_remove:
            try:
                os.remove(old_backup)
                print(f"  - 已删除旧备份: {old_backup}")
            except Exception as e:
                print(f"  - 删除旧备份失败 {old_backup}: {e}")

# --- 主处理函数 ---

def process_trackers():
    """执行所有处理步骤"""
    
    # 确保目录存在
    os.makedirs(TRACKERS_DIR, exist_ok=True)

    # --- 步骤 1: 合并去重排序 ---
    print("--- 步骤 1: 开始合并、清理和排序源 ---")
    
    all_content = []
    
    # 获取本地源
    all_content.append(read_file(LOCAL_FILE))
    
    # 获取URL源
    for url in URL_SOURCES:
        print(f"正在抓取: {url}")
        all_content.append(fetch_url(url))

    raw_lines = "\n".join(all_content).splitlines()
    processed_lines = set()

    for line in raw_lines:
        # 去注释
        line = line.split('#')[0].split('!')[0].split(';')[0].strip()
        
        # 去, ; 空白字符(包括行首尾 行内 即全文)
        line = re.sub(r'[\s,;]', '', line)
        
        # 去空白行 空行
        if line:
            processed_lines.add(line)

    sorted_lines = sorted(list(processed_lines))
    print(f"步骤 1: 完成。共找到 {len(sorted_lines)} 条初步清理的trackers。")

    # --- 步骤 2: 按照正则提取 ---
    print("\n--- 步骤 2: 第一次正则匹配 ---")
    temp1 = set() # 正确
    temp2 = set() # 待处理
    
    for line in sorted_lines:
        if MAIN_REGEX.match(line):
            temp1.add(line)
        else:
            temp2.add(line)
            
    print(f"步骤 2: 完成。 {len(temp1)} 条匹配 (temp1), {len(temp2)} 条待处理 (temp2)。")

    # --- 步骤 3: 处理 temp2 ---
    print("\n--- 步骤 3: 开始清理 temp2 ---")
    cleaned_temp2 = set()

    for line in temp2:
        # (c) 首位连接情况, 如 ...announceudp://...
        # 用换行符分割，后续会按行处理
        lines_c = re.sub(r'(/announce)(?=(?:https?|udp|wss?)://)', r'\1\n', line, flags=re.IGNORECASE).splitlines()
        
        temp_lines_b = []
        for line_c in lines_c:
            # (b) 多协议头, 如 udp://http://wss://...
            protocols = re.findall(r'(https?|udp|wss)://', line_c, flags=re.IGNORECASE)
            if len(protocols) > 1:
                try:
                    # 找到最后一个协议头
                    last_proto_match = list(re.finditer(r'(https?|udp|wss?)://', line_c, flags=re.IGNORECASE))[-1]
                    # 提取 域名/路径
                    host_path = line_c[last_proto_match.start():]
                    host_path = re.sub(r'^(https?|udp|wss?)://', '', host_path, count=1, flags=re.IGNORECASE)
                    
                    # 重新组合
                    for proto in protocols:
                        temp_lines_b.append(f"{proto}://{host_path}")
                except Exception:
                    temp_lines_b.append(line_c) # 提取失败，保留原样
            else:
                temp_lines_b.append(line_c)

        # 对 (b) 和 (c) 拆分后的所有行应用 (a, d, e, f)
        for line_b in temp_lines_b:
            if not line_b:
                continue

            # (a) 协议头:/ 和 //announce
            # 协议头:/ 改为 协议头://
            line_a = re.sub(r'(https?|udp|wss):/([^/])', r'\1://\2', line_b, flags=re.IGNORECASE)
            # (非协议头后的) // 改为 /
            line_a = re.sub(r'(?<!:)/{2,}', '/', line_a)

            # (d) 不正确的后缀改为announce
            line_d = re.sub(r'(/announce)[\s"+].*$', r'\1', line_a, flags=re.IGNORECASE)
            
            # (e) 去掉非ipv6的[]
            line_e = re.sub(r'://\[([^\]]*\.[^\]]*)\]', r'://\1', line_d, flags=re.IGNORECASE)
            
            # (f) 去掉.tld后的数字
            line_f = re.sub(r'(\.(?:[a-z]{2,63}|i2p))(\d+)(/(?:[^/]+/)*announce)', r'\1\3', line_e, flags=re.IGNORECASE)

            cleaned_temp2.add(line_f)

    print(f"步骤 3 (a-f): 清理完成。")

    # (g) 用正则提取temp2，与temp1合并去重排序为temp3，余下为错误track，作为temp4
    temp3 = set(temp1) # 包含第一次匹配
    temp4 = set()
    
    for line in cleaned_temp2:
        if line and MAIN_REGEX.match(line):
            temp3.add(line)
        elif line: # 确保非空行才加入错误列表
            temp4.add(line)

    print(f"步骤 3 (g): 第二次正则匹配完成。")
    print(f"  - temp3 (有效): {len(temp3)} (新增 {len(temp3) - len(temp1)} 条)")
    print(f"  - temp4 (无效): {len(temp4)}")

    # (h) temp3严格提取:80 :443所有端口，去除后去重排序为temp5
    temp5 = set()
    for line in temp3:
        # 使用 lookahead (?=/) 确保只替换 :80/ 和 :443/
        line_h = re.sub(r':(80|443)(?=/)', '', line)
        temp5.add(line_h)
    
    sorted_temp5 = sorted(list(temp5))
    print(f"步骤 3 (h): 移除 :80 和 :443 端口完成。最终有效 tracker: {len(sorted_temp5)} 条。")

    # (i) 备份本地源，更新，保存错误
    print("\n--- 步骤 4: 备份与保存 ---")
    
    # 备份
    manage_backups(LOCAL_FILE, TRACKERS_DIR, keep=BACKUP_KEEP)
    
    # 更新
    write_file(LOCAL_FILE, sorted_temp5)
    
    # 保存错误
    write_file(ERROR_FILE, sorted(list(temp4)))

    print("\n--- 脚本执行完毕 ---")

# --- 运行 ---
if __name__ == "__main__":
    process_trackers()
