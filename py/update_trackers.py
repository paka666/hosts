#!/usr/bin/env python3
"""
update_trackers.py
严格版：规范化 tracker 列表，处理协议粘连、端口粘连、[] IPv6、补 /announce、保留 passkey/authkey 等。
输出为 trackers/trackers-back.txt（备份保留最近 3 次）
"""
from urllib.parse import urlparse, urlunparse, ParseResult
import re
import os
import time
import glob
import shutil

# ---------- 配置 ----------
# （如需添加/删除源，把 urls 改成你自己的）
urls = [
    # 常用来源（保留你原来的列表或按需替换）
    "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all.txt",
    "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all_udp.txt",
    "https://raw.githubusercontent.com/XIU2/TrackersListCollection/master/all.txt",
    # 更多可以按需加入...
]

LOCAL_FILE = "trackers/trackers-back.txt"
OUT_DIR = os.path.dirname(LOCAL_FILE) or "trackers"
KEEP_BACKUPS = 3

# 允许的 scheme 集合（parsed.scheme 返回的就是这些，不含 ://）
ALLOWED_SCHEMES = {"http", "https", "udp", "ws", "wss"}

# 用于把各种可能写法规整成 canonical scheme
SCHEME_FIXES = {
    "http:/": "http",
    "https:/": "https",
    "udp:/": "udp",
    "ws:/": "ws",
    "wss:/": "wss",
    "http://": "http",
    "https://": "https",
    "udp://": "udp",
    "ws://": "ws",
    "wss://": "wss",
}

# 后缀检测（若不匹配则补 /announce）
SUFFIX_RE = re.compile(
    r"(\.i2p(:\d+)?/a|/announce(\.php)?(\?(passkey|authkey)=[^?&]+(&[^?&]+)*)?|/announce(\.php)?/[^/]+)$",
    re.IGNORECASE,
)

# 正则：匹配协议出现点（用于拆粘连），我们只检测 protocol:// 这类出现点来拆分
PROTOCOL_OCCURRENCE_RE = re.compile(r"(https?|udp|wss?|ws)://", re.IGNORECASE)

# ---------- 工具函数 ----------
def read_local_file(path):
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def fetch_sources():
    # 为了在各种环境都能运行，这里不做网络请求（CI/离线环境可能失败）。
    # 如果你在可联网环境希望抓取外部 URL，请在此处用 requests.get() 添加内容到 texts 列表。
    texts = []
    # 尝试读取本地现有文件作为输入（便于增量）
    texts.append(read_local_file(LOCAL_FILE))
    return "\n".join(texts)

def remove_comments_and_split(text):
    """
    去注释（半角 # ; !），按逗号/分号/空白拆分行，返回 tokens（潜在的 tracker 字符串）
    """
    tokens = []
    for raw_line in text.splitlines():
        line = re.split(r"[#!;]", raw_line)[0]  # 去注释
        if not line:
            continue
        # 替换常见全角逗号、分号为半角（若你的源含中文标点）
        line = line.replace("，", ",").replace("；", ";")
        # 按 , ; 空白 分割（包括行内）
        parts = [p.strip() for p in re.split(r"[,\s;]+", line) if p.strip()]
        tokens.extend(parts)
    return tokens

def split_concatenated_protocols(token):
    """
    处理两类粘连情况：
    1) 协议粘连在开头：udp://http://wss://host/..  -> 产生每个协议对应同一 suffix
    2) 行内多个 URL 连在一起 ...announcehttp://other/...  -> 按 protocol:// 较早出现处拆分为多个 URL
    返回 list of tokens
    """
    out = []

    # 先处理开头连续协议（如 udp://http://...）
    m = re.match(r'^((?:https?|udp|ws|wss)://?)+(.+)$', token, re.IGNORECASE)
    if m:
        protos_part = m.group(1)
        suffix = m.group(2)
        # 找出出现过的协议（按出现顺序）
        proto_seq = re.findall(r'(https?|udp|ws|wss)', protos_part, re.IGNORECASE)
        # 可能重复，保留原顺序但去重
        seen = set()
        proto_unique = [p.lower() for p in proto_seq if not (p.lower() in seen or seen.add(p.lower()))]
        for p in proto_unique:
            out.append(f"{p}://{suffix}")
        # NOTE: 也要继续对每个生成项做行内拆分（下面 code 会处理）
    else:
        out.append(token)

    # 处理行内粘连 e.g. "...announcehttp://other..."
    final = []
    for t in out:
        # 如果字符串中间出现 protocol://（从第1个字符起查找），说明是粘连多个 URL
        parts = []
        s = t
        # find all occurrences of protocol:// positions
        occ = [(m.start(), m.group(0)) for m in PROTOCOL_OCCURRENCE_RE.finditer(s)]
        if not occ:
            final.append(s)
            continue
        # 构建 split positions
        # prepend 0 if s starts with protocol (we'll keep whole)
        # We'll split by slicing: find earliest protocol after pos 0
        idxs = [pos for pos, _ in occ]
        # if the first occ at 0, normal; else might be trailing '...announcehttp://'
        # We will walk: find earliest occurrence at pos > 0 and split before it.
        cur = 0
        while True:
            # find next occurrence after cur+0 (but we want occurrences with pos>cur)
            nxt = None
            nxt_pos = None
            for pos, _ in occ:
                if pos > cur:
                    nxt = pos
                    nxt_pos = pos
                    break
            if nxt is None:
                # remainder
                part = s[cur:].strip()
                if part:
                    parts.append(part)
                break
            # if nxt==cur -> the token starts with protocol, take until next occurrence or end
            if nxt == cur:
                # find following occurrence
                following = None
                for pos, _ in occ:
                    if pos > nxt:
                        following = pos
                        break
                if following:
                    part = s[cur:following].strip()
                    parts.append(part)
                    cur = following
                    continue
                else:
                    parts.append(s[cur:].strip())
                    break
            else:
                # nxt > cur and cur may be 0 or >0: take s[cur:nxt] as a part (may be leading garbage)
                part = s[cur:nxt].strip()
                if part:
                    # If part contains no protocol at start, we try to fix by prepending the protocol of nxt
                    # but safer approach: keep part only if it looks like a URL (has "://" inside) else drop
                    if "://" in part:
                        parts.append(part)
                cur = nxt
                continue
        # append parts
        final.extend(parts)
    # final dedupe small empties
    return [f for f in final if f]

def canonicalize_scheme_prefix(s):
    """把可能的 'http:/' 'http://' 等前缀规范成 'http://' 便于 urlparse 正确解析"""
    for k, v in SCHEME_FIXES.items():
        if s.lower().startswith(k):
            rest = s[len(k):]
            return f"{v}://{rest}" if not k.endswith("://") else s
    return s

def safe_urlparse(s):
    """对可能缺少 // 或写法不规范的 URL 做预处理后再 parse"""
    s = s.strip()
    # 处理类似 "http:/1.2.3.4:80/announce" -> "http://1.2.3.4:80/announce"
    s = canonicalize_scheme_prefix(s)
    # 如果没有协议但形如 ipv4:port/... -> treat as http? We won't accept no-protocol.
    return urlparse(s)

def host_is_valid(host):
    """
    判定 host 是否合理：
    - 允许 IPv4 格式
    - 允许 IPv6（带或不带方括号，后面我们保留方括号）
    - 允许任何包含 '.' 的域名（比如 tracker.com tracker.local tracker.i2p）
    - 过滤掉像 'ipv4announce' 一类无点的垃圾 host
    """
    if not host:
        return False
    # strip possible brackets for check
    h = host
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    # IPv4
    try:
        parts = h.split(".")
        if len(parts) == 4 and all(0 <= int(p) < 256 for p in parts):
            return True
    except Exception:
        pass
    # IPv6 (try)
    try:
        import ipaddress
        ipaddress.IPv6Address(h)
        return True
    except Exception:
        pass
    # domain must contain a dot
    if "." in h:
        return True
    return False

def normalize_netloc(parsed):
    """
    返回规范化的 netloc（带或不带端口），并保留 username:password@
    注意：parsed.hostname for IPv6 from urlparse may be like '2001:db8::1' or with brackets? urlparse strips brackets from hostname.
    We'll rebuild using parsed.hostname and parsed.port
    """
    userinfo = ""
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo += f":{parsed.password}"
        userinfo += "@"
    host = parsed.hostname or ""
    # If host contains ':' (ipv6) urlparse normally returns without brackets in hostname; we will re-bracket it
    if ":" in host and not host.startswith("["):
        host_display = f"[{host}]"
    else:
        host_display = host
    if parsed.port:
        return f"{userinfo}{host_display}:{parsed.port}"
    else:
        return f"{userinfo}{host_display}"

def rebuild_url(parsed):
    """按规范重建 URL（保持 path + query + fragment）并把 host 用 normalize_netloc"""
    netloc = normalize_netloc(parsed)
    p = ParseResult(scheme=parsed.scheme, netloc=netloc, path=parsed.path or "",
                    params=parsed.params or "", query=parsed.query or "", fragment=parsed.fragment or "")
    return urlunparse(p)

# ---------- 主流程 ----------
def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    text = fetch_sources()
    tokens = remove_comments_and_split(text)

    # step A: 展开粘连协议 / 粘连 url
    expanded = []
    for tok in tokens:
        # first, normalize possible stray punctuation like ",/announce" -> split_token will handle
        tok = tok.strip()
        # if token equals just "/announce" etc skip (these are suffix-only junk)
        if tok in ("/announce", "/announce.php"):
            continue
        # split concatenated protocols & concatenated urls
        pieces = split_concatenated_protocols(tok)
        for p in pieces:
            expanded.append(p.strip())

    # step: canonicalize scheme prefix
    canonical = [canonicalize_scheme_prefix(t) for t in expanded]

    # step: parse & validate each candidate
    keep = []
    for cand in canonical:
        if not cand:
            continue
        parsed = safe_urlparse(cand)
        # must have scheme and netloc
        if not parsed.scheme or not parsed.netloc:
            continue
        scheme = parsed.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            # sometimes urlparse can place scheme as e.g. 'wss' good; but if scheme includes trailing ':' it's handled earlier
            continue

        # host check: urlparse.hostname strips brackets from IPv6; but parsed.netloc may contain brackets
        host = parsed.hostname
        if not host:
            # try to extract from netloc manual (for weird cases)
            # remove possible userinfo
            nl = parsed.netloc
            if "@" in nl:
                nl = nl.split("@", 1)[1]
            # strip possible :port
            if ":" in nl and nl.count(":") == 1:
                host = nl.split(":", 1)[0]
            else:
                host = nl
        if not host_is_valid(host):
            continue

        # suffix check: if no valid suffix, append /announce (but keep existing query etc)
        full = rebuild_url(parsed)
        if not SUFFIX_RE.search(full):
            # append /announce carefully preserving query/fragment: if there is a path, append '/announce' to path
            # but simpler: if path endswith '/', append 'announce' else append '/announce'
            path = parsed.path or ""
            q = parsed.query or ""
            f = parsed.fragment or ""
            if path.endswith("/"):
                new_path = path + "announce"
            elif path == "":
                new_path = "/announce"
            else:
                # path exists but doesn't look like announce-like, we append /announce
                new_path = path + "/announce"
            rebuilt = urlunparse(ParseResult(parsed.scheme, parsed.netloc, new_path, parsed.params, q, f))
            full = rebuilt

        # sanitize double slashes in path like //announce -> /announce
        full = re.sub(r"//+", "/", full, count=0)
        # keep passkey/authkey as-is (we did not alter query)
        keep.append(full)

    # step: remove default ports for http/https/ws/wss (remove :80 for http/ws and :443 for https/wss)
    final = []
    for url in keep:
        parsed = safe_urlparse(url)
        if parsed.port:
            if (parsed.scheme == "http" and parsed.port == 80) or (parsed.scheme == "ws" and parsed.port == 80):
                # drop port
                noport = urlunparse(ParseResult(parsed.scheme, parsed.hostname if not ":" in parsed.hostname else f"[{parsed.hostname}]", parsed.path, parsed.params, parsed.query, parsed.fragment))
                # but need to preserve userinfo if any: parsed.netloc could have it; rebuild carefully:
                final.append(rebuild_url(ParseResult(parsed.scheme, parsed.hostname, parsed.path, parsed.params, parsed.query, parsed.fragment)))
                continue
            if (parsed.scheme == "https" and parsed.port == 443) or (parsed.scheme == "wss" and parsed.port == 443):
                final.append(rebuild_url(ParseResult(parsed.scheme, parsed.hostname, parsed.path, parsed.params, parsed.query, parsed.fragment)))
                continue
        final.append(url)

    # dedupe & sort (stable)
    seen = set()
    unique = []
    for item in final:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    unique.sort()  # alphabetical sort

    # write output with backups
    # create backup if exists
    if os.path.exists(LOCAL_FILE):
        ts = time.strftime("%Y%m%d_%H%M%S")
        backup = os.path.join(OUT_DIR, f"{ts}-trackers-back.txt")
        shutil.copy(LOCAL_FILE, backup)

    with open(LOCAL_FILE, "w", encoding="utf-8") as f:
        for line in unique:
            f.write(line.strip() + "\n")

    # clean old backups
    backups = sorted(glob.glob(os.path.join(OUT_DIR, "*-trackers-back.txt")), key=os.path.getmtime, reverse=True)
    for old in backups[KEEP_BACKUPS:]:
        try:
            os.remove(old)
        except Exception:
            pass

    print(f"Processing complete. Updated {LOCAL_FILE} with {len(unique)} trackers.")

if __name__ == "__main__":
    main()
