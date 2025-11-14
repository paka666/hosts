#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Robust tracker normalizer (A-F requirements implemented).
Writes trackers/trackers-back.txt and keeps recent 3 backups.
"""
from urllib.parse import urlparse, urlunparse, ParseResult
import re
import os
import time
import glob
import shutil
import requests

# --- CONFIG ---
# If you want remote fetching, add/remove sources in URLS and enable network fetch in fetch_sources()
URLS = [
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

LOCAL_FILE = "trackers/trackers-back.txt"
OUT_DIR = os.path.dirname(LOCAL_FILE) or "trackers"
KEEP_BACKUPS = 3

PROTOS = ("http", "https", "udp", "ws", "wss")
PROTO_RE = re.compile(r'(?:' + "|".join(PROTOS) + r')://', re.IGNORECASE)
# Recognize protocol occurrences to split glued URLs
PROTOCOL_OCCURRENCE_RE = re.compile(r'(https?|udp|wss?|ws)://', re.IGNORECASE)

# Suffix acceptance: if matches, do NOT append /announce
SUFFIX_ACCEPT = re.compile(
    r'(/announce(\.php)?($|[/?])|'                 # /announce or /announce.php or /announce/...
    r'/announce\?(?:.*\b(passkey|authkey)=.+)|'    # /announce?passkey=... or /announce?authkey=...
    r'/announce/[^/]+$|'                           # /announce/<id>
    r'\.i2p(:\d+)?/a$|/a$)',                       # .i2p/a or :port/a or /a
    re.IGNORECASE
)

# Default ports to remove precisely
DEFAULT_PORTS = {'http': 80, 'https': 443, 'ws': 80, 'wss': 443}

# SIMPLE utils

def read_local(path):
    if not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def fetch_sources():
    """
    Return combined text from sources.
    By default we include local file (works offline/CI). If you want remote fetch,
    uncomment the requests loop below.
    """
    parts = []
    # Optional: fetch remote lists (uncomment if environment has network)
    for url in URLS:
        try:
            r = requests.get(url, timeout=10)
            r.raise_for_status()
            parts.append(r.text)
        except Exception:
            # fail silently for remote sources; local file still used
            continue
    # local
    parts.append(read_local(LOCAL_FILE))
    return "\n".join(parts)

# Cleaning and splitting tokens

def remove_comments_and_split(text):
    """
    Remove inline comments (# ; !) and split lines by comma/semicolon/whitespace.
    Return list of tokens.
    """
    tokens = []
    for raw in text.splitlines():
        line = re.split(r'[#!;]', raw, 1)[0].strip()
        if not line:
            continue
        # normalize full-width punctuation often found in mixed lists
        line = line.replace("，", ",").replace("；", ";")
        parts = [p.strip() for p in re.split(r'[,;\s]+', line) if p.strip()]
        tokens.extend(parts)
    return tokens

def normalize_proto_slashes(s: str) -> str:
    # fix accidental single-slash forms: http:/host -> http://host, etc.
    s = re.sub(r'(?i)\bhttp:/([^/])', r'http://\1', s)
    s = re.sub(r'(?i)\bhttps:/([^/])', r'https://\1', s)
    s = re.sub(r'(?i)\budp:/([^/])', r'udp://\1', s)
    s = re.sub(r'(?i)\bws:/([^/])', r'ws://\1', s)
    s = re.sub(r'(?i)\bwss:/([^/])', r'wss://\1', s)
    return s

def split_concatenated(token: str):
    """
    Handle two classes:
      - leading chained protocols: udp://http://wss://host/... => produce one tracker per protocol with same suffix
      - glued-internal URLs: ...announcehttp://other... => split by protocol occurrences
    Return list of candidate URL strings (trimmed).
    """
    s = token.strip()
    if not s:
        return []
    s = normalize_proto_slashes(s)

    # find full proto://... fragments
    fulls = re.findall(r'(?:' + "|".join(PROTOS) + r')://[^\s,;"]+', s, flags=re.IGNORECASE)
    results = []
    if fulls:
        results.extend(fulls)

    # detect leading chained protocols (e.g., udp://http://wss://suffix)
    m = re.match(r'^((?:https?|udp|ws|wss)://?)+(.+)$', token, re.IGNORECASE)
    if m:
        protos_part = m.group(1)
        suffix = m.group(2)
        seq = re.findall(r'(https?|udp|ws|wss)', protos_part, re.IGNORECASE)
        seen = set()
        for p in seq:
            pl = p.lower()
            if pl not in seen:
                seen.add(pl)
                # ensure suffix not prefixed with an extra proto
                suffix2 = re.sub(r'^(?:' + "|".join(PROTOS) + r')://', '', suffix, flags=re.IGNORECASE)
                results.append(f'{pl}://{suffix2}')

    # if nothing found, keep original
    if not results:
        return [s]
    # dedupe keeping order
    seen = set()
    out = []
    for r in results:
        r2 = r.strip()
        if r2 and r2 not in seen:
            seen.add(r2)
            out.append(r2)
    return out

# URL reconstruction helpers

def host_is_valid(host: str) -> bool:
    """Accepts IPv4, IPv6, localhost, or any host containing a dot (covers tracker.i2p, .local, etc.)."""
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    h = host
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    # IPv4 quick check
    try:
        parts = h.split(".")
        if len(parts) == 4 and all(0 <= int(p) < 256 for p in parts):
            return True
    except Exception:
        pass
    # IPv6
    try:
        import ipaddress
        ipaddress.IPv6Address(h)
        return True
    except Exception:
        pass
    # dotted domain
    if "." in h:
        return True
    return False

def build_url_from_parsed(parsed):
    """
    Rebuild URL preserving:
     - IPv6 with brackets in output
     - username:password@
     - port if present
     - path, query, fragment
    """
    scheme = parsed.scheme.lower()
    host = parsed.hostname
    if not host:
        return None
    port = parsed.port
    user = parsed.username
    pwd = parsed.password
    # bracket IPv6 for display
    try:
        from ipaddress import IPv6Address
        IPv6Address(host)
        host_part = f'[{host}]'
    except Exception:
        host_part = host
    auth = ""
    if user:
        auth = user
        if pwd:
            auth += f":{pwd}"
        auth += "@"
    netloc = auth + host_part
    if port:
        netloc += f":{port}"
    path = parsed.path or ""
    params = f";{parsed.params}" if parsed.params else ""
    query = f"?{parsed.query}" if parsed.query else ""
    frag = f"#{parsed.fragment}" if parsed.fragment else ""
    return f"{scheme}://{netloc}{path}{params}{query}{frag}"

def remove_default_port(parsed):
    """Return a ParseResult-like object with default port removed for http/ws and https/wss."""
    scheme = parsed.scheme.lower()
    port = parsed.port
    if port and scheme in DEFAULT_PORTS and DEFAULT_PORTS[scheme] == port:
        # rebuild netloc without port but keep auth and bracketed host if needed
        host = parsed.hostname
        user = parsed.username
        pwd = parsed.password
        try:
            from ipaddress import IPv6Address
            IPv6Address(host)
            host_part = f'[{host}]'
        except Exception:
            host_part = host or ""
        auth = ""
        if user:
            auth = user
            if pwd:
                auth += f":{pwd}"
            auth += "@"
        new_netloc = auth + host_part
        return parsed._replace(netloc=new_netloc)
    return parsed

def must_append_announce(url_str):
    """Return URL string, appending /announce if suffix not acceptable."""
    parsed = urlparse(url_str)
    path = parsed.path or ""
    q = parsed.query or ""
    combined = path + ("?" + q if q else "")
    if SUFFIX_ACCEPT.search(combined):
        return url_str
    # append /announce carefully
    if path.endswith("/"):
        new_path = path + "announce"
    elif path == "":
        new_path = "/announce"
    else:
        new_path = path + "/announce"
    p2 = parsed._replace(path=new_path)
    out = build_url_from_parsed(remove_default_port(p2))
    return out or url_str + ("/announce" if not url_str.endswith("/") else "announce")

# Main pipeline

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    text = fetch_sources()
    tokens = remove_comments_and_split(text)

    # Step A: expand concatenated tokens
    expanded = []
    for t in tokens:
        # skip pure suffix tokens
        if t in ("/announce", "/announce.php", "/announce/"):
            continue
        parts = split_concatenated(t)
        for p in parts:
            if p and p.strip():
                expanded.append(p.strip())

    # normalize protocol stray slashes
    expanded = [normalize_proto_slashes(x) for x in expanded]

    # extract all full proto://... fragments in expanded tokens
    candidates = []
    for t in expanded:
        # skip trivial garbage
        if not PROTO_RE.search(t):
            continue
        found = re.findall(r'(?:' + "|".join(PROTOS) + r')://[^\s,;"]+', t, flags=re.IGNORECASE)
        if found:
            candidates.extend(found)
        else:
            candidates.append(t)

    # Validate, normalize and rebuild
    normalized = []
    for c in candidates:
        # strip quotes and trailing punctuation
        c = c.strip(" '\"")
        parsed = urlparse(c)
        if not parsed.scheme or not parsed.netloc:
            continue
        scheme = parsed.scheme.lower()
        if scheme not in PROTOS:
            continue
        # hostname (urlparse gives hostname without brackets)
        host = parsed.hostname
        if not host:
            # salvage netloc (remove userinfo)
            nl = parsed.netloc
            if "@" in nl:
                nl = nl.split("@", 1)[1]
            # remove trailing :port if single colon
            if ":" in nl and nl.count(":") == 1:
                host = nl.split(":", 1)[0]
            else:
                host = nl
        if not host_is_valid(host):
            continue
        # remove default ports if present
        parsed2 = remove_default_port(parsed)
        # rebuild preserving IPv6 brackets
        out = build_url_from_parsed(parsed2)
        if not out:
            continue
        # fix doubled // in path
        out = re.sub(r'//+', '/', out.replace(':/', '::TEMP::')).replace('::TEMP::', ':/')
        # append announce if needed
        out = must_append_announce(out)
        # final sanitize: remove any stray quotes
        normalized.append(out.strip(" '\""))

    # dedupe and sort
    unique = sorted(dict.fromkeys(normalized))

    # Backup existing local file
    if os.path.exists(LOCAL_FILE):
        ts = time.strftime("%Y%m%d_%H%M%S")
        bak = os.path.join(OUT_DIR, f"{ts}-trackers-back.txt")
        shutil.copy(LOCAL_FILE, bak)
    # write
    with open(LOCAL_FILE, "w", encoding="utf-8") as f:
        for u in unique:
            f.write(u + "\n")

    # cleanup old backups
    backups = sorted(glob.glob(os.path.join(OUT_DIR, "*-trackers-back.txt")), key=os.path.getmtime, reverse=True)
    for old in backups[KEEP_BACKUPS:]:
        try:
            os.remove(old)
        except Exception:
            pass

    print(f"Processing complete. Updated {LOCAL_FILE} with {len(unique)} trackers.")

if __name__ == "__main__":
    main()
