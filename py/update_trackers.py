#!/usr/bin/env python3
"""
Robust tracker list normalizer for trackers/trackers-back.txt

Features:
- Fetch multiple remote sources + read local trackers-back.txt
- Remove comments and separators, split lines into tokens
- Robustly split concatenated trackers (a...announcehttp://b... and
  udp://http://wss://host/announce cases)
- Validate hosts (IPv4, IPv6, dotted domains, localhost, i2p)
- Preserve IPv6 with brackets in output, domain output without brackets
- Preserve /announce, /announce.php, /announce?passkey=..., /announce?authkey=..., /announce/<id>, .i2p/a, :port/a
- Append /announce only when suffix isn't already acceptable
- Remove default ports for http/https/ws/wss
- Deduplicate and sort
- Keep 3 most recent backups of trackers-back.txt
"""

from urllib.parse import urlparse, urlencode
import requests
import re
from ipaddress import IPv6Address, IPv4Address, AddressValueError
import os, time, glob, shutil

# === Config ===
URLS = [
    "http://github.itzmx.com/1265578519/OpenTracker/master/tracker.txt",
    "https://cf.trackerslist.com/all.txt",
    "https://cf.trackerslist.com/best.txt",
    "https://cf.trackerslist.com/http.txt",
    "https://cf.trackerslist.com/nohttp.txt",
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
    "https://trackerslist.com/http.txt",
]

LOCAL_FILE = "trackers/trackers-back.txt"
BACKUP_KEEP = 3

PROTOS = ("http", "https", "udp", "ws", "wss")
PROTO_RE = re.compile(r'(?:' + "|".join(PROTOS) + r')://', re.IGNORECASE)

# Default ports to remove
DEFAULT_PORTS = {'http': 80, 'https': 443, 'ws': 80, 'wss': 443}

# Suffix acceptance regex (if matches, do NOT append /announce)
SUFFIX_ACCEPT = re.compile(
    r'(/announce(\.php)?($|[/?])|'                          # /announce or /announce.php or /announce/...
    r'/announce\?(?:.*\b(passkey|authkey)=.+)|'             # /announce?passkey=... or /announce?authkey=...
    r'/announce/[^/]+$|'                                    # /announce/<id>
    r'\.i2p(:\d+)?/a$|/a$)',                                # .i2p/a or :port/a or /a
    flags=re.IGNORECASE
)

# Utilities

def fetch_all_sources(urls):
    parts = []
    for u in urls:
        try:
            r = requests.get(u, timeout=10)
            r.raise_for_status()
            parts.append(r.text)
        except Exception as e:
            print(f"Failed to fetch {u}: {e}")
    # read local if exists
    if os.path.exists(LOCAL_FILE):
        try:
            with open(LOCAL_FILE, "r", encoding="utf-8") as f:
                parts.append(f.read())
            print(f"Read local file: {LOCAL_FILE}")
        except Exception as e:
            print(f"Failed to read local file: {e}")
    return "\n".join(parts)

def tokenize_lines(text):
    """
    Remove comments (# ! ;) and split by common separators (comma, semicolon, whitespace)
    Return list of tokens (non-empty)
    """
    tokens = []
    for line in text.splitlines():
        # strip trailing comments
        line = re.split(r'[#!;]', line, 1)[0].strip()
        if not line:
            continue
        # split by commas/semicolons/whitespace but keep things like http://a,b as two tokens
        parts = [p.strip() for p in re.split(r'[,\s;]+', line) if p.strip()]
        tokens.extend(parts)
    return tokens

def normalize_proto_slashes(s):
    # Fix occurrences like http:/foo -> http://foo, but do not over-fix
    s = re.sub(r'(?i)\bhttp:/([^/])', r'http://\1', s)
    s = re.sub(r'(?i)\bhttps:/([^/])', r'https://\1', s)
    s = re.sub(r'(?i)\budp:/([^/])', r'udp://\1', s)
    s = re.sub(r'(?i)\bws:/([^/])', r'ws://\1', s)
    s = re.sub(r'(?i)\bwss:/([^/])', r'wss://\1', s)
    return s

def split_concatenated(s):
    """
    Return list of candidate tracker strings from input s.
    Strategy:
      - Find all full occurrences matching proto://... (up to separators or end) with regex.
      - If there is a leading chain of protocol-only prefixes like "udp://http://wss://host/..." then:
           take the last full match as suffix, and for each proto in the leading prefix generate proto + suffix.
      - Also include all full matches found.
    """
    s = s.strip()
    s = normalize_proto_slashes(s)

    # global full matches: proto://non-sep+
    full_matches = PROTO_RE.finditer(s)
    full_spans = []
    for m in full_matches:
        start = m.start()
        # capture to next protocol occurrence or to a separator/newline/end
        # We'll greedily match [^\s,;"']+ from start
        mm = re.match(r'(?:' + "|".join(PROTOS) + r')://[^\s,;"]+', s[start:], flags=re.IGNORECASE)
        if mm:
            full_spans.append((start, start + mm.end(), mm.group(0)))

    results = []
    # extract full-match substrings
    for (_, _, substr) in full_spans:
        results.append(substr)

    # If no full match found, return original token (after proto-sanitization)
    if not full_spans:
        return [s]

    # Check for leading protocol-only prefix before the first full match
    first_full_start = full_spans[0][0]
    prefix = s[:first_full_start]
    # find proto tokens in prefix (e.g. 'udp://http://wss://')
    prefix_protos = re.findall(r'(?:' + "|".join(PROTOS) + r')(?=://)', prefix, flags=re.IGNORECASE)
    if prefix_protos:
        # Use the last full match as suffix (the one that has host/path)
        last_full = full_spans[-1][2]
        # For each proto in prefix_protos produce proto:// + last_full without protocol
        # Need suffix part without its leading proto://
        suffix_no_proto = re.sub(r'^(?:' + "|".join(PROTOS) + r')://', '', last_full, flags=re.IGNORECASE)
        for p in prefix_protos:
            results.append(f"{p.lower()}://{suffix_no_proto}")

    # Also attempt to capture cases where two full matches are glued without separator
    # e.g. '...announcehttp://...' our earlier full_spans extraction handles that.
    # Remove duplicates while preserving order
    seen = set()
    ordered = []
    for r in results:
        if r not in seen:
            seen.add(r)
            ordered.append(r)
    return ordered

def build_url_from_parsed(parsed):
    """
    Reconstruct URL carefully to:
      - Keep IPv6 host bracketed
      - Preserve username/password if present
      - Include port if present
      - Preserve path, params, query, fragment
    Returns string
    """
    scheme = parsed.scheme.lower()
    host = parsed.hostname  # note: this returns without brackets
    if host is None:
        return None
    port = parsed.port
    username = parsed.username
    password = parsed.password
    # Determine if host is IPv6
    is_ipv6 = False
    try:
        IPv6Address(host)
        is_ipv6 = True
    except Exception:
        is_ipv6 = False

    if is_ipv6:
        host_part = f"[{host}]"
    else:
        host_part = host

    # add auth
    if username:
        auth = username
        if password:
            auth += f":{password}"
        hostpart = f"{auth}@{host_part}"
    else:
        hostpart = host_part

    if port:
        hostpart = f"{hostpart}:{port}"

    # Use path, params, query, fragment from parsed
    path = parsed.path or ""
    params = f";{parsed.params}" if parsed.params else ""
    query = f"?{parsed.query}" if parsed.query else ""
    frag = f"#{parsed.fragment}" if parsed.fragment else ""

    return f"{scheme}://{hostpart}{path}{params}{query}{frag}"

def host_is_valid(host):
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    # host might come with brackets or not. strip brackets for checking
    h = host
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    try:
        IPv4Address(h)
        return True
    except AddressValueError:
        pass
    try:
        IPv6Address(h)
        return True
    except AddressValueError:
        pass
    # dotted domain check (simple)
    if "." in h:
        return True
    return False

def append_announce_if_needed(url_str):
    # do not double append
    # parse path and query to see if suffix acceptable
    parsed = urlparse(url_str)
    path = parsed.path or ""
    q = parsed.query or ""
    combined = path
    if q:
        combined += "?" + q
    if SUFFIX_ACCEPT.search(combined):
        return url_str
    # append /announce (avoid double slashes)
    new_path = path
    if not new_path.endswith("/"):
        new_path = new_path + "/announce"
    else:
        # endswith '/' -> append announce
        new_path = new_path + "announce"
    # rebuild manually preserving query/fragment/auth
    # Build a new ParseResult-like by constructing string carefully
    # Keep username/password if any
    try:
        parsed2 = parsed._replace(path=new_path)
        return build_url_from_parsed(parsed2)
    except Exception:
        # fallback
        if url_str.endswith("/"):
            return url_str + "announce"
        else:
            return url_str + "/announce"

def remove_default_port(parsed):
    # Return parsed-like object or tuple that indicates new hostpart
    scheme = parsed.scheme.lower()
    port = parsed.port
    if port and scheme in DEFAULT_PORTS and DEFAULT_PORTS[scheme] == port:
        # create a new ParseResult by removing port from netloc
        host = parsed.hostname
        userinfo = ""
        if parsed.username:
            userinfo = parsed.username
            if parsed.password:
                userinfo += f":{parsed.password}"
            userinfo += "@"
        # ensure IPv6 bracket kept if needed
        host_part = host
        try:
            IPv6Address(host)
            host_part = f"[{host}]"
        except Exception:
            host_part = host
        new_netloc = userinfo + host_part
        # produce a reconstructed URL string
        pnew = parsed._replace(netloc=new_netloc)
        return pnew
    return parsed

# === Main processing ===

def main():
    print("Fetching sources...")
    combined = fetch_all_sources(URLS)
    print("Tokenizing...")
    tokens = tokenize_lines(combined)
    print(f"Initial tokens: {len(tokens)}")

    # Expand tokens by splitting concatenated cases
    expanded = []
    for t in tokens:
        parts = split_concatenated(t)
        for p in parts:
            if p and p.strip():
                expanded.append(p.strip())

    print(f"After concatenation-split: {len(expanded)}")

    # Normalize protocol slashes for safety
    expanded = [normalize_proto_slashes(x) for x in expanded]

    candidates = []
    for t in expanded:
        # strip trailing quotes etc
        t = t.strip(' \'"')
        # require it contains a proto somewhere, otherwise skip
        if not PROTO_RE.search(t):
            # maybe bare 'announce' lines or stray tokens -> ignore
            continue
        # find all full proto://host... matches inside token
        fulls = re.findall(r'(?:' + "|".join(PROTOS) + r')://[^\s,;"]+', t, flags=re.IGNORECASE)
        if fulls:
            for f in fulls:
                candidates.append(f)
        else:
            # maybe a weird token, keep original
            candidates.append(t)

    # Validate and normalize candidates
    normalized = []
    for c in candidates:
        try:
            parsed = urlparse(c)
            # require scheme and netloc
            if not parsed.scheme or not parsed.netloc:
                continue

            scheme = parsed.scheme.lower()
            if scheme not in PROTOS:
                continue

            # handle netloc that might be like "[domain]" or "domain00"
            host = parsed.hostname  # without brackets
            if host is None:
                # try to salvage: maybe netloc is like [domain] or raw ip with brackets
                # skip such malformed ones
                continue

            # host validation
            if not host_is_valid(host):
                continue

            # remove default port if present
            parsed2 = remove_default_port(parsed)

            # rebuild url carefully (keeps IPv6 brackets)
            url_out = build_url_from_parsed(parsed2)
            if not url_out:
                continue

            # suffix check and append if necessary
            url_out2 = append_announce_if_needed(url_out)
            normalized.append(url_out2)
        except Exception:
            continue

    # deduplicate and sort
    unique = sorted(set(normalized))

    # Backup old file
    os.makedirs(os.path.dirname(LOCAL_FILE), exist_ok=True)
    if os.path.exists(LOCAL_FILE):
        ts = time.strftime("%Y%m%d_%H%M%S")
        bak = os.path.join(os.path.dirname(LOCAL_FILE), f"{ts}-trackers-back.txt")
        shutil.copy(LOCAL_FILE, bak)
        print(f"Backup created: {bak}")

    # Write new file
    with open(LOCAL_FILE, "w", encoding="utf-8") as f:
        for u in unique:
            f.write(u + "\n")
    print(f"Processing complete. Updated {LOCAL_FILE} with {len(unique)} trackers.")

    # cleanup old backups
    backups = glob.glob(os.path.join(os.path.dirname(LOCAL_FILE), "*-trackers-back.txt"))
    backups.sort(key=os.path.getmtime, reverse=True)
    for old in backups[BACKUP_KEEP:]:
        try:
            os.remove(old)
        except Exception:
            pass

if __name__ == "__main__":
    main()
