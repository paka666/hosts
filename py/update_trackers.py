import requests
from urllib.parse import urlparse
import re
from ipaddress import IPv6Address, IPv4Address, AddressValueError
import os
import time
import glob
import shutil

# Constants
LOCAL_FILE = "trackers/trackers-back.txt"
BACKUP_KEEP = 3  # Keep recent 3 backups
TIMEOUT = 10  # Request timeout in seconds
DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
    "ws": 80,
    "wss": 443,
    "udp": None  # No default for UDP, but can add if needed
}
PROTOS = ["http", "https", "udp", "ws", "wss"]
PROTO_RE = re.compile(r'(?:' + "|".join(PROTOS) + r')://', re.IGNORECASE)
SUFFIX_ACCEPT = re.compile(
    r"(\.i2p(:\d+)?/a|/announce(\.php)?(\?(passkey|authkey)=[^?&]+(&[^?&]+)*)?|/announce(\.php)?/[^/]+)$",
    re.IGNORECASE
)

# URLs list
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

def fetch_all_sources(urls):
    contents = []
    for url in urls:
        try:
            r = requests.get(url, timeout=TIMEOUT)
            r.raise_for_status()
            contents.append(r.text)
        except Exception as e:
            print(f"Failed to fetch {url}: {e}")
    # Read local file if exists
    if os.path.exists(LOCAL_FILE):
        try:
            with open(LOCAL_FILE, "r", encoding="utf-8") as f:
                contents.append(f.read())
        except Exception as e:
            print(f"Failed to read {LOCAL_FILE}: {e}")
    return "\n".join(contents)

def tokenize_lines(text):
    lines = text.splitlines()
    tokens = []
    for line in lines:
        # Remove comments
        line = re.split(r"[#!;]", line)[0].strip()
        if not line:
            continue
        # Split by delimiters and strip
        parts = [p.strip() for p in re.split(r"[ ,;]", line) if p.strip()]
        tokens.extend(parts)
    return tokens

def normalize_proto_slashes(s):
    # Fix http:/ to http://, etc.
    for proto in PROTOS:
        s = re.sub(rf'^{proto}:/(?!/)', f'{proto}://', s, flags=re.IGNORECASE)
        s = re.sub(rf'^{proto}://+', f'{proto}://', s, flags=re.IGNORECASE)
    # Fix //announce to /announce
    s = re.sub(r'//announce', '/announce', s)
    # Fix /announce+108, /announce+, /announce"
    s = re.sub(r'/announce(\+\d*|\"|\+)?$', '/announce', s)
    return s

def split_concatenated(s):
    """
    Carefully split concatenated trackers without breaking valid ones.
    Handles leading protocols and full matches.
    """
    s = s.strip()
    s = normalize_proto_slashes(s)

    # Find all full proto://non-separator+ matches
    full_matches = PROTO_RE.finditer(s)
    full_spans = []
    for m in full_matches:
        start = m.start()
        # Greedily match until next separator or end
        mm = re.match(r'(?:' + "|".join(PROTOS) + r')://[^\s,;"]+', s[start:], flags=re.IGNORECASE)
        if mm:
            full_spans.append((start, start + mm.end(), mm.group(0)))

    results = []
    if not full_spans:
        return [s] if PROTO_RE.search(s) else []  # Only keep if has protocol

    # Extract full-match substrings
    for (_, _, substr) in full_spans:
        results.append(substr)

    # Handle leading protocol-only prefixes
    first_full_start = full_spans[0][0]
    prefix = s[:first_full_start]
    prefix_protos = re.findall(r'(?:' + "|".join(PROTOS) + r')(?=://)', prefix, flags=re.IGNORECASE)
    if prefix_protos:
        # Use the last full match's suffix (without protocol)
        last_full = full_spans[-1][2]
        suffix_no_proto = re.sub(r'^(?:' + "|".join(PROTOS) + r')://', '', last_full, flags=re.IGNORECASE)
        for p in prefix_protos:
            results.append(f"{p.lower()}://{suffix_no_proto}")

    # Deduplicate while preserving order
    seen = set()
    ordered = []
    for r in results:
        if r not in seen:
            seen.add(r)
            ordered.append(r)
    return ordered

def build_url_from_parsed(parsed):
    scheme = parsed.scheme.lower()
    host = parsed.hostname
    if host is None:
        return None
    port = parsed.port
    username = parsed.username
    password = parsed.password
    # Check if IPv6
    is_ipv6 = False
    try:
        IPv6Address(host)
        is_ipv6 = True
    except AddressValueError:
        pass

    host_part = f"[{host}]" if is_ipv6 else host

    # Add auth if present
    auth_part = ""
    if username:
        auth_part = username
        if password:
            auth_part += f":{password}"
        auth_part += "@"

    netloc = f"{auth_part}{host_part}"
    if port:
        netloc += f":{port}"

    path = parsed.path or ""
    params = f";{parsed.params}" if parsed.params else ""
    query = f"?{parsed.query}" if parsed.query else ""
    frag = f"#{parsed.fragment}" if parsed.fragment else ""

    return f"{scheme}://{netloc}{path}{params}{query}{frag}"

def is_valid_host(host):
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    # Strip brackets for check
    h = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        IPv6Address(h)
        return True
    except AddressValueError:
        pass
    try:
        IPv4Address(h)
        return True
    except AddressValueError:
        pass
    # For domains, require at least one dot (TLD check)
    if "." in h:
        return True
    return False

def append_announce_if_needed(url_str):
    parsed = urlparse(url_str)
    combined = parsed.path
    if parsed.query:
        combined += "?" + parsed.query
    if SUFFIX_ACCEPT.search(combined):
        return url_str
    new_path = parsed.path
    if not new_path or new_path == "/":
        new_path = "/announce"
    elif not new_path.endswith("/"):
        new_path += "/announce"
    else:
        new_path += "announce"
    return build_url_from_parsed(parsed._replace(path=new_path))

def remove_default_port(parsed):
    scheme = parsed.scheme.lower()
    port = parsed.port
    if port and scheme in DEFAULT_PORTS and port == DEFAULT_PORTS[scheme]:
        netloc = parsed.hostname
        if parsed.username:
            auth = parsed.username
            if parsed.password:
                auth += f":{parsed.password}"
            netloc = f"{auth}@{netloc}"
        # Preserve IPv6 brackets
        if ":" in netloc and not netloc.startswith("["):
            netloc = f"[{netloc}]"
        return parsed._replace(netloc=netloc)
    return parsed

def main():
    print("Fetching sources...")
    combined = fetch_all_sources(URLS)
    print("Tokenizing...")
    tokens = tokenize_lines(combined)
    print(f"Initial tokens: {len(tokens)}")

    # Expand concatenated
    expanded = []
    for t in tokens:
        parts = split_concatenated(t)
        expanded.extend([p.strip(' \'"') for p in parts if p.strip(' \'"') and PROTO_RE.search(p)])
    print(f"After split: {len(expanded)}")

    # Normalize and validate
    normalized = []
    for t in expanded:
        try:
            parsed = urlparse(t)
            if not parsed.scheme or not parsed.netloc:
                continue
            scheme = parsed.scheme.lower()
            if scheme not in PROTOS:
                continue
            host = parsed.hostname
            port = parsed.port
            # Fix concatenated port if no port
            if port is None:
                match = re.match(r"^(.+?)(\d+)$", parsed.netloc)
                if match:
                    base = match.group(1)
                    port_str = match.group(2)
                    if 1 <= int(port_str) <= 65535 and is_valid_host(base):
                        new_netloc = f"{base}:{port_str}"
                        parsed = parsed._replace(netloc=new_netloc)
                        host = urlparse(f"{scheme}://{new_netloc}").hostname
            # Remove brackets if not IPv6
            if host and host.startswith("[") and host.endswith("]"):
                inside = host[1:-1]
                try:
                    IPv6Address(inside)
                except AddressValueError:
                    # Not IPv6, remove brackets
                    new_netloc = inside
                    if parsed.port:
                        new_netloc += f":{parsed.port}"
                    if parsed.username:
                        auth = parsed.username + (f":{parsed.password}" if parsed.password else "")
                        new_netloc = f"{auth}@{new_netloc}"
                    parsed = parsed._replace(netloc=new_netloc)
                    host = parsed.hostname
            if not is_valid_host(host):
                continue
            # Remove default port
            parsed = remove_default_port(parsed)
            url_out = build_url_from_parsed(parsed)
            if not url_out:
                continue
            # Append /announce if needed
            url_out = append_announce_if_needed(url_out)
            normalized.append(url_out)
        except Exception as e:
            print(f"Error processing {t}: {e}")
            continue

    # Deduplicate and sort
    unique = sorted(set(normalized))
    print(f"Final unique trackers: {len(unique)}")

    # Backup and save
    os.makedirs(os.path.dirname(LOCAL_FILE), exist_ok=True)
    if os.path.exists(LOCAL_FILE):
        ts = time.strftime("%Y%m%d_%H%M%S")
        bak = os.path.join(os.path.dirname(LOCAL_FILE), f"{ts}-trackers-back.txt")
        shutil.copy(LOCAL_FILE, bak)
        print(f"Backup created: {bak}")

    with open(LOCAL_FILE, "w", encoding="utf-8") as f:
        for u in unique:
            f.write(u + "\n")

    # Clean old backups
    backups = glob.glob(os.path.join(os.path.dirname(LOCAL_FILE), "*-trackers-back.txt"))
    backups.sort(key=os.path.getmtime, reverse=True)
    for old in backups[BACKUP_KEEP:]:
        try:
            os.remove(old)
        except Exception as e:
            print(f"Failed to remove old backup {old}: {e}")

    print(f"Updated {LOCAL_FILE} with {len(unique)} trackers.")

if __name__ == "__main__":
    # Add a short delay for "thinking time" (simulates processing pause, optional for GitHub actions)
    time.sleep(2)
    main()
