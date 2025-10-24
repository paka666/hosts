import re
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network, AddressValueError, NetmaskValueError

# IPv4 pattern
ipv4_pattern = r'((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'

# IPv6 pattern
ipv6_addr = r'(?:(([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))'

# Preprocess the file
lines = []
with open('mixed_rules.txt', 'r', encoding='utf-8') as f:
    for raw_line in f:
        # Strip leading/trailing whitespace
        line = raw_line.strip()
        if not line or line.startswith(('#', '!')):
            continue
        # Remove inline comments
        line = re.split(r'[#!]', line)[0].strip()
        if not line:
            continue
        # Remove all inline whitespaces
        line = ''.join(line.split())
        lines.append(line)

# Re-remove any remaining comment lines
lines = [l for l in lines if l and not l.startswith(('#', '!'))]

# Deduplicate and sort
lines = sorted(set(lines))

# Extract to lists
v4_list = []
v6_list = []
domain_list = []

for line in lines:
    added = False
    # Check if pure IPv4/IPv4 CIDR
    try:
        if '/' in line:
            net = IPv4Network(line, strict=True)
            if str(net) == line:
                v4_list.append(line)
                added = True
        else:
            addr = IPv4Address(line)
            if str(addr) == line:
                v4_list.append(line)
                added = True
    except (AddressValueError, NetmaskValueError, ValueError):
        pass

    if added:
        continue

    # Check if pure IPv6/IPv6 CIDR
    try:
        if '/' in line:
            net = IPv6Network(line, strict=True)
            if str(net) == line:
                v6_list.append(line)
                added = True
        else:
            addr = IPv6Address(line)
            if str(addr) == line:
                v6_list.append(line)
                added = True
    except (AddressValueError, NetmaskValueError, ValueError):
        pass

    if added:
        continue

    # Handle non-pure lines
    is_http = line.startswith('http://') or line.startswith('https://')
    if is_http:
        scheme_len = 7 if line.startswith('http://') else 8
        sub_line = line[scheme_len:]
    else:
        sub_line = line
        scheme_len = 0

    # Search for IPv4 in non-pure lines (anchored at start of sub_line)
    match = re.match(ipv4_pattern, sub_line)
    if match:
        ip = match.group(1)
        try:
            IPv4Address(ip)
            next_index = scheme_len + match.end()
            if next_index == len(line) or line[next_index] in '/:':
                v4_list.append(ip)
                added = True
        except (AddressValueError, ValueError):
            pass

    if added:
        continue

    # Search for IPv6 in non-pure lines (anchored at start of sub_line, handles optional [])
    match = re.match(r'\[?(' + ipv6_addr + r')\]?', sub_line, re.IGNORECASE)
    if match:
        ip = match.group(1)
        try:
            IPv6Address(ip)
            next_index = scheme_len + match.end()
            if next_index == len(line) or line[next_index] in '/:':
                v6_list.append(ip)
                added = True
        except (AddressValueError, ValueError):
            pass

    if not added:
        domain_list.append(line)

# Deduplicate and sort the output lists
v4_list = sorted(set(v4_list))
v6_list = sorted(set(v6_list))
domain_list = sorted(set(domain_list))

# Write to output files
with open('v4.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(v4_list) + '\n')

with open('v6.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(v6_list) + '\n')

with open('domain.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(domain_list) + '\n')

print("Processing complete. Outputs: v4.txt, v6.txt, domain.txt")
