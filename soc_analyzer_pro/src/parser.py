import re
import ipaddress
from collections import Counter

def parse_web_logs(file_path: str, pattern_str: str = r'401 \(UNAUTHORIZED\)') -> Counter:
    ip_counter = Counter()
    ip_block_re = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):')
    status_re = re.compile(pattern_str)
    with open(file_path, 'r', buffering=1024*1024) as f:
        for line in f:
            ip_match = ip_block_re.match(line)
            if ip_match: current_ip = ip_match.group(1)
            if 'current_ip' in locals() and status_re.search(line):
                try: ip_counter[str(ipaddress.ip_address(current_ip))] += 1
                except: continue
    return ip_counter

def parse_firewall_logs(file_path: str) -> Counter:
    ip_counter = Counter()
    firewall_re = re.compile(r'(?:deny|drop|block).*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', re.IGNORECASE)
    with open(file_path, 'r', buffering=1024*1024) as f:
        for line in f:
            match = firewall_re.search(line)
            if match:
                try: ip_counter[str(ipaddress.ip_address(match.group(1)))] += 1
                except: continue
    return ip_counter