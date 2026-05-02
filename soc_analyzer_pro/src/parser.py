import re

def extract_log_data(line):
    # Improved regex to capture IP and the trailing port
    pattern = r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?\s(\d+)\s(?P<port>\d+)$'
    match = re.search(pattern, line.strip())
    if match:
        return match.group("ip"), int(match.group("port"))
    return None, None