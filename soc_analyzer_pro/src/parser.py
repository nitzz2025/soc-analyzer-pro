import re

def parse_log_line(line: str):
    """Extracts SRC, DST, and PORT from firewall logs."""
    pattern = r"SRC=(?P<src>[\d\.]+) DST=(?P<dst>[\d\.]+) PORT=(?P<port>\d+)"
    match = re.search(pattern, line)
    return match.groupdict() if match else None