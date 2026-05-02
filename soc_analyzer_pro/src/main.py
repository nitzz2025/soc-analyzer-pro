import os
from rich.prompt import Prompt
from soc_analyzer_pro.src.parser import extract_log_data
from soc_analyzer_pro.src.alerting import display_threats

def run_analyzer():
    log_path = Prompt.ask("Enter path to log file")
    if not os.path.exists(log_path):
        print(f"Error: File {log_path} not found.")
        return

    threats = {} # IP -> Severity
    severity_scores = {"LOW": 1, "HIGH": 2, "CRITICAL": 3}

    with open(log_path, 'r', encoding='utf-8') as f:
        for line in f:
            ip, port = extract_log_data(line)
            if not ip: continue

            # Severity Logic
            current_sev = "LOW"
            if port == 22:
                current_sev = "CRITICAL"
            elif port == 443:
                current_sev = "HIGH"

            # Vulnerability Patch: Threats can only escalate
            existing_sev = threats.get(ip, "LOW")
            if severity_scores[current_sev] > severity_scores[existing_sev]:
                threats[ip] = current_sev
            elif ip not in threats:
                threats[ip] = current_sev

    display_threats(threats)

if __name__ == "__main__":
    try:
        run_analyzer()
    except KeyboardInterrupt:
        print("\nExiting gracefully...")