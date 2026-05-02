from soc_analyzer_pro.src.parser import parse_log_line
from soc_analyzer_pro.src.alerting import display_threat_report
import os

def run_analysis():
    print("[SEC-OPS] Initializing Analysis Engine...")
    # Example logic
    sample_findings = {"185.15.59.224": "CRITICAL", "198.51.100.33": "HIGH"}
    display_threat_report(sample_findings)

if __name__ == '__main__':
    run_analysis()