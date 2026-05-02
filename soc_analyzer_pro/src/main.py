import sys
import os
from rich.prompt import Prompt
from rich.console import Console
from soc_analyzer_pro.src.parser import parse_log_line
from soc_analyzer_pro.src.alerting import display_threat_report

console = Console()

def run_interactive_analysis():
    console.print("[bold green]SOC Analyzer Pro v3.1.0 - Interactive Mode[/bold green]")
    
    # Interactivity
    log_path = Prompt.ask("[bold cyan]Enter target log file for analysis[/bold cyan]", default="logs/sample_firewall.log")
    
    # Validation
    if not os.path.exists(log_path):
        console.print(f"[bold red]ERROR:[/bold red] File not found: {log_path}")
        sys.exit(1)

    findings = {}

    # Parsing Engine
    with open(log_path, 'r') as f:
        for line in f:
            data = parse_log_line(line)
            if data and 'src' in data and 'port' in data:
                ip = data['src']
                port = data['port']
                
                # Threat Logic
                if port == "22":
                    findings[ip] = "CRITICAL (SSH Brute Force)"
                elif port == "443":
                    findings[ip] = "HIGH (Suspicious HTTPS)"
                else:
                    if ip not in findings:
                        findings[ip] = "INFO (Activity Detected)"

    # Reporting
    if findings:
        display_threat_report(findings)
    else:
        console.print("[yellow]No threats detected in the provided log file.[/yellow]")

if __name__ == '__main__':
    run_interactive_analysis()