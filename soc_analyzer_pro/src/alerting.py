from rich.console import Console
from rich.table import Table

console = Console()

def display_threat_report(findings):
    table = Table(title="[RED-TEAM] SOC Threat Analysis Report")
    table.add_column("Source IP", style="cyan")
    table.add_column("Risk Level", style="red")
    for ip, risk in findings.items():
        table.add_row(ip, risk)
    console.print(table)