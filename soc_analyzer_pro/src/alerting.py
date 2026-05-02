from rich.table import Table
from rich.console import Console

def display_threats(threat_map):
    console = Console()
    table = Table(title="SOC Analyzer - Active Threats")
    table.add_column("Source IP", style="cyan")
    table.add_column("Max Severity", style="bold red")
    
    for ip, severity in sorted(threat_map.items()):
        color = "red" if severity == "CRITICAL" else "orange3" if severity == "HIGH" else "green"
        table.add_row(ip, f"[{color}]{severity}[/]")
    
    console.print(table)