import asyncio
import os
import ipaddress
import aiohttp
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.prompt import Prompt

# Internal Module Imports
from src.utils import validate_path, get_ip_context_async, export_to_csv
from src.parser import parse_web_logs, parse_firewall_logs
from src.alerting import send_webhook_alert

console = Console()

async def enrich_ip(session, ip, sem, token, progress, task_id, locations_dict):
    loc = await get_ip_context_async(session, ip, sem, token)
    locations_dict[ip] = loc
    progress.advance(task_id)

async def main():
    load_dotenv()
    token = os.getenv('IPINFO_TOKEN')

    while True:
        # Welcome Banner
        console.print(Panel(
            "[bold blue]ESLA-PRO v3.1: Enterprise SOC Threat Analyzer[/bold blue]\n"
            "[italic]Continuous Monitoring & Forensic Intelligence Engine[/italic]",
            expand=False
        ))

        # --- Step 1: Engine Selection ---
        console.print("\n[bold cyan]--- Step 1: Select Analysis Engine ---[/bold cyan]")
        console.print("[bold]1. Web Access Logs:[/bold] HTTP 401 Unauthorized anomalies.")
        console.print("[bold]2. Firewall Logs:[/bold] DROP/DENY event analysis.")
        console.print("[bold]3. Exit Dashboard[/bold]")

        log_type = Prompt.ask("Select Option", choices=["1", "2", "3"], default="1")

        if log_type == "3":
            console.print("\n[bold blue]Exiting ESLA-PRO Dashboard. Stay Secure.[/bold blue]")
            break

        engine_label = "Web (401 Anomalies)" if log_type == "1" else "Firewall (DROP/DENY)"
        default_path = "/content/web_activity.log" if log_type == "1" else "/content/sample_firewall.log"

        # --- Step 2: Data Ingestion ---
        console.print("\n[bold cyan]--- Step 2: Data Ingestion ---[/bold cyan]")
        log_path_input = Prompt.ask("Enter target log path", default=default_path)

        # Pre-flight Path & Existence Validation
        try:
            safe_path = validate_path(log_path_input)
            if not os.path.isfile(safe_path):
                console.print(f"\n[bold red]FATAL ERROR:[/bold red] File not found at {safe_path}. Please verify the path.")
                continue
        except Exception as e:
            console.print(f"[bold red]Security Violation:[/bold red] {e}")
            continue

        # --- Step 3: Alerting Configuration ---
        webhook_url = Prompt.ask("\nEnter Webhook URL (optional)", default="")

        # Processing Engine
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            transient=True
        ) as progress:

            task1 = progress.add_task(f"[cyan]Scanning for {engine_label} threats...", total=None)
            if log_type == "1":
                results = parse_web_logs(str(safe_path))
            else:
                results = parse_firewall_logs(str(safe_path))
            progress.update(task1, completed=100)

            if not results:
                console.print("[bold yellow]Zero threats detected in scope.[/bold yellow]")
                continue

            # Enrichment Engine
            top_ips = results.most_common(20)
            locations = {}
            semaphore = asyncio.Semaphore(50)
            task2 = progress.add_task("[magenta]Enriching Geo-Intelligence...", total=len(top_ips))

            async with aiohttp.ClientSession() as session:
                tasks = []
                for ip, _ in top_ips:
                    if ipaddress.ip_address(ip).is_private:
                        locations[ip] = "Internal (RFC1918)"
                        progress.advance(task2)
                    else:
                        tasks.append(enrich_ip(session, ip, semaphore, token, progress, task2, locations))

                if tasks:
                    try:
                        await asyncio.wait_for(asyncio.gather(*tasks), timeout=10.0)
                    except Exception as e:
                        console.print(f"\n[bold red]Enrichment Engine Latency: {e}[/bold red]")

                if webhook_url:
                    alert_payload = {"text": f"🚨 ESLA-PRO Alert: {len(top_ips)} threats found in {engine_label} logs."}
                    await send_webhook_alert(webhook_url, alert_payload)

        # Forensic Reporting UI
        table = Table(title=f"[bold red]ESLA-PRO Forensic Evidence: {engine_label}[/bold red]", box=None)
        table.add_column("Rank", justify="right", style="dim")
        table.add_column("IP Address", style="bold red")
        table.add_column("Attempts", justify="center", style="bold")
        table.add_column("Location", style="green")

        for i, (ip, count) in enumerate(top_ips, 1):
            table.add_row(str(i), ip, str(count), locations.get(ip, "Unknown"))

        console.print(table)

        if Prompt.ask("Export forensic report to CSV?", choices=["y", "n"], default="y") == "y":
            report_file = export_to_csv(dict(top_ips), locations)
            console.print(f"[bold green]Exported successfully:[/bold green] {report_file}")

        console.print("\n[dim]Returning to main menu...[/dim]")

if __name__ == '__main__':
    asyncio.run(main())