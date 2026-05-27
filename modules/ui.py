"""
User Interface Module
"""

import sys
import threading
from typing import Dict, Any, List
from datetime import datetime
from colorama import init, Fore, Style
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich.layout import Layout
from rich.align import Align

init(autoreset=True)

class ConsoleUI:
    def __init__(self):
        self.console = Console()

    def display_header(self):
        banner = r"""[bold red]
   ___ _     __                                _            _               _                    
  / __\ |__ / _\ ___  ___  /\  /\___  __ _  __| | ___ _ __ /_\  _ __   __ _| |_   _ _______ _ __ 
 / /  | '_ \\ \ / _ \/ __|/ /_/ / _ \/ _` |/ _` |/ _ \ '__//_\\| '_ \ / _` | | | | |_  / _ \ '__|
/ /___| | | |\ \  __/ (__/ __  /  __/ (_| | (_| |  __/ | /  _  \ | | | (_| | | |_| |/ /  __/ |   
\____/|_| |_\__/\___|\___\/ /_/ \___|\__,_|\__,_|\___|_| \_/ \_/_| |_|\__,_|_|\__, /___\___|_| [bold white] v2.0 [/bold white] 
                                                                              |___/              [/bold red]
                                   [bold white]Owned By [/][bold blue][[/] [bold red]Ch4120N[/] [bold blue]][/]
                                    [bold blue]GitHub.com/Ch4120N[/]"""
        print('-'*100)
        self.console.print(banner)
        print('-'*100, '\n\n')

    def print_info(self, message):
        self.console.print(f"[bold cyan][[/] [white]*[/] [bold cyan]][/] [white]{message}[/]")

    def print_success(self, message):
        self.console.print(f"[bold green][[/] [white]+[/] [bold green]][/] [bold green]{message}[/]")

    def print_warning(self, message):
        self.console.print(f"[yellow][[/] [white]![/] [yellow]][/] [yellow]{message}[/]")

    def print_error(self, message):
        self.console.print(f"[bold red][[/] [white]-[/] [bold red]][/] [bold red]{message}[/]")

    def display_results(self, analysis: Dict[str, Any]):
        self.console.print(f"\n[bold cyan]ANALYSIS RESULTS: {analysis['url']}[/]")
        grade_color = self._grade_style(analysis['grade'])
        self.console.print(f"Security Score: [bold]{analysis['security_score']}/100[/]")
        self.console.print(f"Security Grade: [{grade_color}]{analysis['grade']}[/]")
        self.console.print(f"Scan Date: {analysis['scan_date']}\n")

        # Show required headers dynamically from config
        # We'll use a simple list for display; for a config-driven approach, you could pass config
        required = ['Strict-Transport-Security','Content-Security-Policy','X-Frame-Options',
                    'X-Content-Type-Options','Referrer-Policy','Permissions-Policy']
        for h in required:
            present = h.lower() in analysis['headers_found']
            status = '[green]Present[/]' if present else '[red]Missing[/]'
            value = analysis['headers_found'].get(h.lower(), '')[:50] if present else ''
            self.console.print(f"  {h:<30} {status:<20} {value}")

        if analysis['vulnerabilities']:
            self.console.print("\n[bold]Vulnerabilities:[/]")
            for v in analysis['vulnerabilities']:
                if v['severity'] == 'info': continue   # skip pure info
                color = {'critical':'red','high':'bright_red','medium':'yellow','low':'white'}.get(v['severity'],'white')
                self.console.print(f"  [{color}][{v['severity'].upper()}][/] {v['description']}")
        else:
            self.console.print("\n[green]✓ No vulnerabilities[/]")

        if analysis['recommendations']:
            self.console.print("\n[bold]Recommendations:[/]")
            for i, rec in enumerate(analysis['recommendations'][:5], 1):
                self.console.print(f"  {i}. {rec}")
            if len(analysis['recommendations']) > 5:
                self.console.print(f"  ... and {len(analysis['recommendations'])-5} more")

        self.console.print("="*70)

    def print_progress(self, tracker):
        tracker.lock.acquire()
        try:
            percent = tracker.get_percentage()
            bar = '█' * int(30 * percent / 100) + '░' * (30 - int(30 * percent / 100))
            sys.stdout.write(f'\r[cyan][{bar}] {percent:.1f}% ({tracker.completed}/{tracker.total})')
            sys.stdout.flush()
        finally:
            tracker.lock.release()
        if tracker.completed == tracker.total:
            print()

    def _grade_style(self, grade: str) -> str:
        return {'A':'green','B':'cyan','C':'yellow','D':'red','F':'bright_red'}.get(grade, 'white')


class ProgressTracker:
    def __init__(self, total: int):
        self.total = total
        self.completed = 0
        self.lock = threading.Lock()
        self.start_time = datetime.now()

    def update(self, increment: int = 1):
        with self.lock:
            self.completed += increment

    def get_percentage(self) -> float:
        with self.lock:
            return (self.completed / self.total) * 100 if self.total > 0 else 0

    def get_elapsed_time(self) -> float:
        return (datetime.now() - self.start_time).total_seconds()