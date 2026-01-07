"""
User Interface Module
"""

import sys
from typing import Dict, Any, List
from datetime import datetime
from colorama import init, Fore, Style, Back
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich.layout import Layout
from rich.align import Align
from rich.text import Text

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class ConsoleUI:
    def __init__(self):
        self.console = Console()
        self.colors = {
            'info': Fore.CYAN,
            'success': Fore.GREEN,
            'warning': Fore.YELLOW,
            'error': Fore.RED,
            'critical': Fore.RED + Style.BRIGHT,
            'header': Fore.BLUE + Style.BRIGHT,
            'url': Fore.MAGENTA
        }
    
    def display_header(self):
        """Display tool header"""
        centered_banner = Align.center(fr"""[bold red]
   ___ _     __                                _            _               _                    
  / __\ |__ / _\ ___  ___  /\  /\___  __ _  __| | ___ _ __ /_\  _ __   __ _| |_   _ _______ _ __ 
 / /  | '_ \\ \ / _ \/ __|/ /_/ / _ \/ _` |/ _` |/ _ \ '__//_\\| '_ \ / _` | | | | |_  / _ \ '__|
/ /___| | | |\ \  __/ (__/ __  /  __/ (_| | (_| |  __/ | /  _  \ | | | (_| | | |_| |/ /  __/ |   
\____/|_| |_\__/\___|\___\/ /_/ \___|\__,_|\__,_|\___|_| \_/ \_/_| |_|\__,_|_|\__, /___\___|_|   
                                                                              |___/              [/bold red]
        """)
        self.console.print(centered_banner)
        self.console.print("[bold white]Owned By [/][bold blue][[/] [bold red]Ch4120N[/] [bold blue]][/]", justify="center")
        self.console.print("[bold blue]GitHub.com/Ch4120N[/]", justify='center')
    
    def print_info(self, message: str):
        """Print informational message"""
        self.console.print(f"[bold cyan][[/] [bold white]*[/] [bold cyan]][/] [white]{message}[/]")
    
    def print_success(self, message: str):
        """Print success message"""
        self.console.print(f"[bold green][[/] [bold white]+[/] [bold green]][/] [bold green]{message}[/]")
    
    def print_warning(self, message: str):
        """Print warning message"""
        self.console.print(f"[yellow][[/] [bold white]![/] [yellow]][/] [yellow]{message}[/]")
    
    def print_error(self, message: str):
        """Print error message"""
        self.console.print(f"[bold red][[/] [bold white]-[/] [bold red]][/] [bold red]{message}[/]")
        
        # print(f"{self.colors['error']}[-] {message}", file=sys.stderr)
    
    def print_critical(self, message: str):
        """Print critical message"""
        self.console.print(f"[bold white][[/] [bold red]CRITICAL[/] [bold white]][/] [bold red]{message}[/]")
        
        # print(f"{self.colors['critical']}[CRITICAL] {message}", file=sys.stderr)
    
    def display_results(self, analysis: Dict[str, Any]):
        """Display analysis results in a formatted table"""
        print(f"\n{self.colors['header']}{'='*70}")
        print(f"ANALYSIS RESULTS: {analysis['url']}")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        # Summary
        grade_color = self._get_grade_color(analysis['grade'])
        print(f"{self.colors['info']}Security Score: {Style.BRIGHT}{analysis['security_score']}/100")
        print(f"{self.colors['info']}Security Grade: {grade_color}{Style.BRIGHT}{analysis['grade']}{Style.RESET_ALL}")
        print(f"{self.colors['info']}Scan Date: {analysis['scan_date']}\n")
        
        # Headers Summary
        print(f"{self.colors['header']}Headers Summary:{Style.RESET_ALL}")
        required_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 
                           'X-Frame-Options', 'X-Content-Type-Options', 
                           'Referrer-Policy', 'Permissions-Policy']
        
        for header in required_headers:
            header_lower = header.lower()
            if header_lower in analysis['headers_found']:
                status = f"{Fore.GREEN}✓ Present{Style.RESET_ALL}"
                value = analysis['headers_found'][header_lower][:50]
                if len(analysis['headers_found'][header_lower]) > 50:
                    value += "..."
            else:
                status = f"{Fore.RED}✗ Missing{Style.RESET_ALL}"
                value = ""
            
            print(f"  {header:30} {status:20} {value}")
        
        # Vulnerabilities
        if analysis['vulnerabilities']:
            print(f"\n{self.colors['header']}Vulnerabilities Found:{Style.RESET_ALL}")
            for vuln in analysis['vulnerabilities']:
                severity_color = self._get_severity_color(vuln['severity'])
                print(f"  {severity_color}[{vuln['severity'].upper()}] {vuln['description']}")
        else:
            print(f"\n{self.colors['success']}✓ No vulnerabilities found{Style.RESET_ALL}")
        
        # Recommendations
        if analysis['recommendations']:
            print(f"\n{self.colors['header']}Recommendations:{Style.RESET_ALL}")
            for i, rec in enumerate(analysis['recommendations'][:5], 1):
                print(f"  {i}. {rec}")
            if len(analysis['recommendations']) > 5:
                print(f"  ... and {len(analysis['recommendations']) - 5} more recommendations")
        
        print(f"\n{self.colors['header']}{'='*70}{Style.RESET_ALL}")
    
    def display_rich_results(self, analysis: Dict[str, Any]):
        """Display results using rich library for better formatting"""
        table = Table(title=f"Security Analysis: {analysis['url']}")
        
        table.add_column("Category", style="cyan", no_wrap=True)
        table.add_column("Status", style="magenta")
        table.add_column("Details", style="green")
        
        # Add rows
        table.add_row("Security Score", str(analysis['security_score']), 
                     self._get_score_rating(analysis['security_score']))
        table.add_row("Security Grade", analysis['grade'], 
                     self._get_grade_comment(analysis['grade']))
        
        # Headers
        headers_found = sum(1 for h in self._get_required_headers() 
                          if h.lower() in analysis['headers_found'])
        table.add_row("Headers Found", f"{headers_found}/6", 
                     f"{headers_found} of 6 required headers present")
        
        # Vulnerabilities
        vuln_count = len(analysis['vulnerabilities'])
        vuln_style = "red" if vuln_count > 0 else "green"
        table.add_row("Vulnerabilities", str(vuln_count), 
                     f"{vuln_count} issues found", style=vuln_style)
        
        self.console.print(table)
        
        # Detailed vulnerabilities
        if analysis['vulnerabilities']:
            vuln_table = Table(title="Vulnerabilities Details")
            vuln_table.add_column("Severity", style="bold")
            vuln_table.add_column("Type", style="cyan")
            vuln_table.add_column("Description")
            
            for vuln in analysis['vulnerabilities']:
                severity_color = {
                    'critical': 'red',
                    'high': 'bright_red',
                    'medium': 'yellow',
                    'low': 'white'
                }.get(vuln['severity'], 'white')
                
                vuln_table.add_row(
                    f"[{severity_color}]{vuln['severity'].upper()}[/{severity_color}]",
                    vuln['type'].replace('_', ' ').title(),
                    vuln['description']
                )
            
            self.console.print(vuln_table)
    
    def print_progress(self, progress_tracker):
        """Print progress information"""
        percent = progress_tracker.get_percentage()
        bar_length = 30
        filled_length = int(bar_length * percent / 100)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        
        sys.stdout.write(f'\r{self.colors["info"]}[{bar}] {percent:.1f}% '
                        f'({progress_tracker.completed}/{progress_tracker.total})')
        sys.stdout.flush()
        
        if progress_tracker.completed == progress_tracker.total:
            print()
    
    def _get_grade_color(self, grade: str) -> str:
        """Get color for grade"""
        colors = {
            'A': Fore.GREEN + Style.BRIGHT,
            'B': Fore.GREEN,
            'C': Fore.YELLOW,
            'D': Fore.RED,
            'F': Fore.RED + Style.BRIGHT
        }
        return colors.get(grade, Fore.WHITE)
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity"""
        colors = {
            'critical': Fore.RED + Style.BRIGHT,
            'high': Fore.RED,
            'medium': Fore.YELLOW,
            'low': Fore.WHITE
        }
        return colors.get(severity, Fore.WHITE)
    
    def _get_required_headers(self) -> List[str]:
        """Get list of required headers"""
        return ['Strict-Transport-Security', 'Content-Security-Policy', 
                'X-Frame-Options', 'X-Content-Type-Options', 
                'Referrer-Policy', 'Permissions-Policy']
    
    def _get_score_rating(self, score: int) -> str:
        """Get rating text for score"""
        if score >= 90:
            return "Excellent"
        elif score >= 80:
            return "Good"
        elif score >= 70:
            return "Fair"
        elif score >= 60:
            return "Poor"
        else:
            return "Critical"
    
    def _get_grade_comment(self, grade: str) -> str:
        """Get comment for grade"""
        comments = {
            'A': "Excellent security headers configuration",
            'B': "Good security headers, minor improvements possible",
            'C': "Average security, several improvements needed",
            'D': "Poor security, significant improvements required",
            'F': "Critical security issues, immediate action required"
        }
        return comments.get(grade, "Unknown grade")
    
class ProgressTracker:
    """Track progress of scans"""
    def __init__(self, total: int):
        self.total = total
        self.completed = 0
        self.start_time = datetime.now()
    
    def update(self, increment: int = 1):
        """Update completed count"""
        self.completed += increment
    
    def get_percentage(self) -> float:
        """Get completion percentage"""
        return (self.completed / self.total) * 100 if self.total > 0 else 0
    
    def get_elapsed_time(self) -> float:
        """Get elapsed time in seconds"""
        return (datetime.now() - self.start_time).total_seconds()
    
    def get_eta(self) -> float:
        """Get estimated time remaining"""
        if self.completed == 0:
            return 0
        elapsed = self.get_elapsed_time()
        return (elapsed / self.completed) * (self.total - self.completed)