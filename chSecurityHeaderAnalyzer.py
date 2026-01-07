#!/usr/bin/env python3

#  ____  _____  _    _  ____  ____  ____  ____     ____  _  _     ___  _   _  __  __  ___   ___  _  _ 
# (  _ \(  _  )( \/\/ )( ___)(  _ \( ___)(  _ \   (  _ \( \/ )   / __)( )_( )/. |/  )(__ \ / _ \( \( )
#  )___/ )(_)(  )    (  )__)  )   / )__)  )(_) )   ) _ < \  /   ( (__  ) _ ((_  _))(  / _/( (_) ))  ( 
# (__)  (_____)(__/\__)(____)(_)\_)(____)(____/   (____/ (__)    \___)(_) (_) (_)(__)(____)\___/(_)\_)
# 

# Project   : ChSecurityHeaderAnalyzer - Comprehensive Security Header Analysis Tool
# Owner     : Ch4120N
# Version   : 1.0.0
# Repo URL  : https://github.com/Ch4120N/ChSecurityHeaderAnalyzer

import argparse
import sys
import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
from datetime import datetime

try:
    import requests
    import pandas
    import jinja2
    import colorama
    import rich
    import yaml
except ImportError:
    sys.exit(
        '[ - ] Please install missing modules with following command:\n\n'
        '\t - python -m pip install -r requirements.txt'
        )



from modules.scanner import SecurityScanner
from modules.analyzer import HeaderAnalyzer
from modules.reporter import ReportGenerator
from modules.ui import ConsoleUI, ProgressTracker
from modules.utils import setup_logging, load_config, validate_url



class ChSecurityHeaderAnalyzer:
    def __init__(self):
        self.config = load_config()
        self.logger = setup_logging()
        self.scanner = SecurityScanner(self.config)
        self.analyzer = HeaderAnalyzer(self.config)
        self.reporter = ReportGenerator(self.config)
        self.ui = ConsoleUI()
    
    def run(self):
        parser = argparse.ArgumentParser(
            description=(
                "ChSecurityHeaderAnalyzer - Comprehensive Security Header Analysis Tool\n"
                "Owned By: @Ch4120N\n"
                "GitHub Repo: https://github.com/Ch4120N/ChSecurityHeaderAnalyzer"
            ),
            formatter_class=argparse.RawTextHelpFormatter,
            epilog=(
                "Examples:\n"
                "  %(prog)s https://example.com\n"
                "  %(prog)s -u https://example.com -o json csv\n"
                "  %(prog)s -f urls.txt -t 20 -o all\n"
                "  %(prog)s -u https://example.com --no-verify --timeout 30\n"
                "  %(prog)s -b -f urls.txt -o html --output-dir ./reports\n"
            ))
        
        # Input options
        input_group = parser.add_mutually_exclusive_group(required=True)
        input_group.add_argument('-u', '--url', help='Single URL to analyze')
        input_group.add_argument('-f', '--file', help='File containing URLs (one per line)')
        input_group.add_argument('--bulk', action='store_true', help='Treat URL argument as comma-separated list')
        
        # Output options
        parser.add_argument('-o', '--output', nargs='+', 
                        choices=['txt', 'json', 'csv', 'html', 'all'],
                        default=['txt'],
                        help='Output format(s)')
        parser.add_argument('--output-dir', help='Custom output directory')
        parser.add_argument('--no-report', action='store_true', 
                        help='Don\'t save reports, only display results')
        
        # Scan options
        parser.add_argument('-t', '--threads', type=int, help='Number of threads for bulk scan')
        parser.add_argument('--timeout', type=int, help='Request timeout in seconds')
        parser.add_argument('--no-verify', action='store_true', 
                        help='Disable SSL certificate verification')
        parser.add_argument('--no-redirect', action='store_true',
                        help='Disable following redirects')
        parser.add_argument('--user-agent', help='Custom User-Agent string')
        
        # Display options
        parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')
        parser.add_argument('-q', '--quiet', action='store_true',
                        help='Quiet mode (minimal output)')
        parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
        
        # Other options
        parser.add_argument('--version', action='version', 
                        version='ChSecurityHeaderAnalyzer 1.0.0')
        
        args = parser.parse_args()

        output_formats = None if args.no_report else args.output

        if 'all' in output_formats:
            output_formats = ['txt', 'json', 'csv', 'html']
        
        # Process based on input type
        if args.url:
            if args.bulk:
                urls = [url.strip() for url in args.url.split(',')]
                self.analyze_multiple(urls, output_formats, args.output_dir, args.threads)
            else:
                self.analyze_single(args.url, output_formats)
        
        elif args.file:
            self.analyze_from_file(args.file, output_formats, args.output_dir, args.threads)
        
        self.ui.print_success("Analysis completed!")

    def analyze_single(self, url: str, output_formats: List[str] = None) -> Dict[str, Any]:
        """Analyze a single website"""
        self.ui.display_header()
        
        if not validate_url(url):
            self.ui.print_error(f"Invalid URL: {url}")
            return None
            
        try:
            # Scan headers
            self.ui.print_info(f"Scanning: {url}")
            headers = self.scanner.scan_url(url)
            
            if not headers:
                self.ui.print_error(f"No headers found for {url}")
                return None
            
            # Analyze headers
            self.ui.print_info("Analyzing security headers...")
            analysis = self.analyzer.analyze_headers(headers, url)
            
            # Display results
            self.ui.display_results(analysis)
            
            # Generate reports
            if output_formats:
                report_paths = self.reporter.generate_reports(analysis, url, output_formats)
                for format, path in report_paths.items():
                    self.ui.print_success(f"{format.upper()} report saved: {path}")
            
            return analysis
            
        except Exception as e:
            self.ui.print_error(f"Error analyzing {url}: {str(e)}")
            self.logger.error(f"Error analyzing {url}", exc_info=True)
            return None
    

    def analyze_multiple(self, urls: List[str], output_formats: List[str] = None, 
                        output_dir: str = None, threads: int = None) -> List[Dict[str, Any]]:
        """Analyze multiple websites with multithreading"""
        self.ui.display_header()
        
        # Filter valid URLs
        valid_urls = [url for url in urls if validate_url(url)]
        invalid_urls = set(urls) - set(valid_urls)
        
        if invalid_urls:
            self.ui.print_warning(f"Skipped {len(invalid_urls)} invalid URLs")
            for url in invalid_urls:
                self.ui.print_warning(f"  Invalid: {url}")
        
        if not valid_urls:
            self.ui.print_error("No valid URLs to analyze")
            return []
        
        self.ui.print_info(f"Analyzing {len(valid_urls)} URLs with {threads or self.config['scanner']['thread_count']} threads")
        
        results = []
        progress = ProgressTracker(total=len(valid_urls))
        
        # Thread pool for parallel scanning
        thread_count = threads or self.config['scanner']['thread_count']
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            # Submit all tasks
            future_to_url = {
                executor.submit(self._analyze_single_worker, url, output_formats): url 
                for url in valid_urls
            }
            
            # Process results as they complete
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    self.ui.print_error(f"Error processing {url}: {str(e)}")
                
                progress.update()
                self.ui.print_progress(progress)
        
        # Generate combined report if multiple URLs
        if len(results) > 1 and output_formats:
            self.ui.print_info("Generating combined report...")
            combined_paths = self.reporter.generate_combined_report(results, output_formats, output_dir)
            for format, path in combined_paths.items():
                self.ui.print_success(f"Combined {format.upper()} report saved: {path}")
        
        return results
    

    def _analyze_single_worker(self, url: str, output_formats: List[str] = None) -> Dict[str, Any]:
        """Worker function for multithreaded analysis"""
        try:
            headers = self.scanner.scan_url(url)
            if headers:
                analysis = self.analyzer.analyze_headers(headers, url)
                analysis['url'] = url
                
                # Generate individual reports if requested
                if output_formats:
                    self.reporter.generate_reports(analysis, url, output_formats)
                
                return analysis
        except Exception as e:
            self.logger.error(f"Worker error for {url}: {str(e)}")
        
        return None
    

    def analyze_from_file(self, file_path: str, output_formats: List[str] = None,
                         output_dir: str = None, threads: int = None) -> List[Dict[str, Any]]:
        """Analyze websites from a file (one URL per line)"""
        try:
            with open(file_path, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            if not urls:
                self.ui.print_error(f"No URLs found in {file_path}")
                return []
            
            self.ui.print_info(f"Loaded {len(urls)} URLs from {file_path}")
            return self.analyze_multiple(urls, output_formats, output_dir, threads)
            
        except FileNotFoundError:
            self.ui.print_error(f"File not found: {file_path}")
            return []
        except Exception as e:
            self.ui.print_error(f"Error reading file: {str(e)}")
            return []
    
if __name__ == '__main__':
    app = ChSecurityHeaderAnalyzer()
    app.run()