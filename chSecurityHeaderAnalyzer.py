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
    
    