"""
Report Generator Module
"""

import json
import csv
import os
from typing import Dict, List, Any
from datetime import datetime
import pandas as pd
from jinja2 import Template


class ReportGenerator:
    def __init__(self, config: Dict):
        self.config = config
        self.output_dir = config['reporting']['default_output_dir']
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_reports(self, analysis: Dict[str, Any], url: str, 
                        formats: List[str]) -> Dict[str, str]:
        """Generate reports in specified formats"""
        report_paths = {}
        
        # Sanitize filename from URL
        filename_base = self._sanitize_filename(url)
        
        for fmt in formats:
            if fmt == 'txt':
                path = self._generate_txt_report(analysis, filename_base)
                report_paths['txt'] = path
            elif fmt == 'json':
                path = self._generate_json_report(analysis, filename_base)
                report_paths['json'] = path
            elif fmt == 'csv':
                path = self._generate_csv_report(analysis, filename_base)
                report_paths['csv'] = path
            elif fmt == 'html':
                path = self._generate_html_report(analysis, filename_base)
                report_paths['html'] = path
        
        return report_paths
    
    def generate_combined_report(self, analyses: List[Dict[str, Any]], 
                               formats: List[str], output_dir: str = None) -> Dict[str, str]:
        """Generate combined report for multiple analyses"""
        if output_dir:
            self.output_dir = output_dir
            os.makedirs(self.output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename_base = f"combined_report_{timestamp}"
        
        report_paths = {}
        
        for fmt in formats:
            if fmt == 'txt':
                path = self._generate_combined_txt(analyses, filename_base)
                report_paths['txt'] = path
            elif fmt == 'json':
                path = self._generate_combined_json(analyses, filename_base)
                report_paths['json'] = path
            elif fmt == 'csv':
                path = self._generate_combined_csv(analyses, filename_base)
                report_paths['csv'] = path
            elif fmt == 'html':
                path = self._generate_combined_html(analyses, filename_base)
                report_paths['html'] = path
        
        return report_paths

    def _sanitize_filename(self, url: str) -> str:
        """Create safe filename from URL"""
        # Remove protocol
        if '://' in url:
            url = url.split('://')[1]
        
        # Replace special characters
        filename = url.replace('/', '_').replace(':', '_').replace('?', '_')
        filename = filename.replace('&', '_').replace('=', '_').replace('%', '_')
        
        # Limit length
        if len(filename) > 100:
            filename = filename[:100]
        
        # Add timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{filename}_{timestamp}"
    
    