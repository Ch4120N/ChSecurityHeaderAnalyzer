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
    

    def _generate_txt_report(self, analysis: Dict[str, Any], filename_base: str) -> str:
        """Generate TXT report"""
        filepath = os.path.join(self.output_dir, f"{filename_base}.txt")
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("SECURITY HEADER ANALYSIS REPORT\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"URL: {analysis['url']}\n")
            f.write(f"Scan Date: {analysis['scan_date']}\n")
            f.write(f"Security Score: {analysis['security_score']}/100\n")
            f.write(f"Security Grade: {analysis['grade']}\n\n")
            
            f.write("-" * 60 + "\n")
            f.write("HEADERS FOUND\n")
            f.write("-" * 60 + "\n")
            for header, value in analysis['headers_found'].items():
                if not header.startswith('_'):
                    f.write(f"{header}: {value}\n")
            
            f.write("\n" + "-" * 60 + "\n")
            f.write("MISSING HEADERS\n")
            f.write("-" * 60 + "\n")
            for header in analysis['missing_headers']:
                f.write(f"✗ {header}\n")
            
            if not analysis['missing_headers']:
                f.write("✓ All required headers present\n")
            
            f.write("\n" + "-" * 60 + "\n")
            f.write("VULNERABILITIES\n")
            f.write("-" * 60 + "\n")
            for vuln in analysis['vulnerabilities']:
                f.write(f"[{vuln['severity'].upper()}] {vuln['description']}\n")
            
            if not analysis['vulnerabilities']:
                f.write("✓ No vulnerabilities found\n")
            
            f.write("\n" + "-" * 60 + "\n")
            f.write("RECOMMENDATIONS\n")
            f.write("-" * 60 + "\n")
            for rec in analysis['recommendations']:
                f.write(f"• {rec}\n")
        
        return filepath
    
    def _generate_json_report(self, analysis: Dict[str, Any], filename_base: str) -> str:
        """Generate JSON report"""
        filepath = os.path.join(self.output_dir, f"{filename_base}.json")
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(analysis, f, indent=2, default=str)
        
        return filepath

    
    def _generate_csv_report(self, analysis: Dict[str, Any], filename_base: str) -> str:
        """Generate CSV report"""
        filepath = os.path.join(self.output_dir, f"{filename_base}.csv")
        
        # Prepare data for CSV
        data = {
            'URL': [analysis['url']],
            'Scan_Date': [analysis['scan_date']],
            'Security_Score': [analysis['security_score']],
            'Grade': [analysis['grade']],
            'Missing_Headers': [';'.join(analysis['missing_headers'])],
            'Vulnerability_Count': [len(analysis['vulnerabilities'])],
            'Recommendation_Count': [len(analysis['recommendations'])]
        }
        
        # Add headers as columns
        for header, value in analysis['headers_found'].items():
            if not header.startswith('_'):
                data[f"Header_{header}"] = [value]
        
        df = pd.DataFrame(data)
        df.to_csv(filepath, index=False, encoding='utf-8')
        
        return filepath

    def _generate_html_report(self, analysis: Dict[str, Any], filename_base: str) -> str:
        """Generate HTML report"""
        filepath = os.path.join(self.output_dir, f"{filename_base}.html")
        
        # HTML template
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Security Header Analysis Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
                .section { margin: 30px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
                .grade-a { color: #27ae60; font-weight: bold; }
                .grade-b { color: #f39c12; font-weight: bold; }
                .grade-c { color: #e67e22; font-weight: bold; }
                .grade-d { color: #e74c3c; font-weight: bold; }
                .grade-f { color: #c0392b; font-weight: bold; }
                .vuln-high { color: #e74c3c; }
                .vuln-medium { color: #e67e22; }
                .vuln-low { color: #f39c12; }
                table { width: 100%; border-collapse: collapse; margin: 10px 0; }
                th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #f2f2f2; }
                .present { color: #27ae60; }
                .missing { color: #e74c3c; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Header Analysis Report</h1>
                <p>Generated: {{ scan_date }}</p>
            </div>
            
            <div class="section">
                <h2>Summary</h2>
                <p><strong>URL:</strong> {{ url }}</p>
                <p><strong>Security Score:</strong> {{ security_score }}/100</p>
                <p><strong>Grade:</strong> <span class="grade-{{ grade.lower() }}">{{ grade }}</span></p>
            </div>
            
            <div class="section">
                <h2>Headers Analysis</h2>
                <table>
                    <tr><th>Header</th><th>Status</th><th>Value</th></tr>
                    {% for header in required_headers %}
                    <tr>
                        <td>{{ header }}</td>
                        <td>
                            {% if header.lower() in headers_found %}
                            <span class="present">✓ Present</span>
                            {% else %}
                            <span class="missing">✗ Missing</span>
                            {% endif %}
                        </td>
                        <td>{{ headers_found.get(header.lower(), 'N/A') }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
            
            {% if vulnerabilities %}
            <div class="section">
                <h2>Vulnerabilities</h2>
                <table>
                    <tr><th>Severity</th><th>Description</th></tr>
                    {% for vuln in vulnerabilities %}
                    <tr>
                        <td class="vuln-{{ vuln.severity }}">{{ vuln.severity|upper }}</td>
                        <td>{{ vuln.description }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
            {% endif %}
            
            {% if recommendations %}
            <div class="section">
                <h2>Recommendations</h2>
                <ul>
                    {% for rec in recommendations %}
                    <li>{{ rec }}</li>
                    {% endfor %}
                </ul>
            </div>
            {% endif %}
            
            <div class="section">
                <h2>Raw Headers</h2>
                <pre>{{ raw_headers }}</pre>
            </div>
        </body>
        </html>
        """
        
        # Prepare context
        context = {
            'url': analysis['url'],
            'scan_date': analysis['scan_date'],
            'security_score': analysis['security_score'],
            'grade': analysis['grade'],
            'required_headers': self.config['security_headers']['required'],
            'headers_found': analysis['headers_found'],
            'vulnerabilities': analysis['vulnerabilities'],
            'recommendations': analysis['recommendations'],
            'raw_headers': json.dumps(
                {k: v for k, v in analysis['headers_found'].items() if not k.startswith('_')},
                indent=2
            )
        }
        
        # Render template
        template = Template(html_template)
        html_content = template.render(**context)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filepath

    def _generate_combined_txt(self, analyses: List[Dict[str, Any]], filename_base: str) -> str:
        """Generate combined TXT report"""
        filepath = os.path.join(self.output_dir, f"{filename_base}.txt")
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("COMBINED SECURITY HEADER ANALYSIS REPORT\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Total Websites Analyzed: {len(analyses)}\n")
            f.write(f"Report Date: {datetime.now().isoformat()}\n\n")
            
            # Summary table
            f.write("-" * 60 + "\n")
            f.write("SUMMARY\n")
            f.write("-" * 60 + "\n")
            f.write(f"{'URL':<40} {'Score':<6} {'Grade':<6} {'Missing':<8}\n")
            f.write("-" * 60 + "\n")
            
            for analysis in analyses:
                url_short = analysis['url'][:38] + '..' if len(analysis['url']) > 40 else analysis['url']
                f.write(f"{url_short:<40} {analysis['security_score']:<6} {analysis['grade']:<6} {len(analysis['missing_headers']):<8}\n")
        
        return filepath
    
    def _generate_combined_json(self, analyses: List[Dict[str, Any]], filename_base: str) -> str:
        """Generate combined JSON report"""
        filepath = os.path.join(self.output_dir, f"{filename_base}.json")
        
        combined = {
            'report_date': datetime.now().isoformat(),
            'total_websites': len(analyses),
            'analyses': analyses,
            'statistics': self._calculate_statistics(analyses)
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(combined, f, indent=2, default=str)
        
        return filepath
    
    def _generate_combined_csv(self, analyses: List[Dict[str, Any]], filename_base: str) -> str:
        """Generate combined CSV report"""
        filepath = os.path.join(self.output_dir, f"{filename_base}.csv")
        
        # Prepare data
        rows = []
        for analysis in analyses:
            row = {
                'URL': analysis['url'],
                'Security_Score': analysis['security_score'],
                'Grade': analysis['grade'],
                'Missing_Headers_Count': len(analysis['missing_headers']),
                'Vulnerability_Count': len(analysis['vulnerabilities']),
                'Missing_Headers': ';'.join(analysis['missing_headers'])
            }
            rows.append(row)
        
        df = pd.DataFrame(rows)
        df.to_csv(filepath, index=False, encoding='utf-8')
        
        return filepath

    def _generate_combined_html(self, analyses: List[Dict[str, Any]], filename_base: str) -> str:
        """Generate combined HTML report"""
        filepath = os.path.join(self.output_dir, f"{filename_base}.html")
        
        # Statistics
        stats = self._calculate_statistics(analyses)
        
        # HTML template for combined report
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Combined Security Header Analysis Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
                .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
                .stat-card { background: #f8f9fa; padding: 20px; border-radius: 5px; text-align: center; }
                .stat-value { font-size: 2em; font-weight: bold; }
                table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #2c3e50; color: white; }
                tr:hover { background-color: #f5f5f5; }
                .grade-a { background-color: #d4edda; }
                .grade-b { background-color: #fff3cd; }
                .grade-c { background-color: #ffeaa7; }
                .grade-d { background-color: #f8d7da; }
                .grade-f { background-color: #f5c6cb; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Combined Security Header Analysis Report</h1>
                <p>Generated: {{ report_date }}</p>
                <p>Total Websites Analyzed: {{ total_websites }}</p>
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-value">{{ average_score|round(1) }}</div>
                    <div>Average Score</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ grade_distribution.A|default(0) }}</div>
                    <div>Grade A</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ grade_distribution.B|default(0) }}</div>
                    <div>Grade B</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ grade_distribution.C|default(0) }}</div>
                    <div>Grade C</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ grade_distribution.D|default(0) }}</div>
                    <div>Grade D</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ grade_distribution.F|default(0) }}</div>
                    <div>Grade F</div>
                </div>
            </div>
            
            <h2>Detailed Results</h2>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Score</th>
                    <th>Grade</th>
                    <th>Missing Headers</th>
                    <th>Vulnerabilities</th>
                </tr>
                {% for analysis in analyses %}
                <tr class="grade-{{ analysis.grade.lower() }}">
                    <td><a href="#{{ loop.index }}">{{ analysis.url[:50] }}{% if analysis.url|length > 50 %}...{% endif %}</a></td>
                    <td>{{ analysis.security_score }}</td>
                    <td>{{ analysis.grade }}</td>
                    <td>{{ analysis.missing_headers|length }}</td>
                    <td>{{ analysis.vulnerabilities|length }}</td>
                </tr>
                {% endfor %}
            </table>
            
            <h2>Individual Reports</h2>
            {% for analysis in analyses %}
            <div id="{{ loop.index }}" style="margin: 40px 0; padding: 20px; border: 1px solid #ddd;">
                <h3>{{ analysis.url }}</h3>
                <p><strong>Score:</strong> {{ analysis.security_score }} | <strong>Grade:</strong> {{ analysis.grade }}</p>
                <p><strong>Missing Headers:</strong> {{ analysis.missing_headers|join(', ') or 'None' }}</p>
                {% if analysis.vulnerabilities %}
                <p><strong>Vulnerabilities:</strong></p>
                <ul>
                    {% for vuln in analysis.vulnerabilities[:3] %}
                    <li>[{{ vuln.severity|upper }}] {{ vuln.description }}</li>
                    {% endfor %}
                    {% if analysis.vulnerabilities|length > 3 %}
                    <li>... and {{ analysis.vulnerabilities|length - 3 }} more</li>
                    {% endif %}
                </ul>
                {% endif %}
            </div>
            {% endfor %}
        </body>
        </html>
        """
        
        # Prepare context
        context = {
            'report_date': datetime.now().isoformat(),
            'total_websites': len(analyses),
            'analyses': analyses,
            'average_score': stats['average_score'],
            'grade_distribution': stats['grade_distribution']
        }
        
        # Render template
        template = Template(html_template)
        html_content = template.render(**context)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filepath

