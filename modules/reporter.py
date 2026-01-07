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
        """Generate HTML report using the provided beautiful template"""
        filepath = os.path.join(self.output_dir, f"{filename_base}.html")
        
        # Prepare context for the template
        grade_class = f"grade-{analysis['grade'].lower()}"
        grade_display = f"{analysis['grade']} - {self._get_grade_text(analysis['grade'])}"
        
        # Count vulnerabilities by severity
        vulnerability_count = {
            'high': sum(1 for v in analysis['vulnerabilities'] if v['severity'] == 'high'),
            'medium': sum(1 for v in analysis['vulnerabilities'] if v['severity'] == 'medium'),
            'low': sum(1 for v in analysis['vulnerabilities'] if v['severity'] == 'low'),
            'critical': sum(1 for v in analysis['vulnerabilities'] if v['severity'] == 'critical'),
        }
        total_vulnerabilities = sum(vulnerability_count.values())
        
        # Prepare headers analysis rows
        headers_rows = self._prepare_headers_rows(analysis)
        
        # Prepare vulnerabilities rows
        vulnerabilities_rows = self._prepare_vulnerabilities_rows(analysis['vulnerabilities'])
        
        # Prepare recommendations list
        recommendations_list = self._prepare_recommendations_list(analysis['recommendations'])
        
        # Prepare raw headers JSON
        raw_headers = {k: v for k, v in analysis['headers_found'].items() if not k.startswith('_')}
        
        # HTML template (using the provided template)
        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Header Analysis Report</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {{
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --success-color: #27ae60;
            --warning-color: #f39c12;
            --danger-color: #e74c3c;
            --dark-color: #2c3e50;
            --light-color: #ecf0f1;
            --gray-color: #95a5a6;
            --border-radius: 10px;
            --box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            --transition: all 0.3s ease;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
            padding: 20px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        .header {{
            background: linear-gradient(135deg, var(--primary-color) 0%, #1a252f 100%);
            color: white;
            padding: 30px;
            border-radius: var(--border-radius);
            margin-bottom: 30px;
            box-shadow: var(--box-shadow);
            position: relative;
            overflow: hidden;
        }}

        .header::before {{
            content: '';
            position: absolute;
            top: -50%;
            right: -50%;
            width: 200px;
            height: 200px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 50%;
        }}

        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 15px;
        }}

        .header h1 i {{
            color: var(--secondary-color);
        }}

        .header p {{
            font-size: 1.1rem;
            opacity: 0.9;
        }}

        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .card {{
            background: white;
            border-radius: var(--border-radius);
            padding: 25px;
            box-shadow: var(--box-shadow);
            transition: var(--transition);
        }}

        .card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.15);
        }}

        .card h3 {{
            color: var(--primary-color);
            margin-bottom: 15px;
            font-size: 1.3rem;
            border-bottom: 2px solid var(--light-color);
            padding-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .score-card {{
            text-align: center;
            background: linear-gradient(135deg, #fff 0%, #f8f9fa 100%);
        }}

        .score {{
            font-size: 4rem;
            font-weight: 800;
            margin: 20px 0;
        }}

        .grade {{
            display: inline-block;
            padding: 8px 25px;
            border-radius: 50px;
            font-weight: bold;
            font-size: 1.5rem;
            letter-spacing: 1px;
        }}

        .grade-a {{ background-color: #d5f4e6; color: var(--success-color); }}
        .grade-b {{ background-color: #fff3cd; color: #e6a700; }}
        .grade-c {{ background-color: #ffeaa7; color: #e67e22; }}
        .grade-d {{ background-color: #fadbd8; color: #e74c3c; }}
        .grade-f {{ background-color: var(--danger-color); color: white; }}

        .section {{
            background: white;
            border-radius: var(--border-radius);
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: var(--box-shadow);
        }}

        .section h2 {{
            color: var(--primary-color);
            margin-bottom: 25px;
            font-size: 1.8rem;
            border-left: 5px solid var(--secondary-color);
            padding-left: 15px;
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            border-radius: var(--border-radius);
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
        }}

        th {{
            background-color: var(--primary-color);
            color: white;
            font-weight: 600;
            padding: 18px 15px;
            text-align: left;
        }}

        td {{
            padding: 16px 15px;
            border-bottom: 1px solid #eee;
        }}

        tr:hover {{
            background-color: #f9f9f9;
        }}

        .present, .missing {{
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 6px 15px;
            border-radius: 50px;
        }}

        .present {{
            background-color: #d5f4e6;
            color: var(--success-color);
        }}

        .missing {{
            background-color: #fadbd8;
            color: var(--danger-color);
        }}

        .vuln-high, .vuln-medium, .vuln-low, .vuln-critical {{
            font-weight: bold;
            display: inline-block;
            padding: 6px 15px;
            border-radius: 50px;
            text-align: center;
            min-width: 100px;
        }}

        .vuln-critical {{
            background-color: #ff4444;
            color: white;
        }}

        .vuln-high {{
            background-color: #fadbd8;
            color: var(--danger-color);
        }}

        .vuln-medium {{
            background-color: #ffeaa7;
            color: #e67e22;
        }}

        .vuln-low {{
            background-color: #fff3cd;
            color: #f39c12;
        }}

        ul {{
            padding-left: 20px;
        }}

        li {{
            margin-bottom: 12px;
            padding-left: 10px;
            position: relative;
        }}

        li:before {{
            content: '→';
            position: absolute;
            left: -15px;
            color: var(--secondary-color);
            font-weight: bold;
        }}

        pre {{
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 20px;
            border-radius: var(--border-radius);
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            line-height: 1.5;
            margin-top: 15px;
            box-shadow: inset 0 2px 10px rgba(0, 0, 0, 0.3);
        }}

        .status-badge {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .footer {{
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: var(--gray-color);
            font-size: 0.9rem;
            border-top: 1px solid #eee;
        }}

        .recommendation-list li {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 10px;
            border-left: 4px solid var(--secondary-color);
        }}

        /* Responsive design */
        @media (max-width: 768px) {{
            .header h1 {{
                font-size: 2rem;
            }}
            
            .summary-cards {{
                grid-template-columns: 1fr;
            }}
            
            .score {{
                font-size: 3rem;
            }}
            
            table {{
                display: block;
                overflow-x: auto;
            }}
            
            .section {{
                padding: 20px;
            }}
        }}

        /* Animation for grade */
        @keyframes pulse {{
            0% {{ transform: scale(1); }}
            50% {{ transform: scale(1.05); }}
            100% {{ transform: scale(1); }}
        }}

        .grade-f {{
            animation: pulse 2s infinite;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> Security Header Analysis Report</h1>
            <p><i class="far fa-calendar-alt"></i> Generated: {analysis['scan_date']}</p>
        </div>
        
        <div class="summary-cards">
            <div class="card score-card">
                <h3><i class="fas fa-chart-line"></i> Security Score</h3>
                <div class="score">{analysis['security_score']}/100</div>
                <div class="grade {grade_class}">{grade_display}</div>
                <p style="margin-top: 15px; color: var(--gray-color);">{self._get_security_advice(analysis['security_score'])}</p>
            </div>
            
            <div class="card">
                <h3><i class="fas fa-globe"></i> Target URL</h3>
                <p style="font-size: 1.2rem; word-break: break-all;"><i class="fas fa-link"></i> {analysis['url']}</p>
                <div style="margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                    <p><strong>Headers Analyzed:</strong> {len(analysis['headers_found'])}</p>
                    <p><strong>Vulnerabilities Found:</strong> {total_vulnerabilities}</p>
                    <p><strong>Missing Headers:</strong> {len(analysis['missing_headers'])}</p>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2><i class="fas fa-search"></i> Headers Analysis</h2>
            <table>
                <thead>
                    <tr>
                        <th>Security Header</th>
                        <th>Status</th>
                        <th>Value / Issue</th>
                    </tr>
                </thead>
                <tbody>
                    {headers_rows}
                </tbody>
            </table>
        </div>
        
        {self._get_vulnerabilities_section(analysis['vulnerabilities'])}
        
        <div class="section">
            <h2><i class="fas fa-lightbulb"></i> Recommendations</h2>
            <div class="recommendation-list">
                <ul>
                    {recommendations_list}
                </ul>
            </div>
        </div>
        
        <div class="section">
            <h2><i class="fas fa-code"></i> Raw Headers</h2>
            <pre>{json.dumps(raw_headers, indent=2, default=str)}</pre>
        </div>
        
        <div class="footer">
            <p><i class="fas fa-info-circle"></i> Report generated by Security Header Analyzer</p>
            <p>This report highlights security vulnerabilities that should be addressed immediately.</p>
        </div>
    </div>
    
    <script>
        // Simple script to add interactivity
        document.addEventListener('DOMContentLoaded', function() {{
            // Add click effect to cards
            const cards = document.querySelectorAll('.card');
            cards.forEach(card => {{
                card.addEventListener('click', function() {{
                    this.style.transform = 'translateY(-5px)';
                    setTimeout(() => {{
                        this.style.transform = '';
                    }}, 200);
                }});
            }});
            
            // Highlight vulnerabilities on hover
            const vulnRows = document.querySelectorAll('tbody tr');
            vulnRows.forEach(row => {{
                row.addEventListener('mouseenter', function() {{
                    this.style.backgroundColor = '#fff9e6';
                }});
                row.addEventListener('mouseleave', function() {{
                    this.style.backgroundColor = '';
                }});
            }});
            
            // Add timestamp update (demo)
            const timestamp = document.querySelector('.header p');
            if (timestamp) {{
                const now = new Date();
                const formatted = now.toISOString().replace('T', ' ').substring(0, 19);
                timestamp.innerHTML = `<i class="far fa-calendar-alt"></i> Generated: ${{formatted}}`;
            }}
        }});
    </script>
</body>
</html>"""
    
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_template)
        
        return filepath

    def _prepare_headers_rows(self, analysis: Dict[str, Any]) -> str:
        """Prepare HTML rows for headers analysis table"""
        rows = []
        required_headers = self.config['security_headers']['required']
        
        for header in required_headers:
            header_lower = header.lower()
            if header_lower in analysis['headers_found']:
                status_html = '<div class="status-badge"><span class="present"><i class="fas fa-check-circle"></i> Present</span></div>'
                value = analysis['headers_found'][header_lower]
                
                # Check for issues in present headers
                issues = []
                if header == 'Strict-Transport-Security':
                    if 'max-age' in value.lower():
                        import re
                        max_age_match = re.search(r'max-age=(\d+)', value.lower())
                        if max_age_match:
                            max_age = int(max_age_match.group(1))
                            if max_age < 63072000:  # 2 years
                                issues.append('(Too low)')
                
                value_html = value
                if issues:
                    value_html = f"{value} <span style='color: var(--warning-color); font-weight: bold;'>{' '.join(issues)}</span>"
            else:
                status_html = '<div class="status-badge"><span class="missing"><i class="fas fa-times-circle"></i> Missing</span></div>'
                value_html = "<span style='color: var(--danger-color);'>Critical security header missing</span>"
            
            rows.append(f"""
                        <tr>
                            <td><strong>{header}</strong></td>
                            <td>{status_html}</td>
                            <td>{value_html}</td>
                        </tr>
                        """)
        
        return '\n'.join(rows)

    def _prepare_vulnerabilities_rows(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Prepare HTML rows for vulnerabilities table"""
        rows = []
        icons = {
            'critical': 'fas fa-radiation',
            'high': 'fas fa-bug',
            'medium': 'fas fa-shield-alt',
            'low': 'fas fa-info-circle'
        }
        
        for vuln in vulnerabilities:
            severity_class = f"vuln-{vuln['severity']}"
            icon = icons.get(vuln['severity'], 'fas fa-exclamation-circle')
            
            rows.append(f"""
                        <tr>
                            <td><span class="{severity_class}">{vuln['severity'].upper()}</span></td>
                            <td><i class="{icon}"></i> {vuln['description']}</td>
                        </tr>
                        """)
        
        return '\n'.join(rows)

    def _get_vulnerabilities_section(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Get vulnerabilities section HTML"""
        if not vulnerabilities:
            return f"""
            <div class="section">
                <h2><i class="fas fa-exclamation-triangle"></i> Vulnerabilities Found</h2>
                <p style="padding: 20px; background-color: #d5f4e6; border-radius: 8px; color: var(--success-color);">
                    <i class="fas fa-check-circle"></i> No vulnerabilities found! Excellent security configuration.
                </p>
            </div>
            """
        
        vulnerabilities_rows = self._prepare_vulnerabilities_rows(vulnerabilities)
        
        return f"""
            <div class="section">
                <h2><i class="fas fa-exclamation-triangle"></i> Vulnerabilities Found</h2>
                <table>
                    <thead>
                        <tr>
                            <th style="width: 120px;">Severity</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {vulnerabilities_rows}
                    </tbody>
                </table>
            </div>
            """

    def _prepare_recommendations_list(self, recommendations: List[str]) -> str:
        """Prepare HTML list for recommendations"""
        if not recommendations:
            return '<li>No recommendations. All security headers are properly configured.</li>'
        
        items = []
        for rec in recommendations[:15]:  # Limit to 15 recommendations
            # Format the recommendation nicely
            if rec.startswith('Add missing header:'):
                header = rec.replace('Add missing header:', '').strip()
                items.append(f'<li><strong>Add missing header:</strong> {header} with appropriate directives</li>')
            elif rec.startswith('Strengthen configuration for:'):
                header = rec.replace('Strengthen configuration for:', '').strip()
                items.append(f'<li><strong>Strengthen configuration for:</strong> {header}</li>')
            elif rec.startswith('Remove or obfuscate header:'):
                header = rec.replace('Remove or obfuscate header:', '').strip()
                items.append(f'<li><strong>Remove or obfuscate header:</strong> {header}</li>')
            elif rec.startswith('Consider adding recommended header:'):
                header = rec.replace('Consider adding recommended header:', '').strip()
                items.append(f'<li><strong>Consider adding recommended header:</strong> {header}</li>')
            else:
                items.append(f'<li>{rec}</li>')
        
        if len(recommendations) > 15:
            items.append(f'<li>... and {len(recommendations) - 15} more recommendations</li>')
        
        return '\n'.join(items)

    def _get_grade_text(self, grade: str) -> str:
        """Get descriptive text for grade"""
        grade_texts = {
            'A': 'EXCELLENT',
            'B': 'GOOD',
            'C': 'FAIR',
            'D': 'POOR',
            'F': 'CRITICAL'
        }
        return grade_texts.get(grade, 'UNKNOWN')

    def _get_security_advice(self, score: int) -> str:
        """Get security advice based on score"""
        if score >= 90:
            return "Excellent security configuration"
        elif score >= 80:
            return "Good security, minor improvements possible"
        elif score >= 70:
            return "Fair security, some improvements needed"
        elif score >= 60:
            return "Poor security, significant improvements required"
        else:
            return "Critical security issues - needs immediate attention"
        
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
        """Generate combined HTML report for multiple analyses"""
        filepath = os.path.join(self.output_dir, f"{filename_base}.html")
        
        # Calculate statistics
        stats = self._calculate_statistics(analyses)
        
        # Prepare summary table rows
        summary_rows = []
        for i, analysis in enumerate(analyses):
            grade_class = f"grade-{analysis['grade'].lower()}"
            url_short = analysis['url'][:50] + '...' if len(analysis['url']) > 50 else analysis['url']
            
            summary_rows.append(f"""
                <tr class="{grade_class}">
                    <td><a href="#analysis-{i}">{url_short}</a></td>
                    <td>{analysis['security_score']}</td>
                    <td>{analysis['grade']}</td>
                    <td>{len(analysis['missing_headers'])}</td>
                    <td>{len(analysis['vulnerabilities'])}</td>
                </tr>
            """)
        
        summary_rows_html = '\n'.join(summary_rows)
        
        # Prepare individual analysis sections
        analysis_sections = []
        for i, analysis in enumerate(analyses):
            grade_class = f"grade-{analysis['grade'].lower()}"
            grade_display = f"{analysis['grade']} - {self._get_grade_text(analysis['grade'])}"
            
            # Get first 3 vulnerabilities
            vuln_list = ""
            for vuln in analysis['vulnerabilities'][:3]:
                vuln_list += f'<li>[{vuln["severity"].upper()}] {vuln["description"]}</li>'
            
            if len(analysis['vulnerabilities']) > 3:
                vuln_list += f'<li>... and {len(analysis["vulnerabilities"]) - 3} more</li>'
            
            analysis_sections.append(f"""
                <div id="analysis-{i}" class="analysis-section" style="margin: 40px 0; padding: 20px; border: 1px solid #ddd; border-radius: 8px; background: white;">
                    <h3 style="color: var(--primary-color); margin-bottom: 15px;">
                        <i class="fas fa-link"></i> {analysis['url']}
                    </h3>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 15px 0;">
                        <div style="padding: 10px; background: #f8f9fa; border-radius: 6px;">
                            <strong>Score:</strong> {analysis['security_score']}
                        </div>
                        <div style="padding: 10px; background: #f8f9fa; border-radius: 6px;">
                            <strong>Grade:</strong> <span class="grade {grade_class}" style="padding: 4px 10px; font-size: 1rem;">{grade_display}</span>
                        </div>
                        <div style="padding: 10px; background: #f8f9fa; border-radius: 6px;">
                            <strong>Missing Headers:</strong> {len(analysis['missing_headers'])}
                        </div>
                        <div style="padding: 10px; background: #f8f9fa; border-radius: 6px;">
                            <strong>Vulnerabilities:</strong> {len(analysis['vulnerabilities'])}
                        </div>
                    </div>
                    <p><strong>Missing Headers:</strong> {', '.join(analysis['missing_headers']) or 'None'}</p>
                    {self._get_vulnerabilities_preview(analysis['vulnerabilities'])}
                </div>
            """)
        
        analysis_sections_html = '\n'.join(analysis_sections)
        
        # Combined HTML template
        html_template = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Combined Security Header Analysis Report</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            :root {{
                --primary-color: #2c3e50;
                --secondary-color: #3498db;
                --success-color: #27ae60;
                --warning-color: #f39c12;
                --danger-color: #e74c3c;
                --dark-color: #2c3e50;
                --light-color: #ecf0f1;
                --gray-color: #95a5a6;
                --border-radius: 10px;
                --box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
                --transition: all 0.3s ease;
            }}

            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}

            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
                min-height: 100vh;
                padding: 20px;
            }}

            .container {{
                max-width: 1200px;
                margin: 0 auto;
            }}

            .header {{
                background: linear-gradient(135deg, var(--primary-color) 0%, #1a252f 100%);
                color: white;
                padding: 30px;
                border-radius: var(--border-radius);
                margin-bottom: 30px;
                box-shadow: var(--box-shadow);
                position: relative;
                overflow: hidden;
            }}

            .header::before {{
                content: '';
                position: absolute;
                top: -50%;
                right: -50%;
                width: 200px;
                height: 200px;
                background: rgba(255, 255, 255, 0.05);
                border-radius: 50%;
            }}

            .header h1 {{
                font-size: 2.5rem;
                margin-bottom: 10px;
                display: flex;
                align-items: center;
                gap: 15px;
            }}

            .header h1 i {{
                color: var(--secondary-color);
            }}

            .header p {{
                font-size: 1.1rem;
                opacity: 0.9;
            }}

            .stats {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin: 30px 0;
            }}

            .stat-card {{
                background: white;
                padding: 20px;
                border-radius: var(--border-radius);
                text-align: center;
                box-shadow: var(--box-shadow);
                transition: var(--transition);
            }}

            .stat-card:hover {{
                transform: translateY(-5px);
            }}

            .stat-value {{
                font-size: 2em;
                font-weight: bold;
                margin: 10px 0;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
                border-radius: var(--border-radius);
                overflow: hidden;
                box-shadow: var(--box-shadow);
            }}

            th {{
                background-color: var(--primary-color);
                color: white;
                font-weight: 600;
                padding: 18px 15px;
                text-align: left;
            }}

            td {{
                padding: 16px 15px;
                border-bottom: 1px solid #eee;
            }}

            tr:hover {{
                background-color: #f9f9f9;
            }}

            .grade-a {{ background-color: #d5f4e6; }}
            .grade-b {{ background-color: #fff3cd; }}
            .grade-c {{ background-color: #ffeaa7; }}
            .grade-d {{ background-color: #fadbd8; }}
            .grade-f {{ background-color: #f5c6cb; }}

            .grade {{
                display: inline-block;
                padding: 4px 12px;
                border-radius: 50px;
                font-weight: bold;
                font-size: 0.9rem;
            }}

            .grade-a .grade {{ background-color: #27ae60; color: white; }}
            .grade-b .grade {{ background-color: #f39c12; color: white; }}
            .grade-c .grade {{ background-color: #e67e22; color: white; }}
            .grade-d .grade {{ background-color: #e74c3c; color: white; }}
            .grade-f .grade {{ background-color: #c0392b; color: white; }}

            .analysis-section {{
                background: white;
                border-radius: var(--border-radius);
                padding: 20px;
                margin-bottom: 20px;
                box-shadow: var(--box-shadow);
            }}

            @media (max-width: 768px) {{
                .header h1 {{
                    font-size: 2rem;
                }}
                
                .stats {{
                    grid-template-columns: 1fr;
                }}
                
                table {{
                    display: block;
                    overflow-x: auto;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1><i class="fas fa-shield-alt"></i> Combined Security Header Analysis Report</h1>
                <p><i class="far fa-calendar-alt"></i> Generated: {datetime.now().isoformat()}</p>
                <p><i class="fas fa-globe"></i> Total Websites Analyzed: {len(analyses)}</p>
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-value">{stats['average_score']:.1f}</div>
                    <div>Average Score</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['grade_distribution'].get('A', 0)}</div>
                    <div>Grade A</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['grade_distribution'].get('B', 0)}</div>
                    <div>Grade B</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['grade_distribution'].get('C', 0)}</div>
                    <div>Grade C</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['grade_distribution'].get('D', 0)}</div>
                    <div>Grade D</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['grade_distribution'].get('F', 0)}</div>
                    <div>Grade F</div>
                </div>
            </div>
            
            <h2 style="color: var(--primary-color); margin: 30px 0 20px 0;">Detailed Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Score</th>
                        <th>Grade</th>
                        <th>Missing Headers</th>
                        <th>Vulnerabilities</th>
                    </tr>
                </thead>
                <tbody>
                    {summary_rows_html}
                </tbody>
            </table>
            
            <h2 style="color: var(--primary-color); margin: 40px 0 20px 0;">Individual Reports</h2>
            {analysis_sections_html}
            
            <div class="footer" style="text-align: center; margin-top: 40px; padding: 20px; color: var(--gray-color); font-size: 0.9rem; border-top: 1px solid #eee;">
                <p><i class="fas fa-info-circle"></i> Report generated by Security Header Analyzer</p>
                <p>This combined report summarizes security analysis for multiple websites.</p>
            </div>
        </div>
        
        <script>
            document.addEventListener('DOMContentLoaded', function() {{
                // Smooth scrolling for anchor links
                document.querySelectorAll('a[href^="#"]').forEach(anchor => {{
                    anchor.addEventListener('click', function (e) {{
                        e.preventDefault();
                        const targetId = this.getAttribute('href');
                        const targetElement = document.querySelector(targetId);
                        if (targetElement) {{
                            window.scrollTo({{
                                top: targetElement.offsetTop - 20,
                                behavior: 'smooth'
                            }});
                        }}
                    }});
                }});
                
                // Add hover effect to analysis sections
                const analysisSections = document.querySelectorAll('.analysis-section');
                analysisSections.forEach(section => {{
                    section.addEventListener('mouseenter', function() {{
                        this.style.boxShadow = '0 8px 25px rgba(0, 0, 0, 0.15)';
                        this.style.transform = 'translateY(-5px)';
                    }});
                    section.addEventListener('mouseleave', function() {{
                        this.style.boxShadow = '';
                        this.style.transform = '';
                    }});
                }});
            }});
        </script>
    </body>
    </html>"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_template)
        
        return filepath

    def _get_vulnerabilities_preview(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Get HTML for vulnerabilities preview in combined report"""
        if not vulnerabilities:
            return '<p><strong>Vulnerabilities:</strong> None</p>'
        
        vuln_list = '<ul style="margin-top: 10px; padding-left: 20px;">'
        for vuln in vulnerabilities[:3]:
            severity_color = {
                'critical': '#ff4444',
                'high': '#e74c3c',
                'medium': '#e67e22',
                'low': '#f39c12'
            }.get(vuln['severity'], '#95a5a6')
            
            vuln_list += f'<li style="margin-bottom: 5px;"><span style="color: {severity_color}; font-weight: bold;">[{vuln["severity"].upper()}]</span> {vuln["description"][:100]}{"..." if len(vuln["description"]) > 100 else ""}</li>'
        
        if len(vulnerabilities) > 3:
            vuln_list += f'<li style="color: var(--gray-color);">... and {len(vulnerabilities) - 3} more vulnerabilities</li>'
        
        vuln_list += '</ul>'
        
        return f'<div style="margin-top: 15px;"><strong>Vulnerabilities:</strong>{vuln_list}</div>'

    def _calculate_statistics(self, analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate statistics from multiple analyses"""
        if not analyses:
            return {}
        
        stats = {
            'average_score': sum(a['security_score'] for a in analyses) / len(analyses),
            'grade_distribution': {},
            'common_missing_headers': {},
            'total_vulnerabilities': sum(len(a['vulnerabilities']) for a in analyses)
        }
        
        # Grade distribution
        for analysis in analyses:
            grade = analysis['grade']
            stats['grade_distribution'][grade] = stats['grade_distribution'].get(grade, 0) + 1
        
        # Common missing headers
        for analysis in analyses:
            for header in analysis['missing_headers']:
                stats['common_missing_headers'][header] = stats['common_missing_headers'].get(header, 0) + 1
        
        return stats

