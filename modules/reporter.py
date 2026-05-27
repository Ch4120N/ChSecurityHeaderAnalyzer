"""
Report Generator Module - Excellent Edition
"""

import json
import csv
import os
from typing import Dict, List, Any
from datetime import datetime
from collections import Counter

import pandas as pd
from jinja2 import Template

class ReportGenerator:
    def __init__(self, config: Dict):
        self.config = config
        self.output_dir = config['reporting']['default_output_dir']
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)

    def _get_cookie_analysis_summary(self, cookie_analysis: List[Dict]) -> str:
        """Get summary of cookie analysis"""
        if not cookie_analysis:
            return "No cookies set"
        
        secure_count = sum(1 for c in cookie_analysis if c.get('flags', {}).get('secure'))
        httponly_count = sum(1 for c in cookie_analysis if c.get('flags', {}).get('httponly'))
        samesite_count = sum(1 for c in cookie_analysis if 'samesite' in c.get('flags', {}))
        issue_count = sum(len(c.get('issues', [])) for c in cookie_analysis)
        
        return f"{len(cookie_analysis)} cookies, {secure_count} Secure, {httponly_count} HttpOnly, {samesite_count} SameSite, {issue_count} issues"

    def _get_cors_analysis_summary(self, cors_analysis: Dict) -> str:
        """Get summary of CORS analysis"""
        if not cors_analysis:
            return "No CORS headers"
        
        issues = cors_analysis.get('issues', [])
        origin = cors_analysis.get('origin', 'Not set')
        credentials = cors_analysis.get('credentials', 'Not set')
        
        return f"Origin: {origin}, Credentials: {credentials}, Issues: {len(issues)}"

    def _get_cache_analysis_summary(self, cache_analysis: Dict) -> str:
        """Get summary of cache analysis"""
        if not cache_analysis:
            return "No cache control"
        
        issues = cache_analysis.get('issues', [])
        directives = len(cache_analysis.get('directives', {}))
        
        return f"{directives} directives, Issues: {len(issues)}"

    def _get_additional_checks_summary(self, additional_checks: Dict) -> str:
        """Get summary of additional checks"""
        if not additional_checks:
            return "No additional checks performed"
        
        checks = []
        if 'ssl_certificate' in additional_checks:
            ssl = additional_checks['ssl_certificate']
            checks.append(f"SSL: {'Valid' if ssl.get('valid') else 'Invalid'}")
        
        if 'server_banner' in additional_checks:
            banner = additional_checks['server_banner']
            checks.append(f"Server: {banner.get('value', 'N/A')}")
        
        return ', '.join(checks)

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
    
    def _get_total_missing(self, analysis: Dict[str, Any]) -> int:
        """Helper to get total missing headers count"""
        missing_required = len(analysis.get('missing_required', []))
        missing_recommended = len(analysis.get('missing_recommended', []))
        return missing_required + missing_recommended

    def _get_all_missing_headers(self, analysis: Dict[str, Any]) -> List[str]:
        """Helper to get all missing headers (required + recommended)"""
        return analysis.get('missing_required', []) + analysis.get('missing_recommended', [])

    def _generate_txt_report(self, analysis: Dict[str, Any], filename_base: str) -> str:
        """Generate TXT report with enhanced recommendations"""
        filepath = os.path.join(self.output_dir, f"{filename_base}.txt")
        
        total_missing = self._get_total_missing(analysis)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("SECURITY HEADER ANALYSIS REPORT\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"URL: {analysis['url']}\n")
            f.write(f"Scan Date: {analysis['scan_date']}\n")
            f.write(f"Security Score: {analysis['security_score']}/100\n")
            f.write(f"Security Grade: {analysis['grade']}\n\n")
            
            f.write("-" * 60 + "\n")
            f.write("SUMMARY\n")
            f.write("-" * 60 + "\n")
            f.write(f"Headers Analyzed: {len(analysis['headers_found'])}\n")
            f.write(f"Missing Required Headers: {len(analysis.get('missing_required', []))}\n")
            f.write(f"Missing Recommended Headers: {len(analysis.get('missing_recommended', []))}\n")
            f.write(f"Vulnerabilities Found: {len(analysis['vulnerabilities'])}\n")
            f.write(f"Recommendations: {len(analysis['recommendations'])}\n\n")
            
            f.write("-" * 60 + "\n")
            f.write("HEADERS FOUND\n")
            f.write("-" * 60 + "\n")
            for header, value in analysis['headers_found'].items():
                if not header.startswith('_'):
                    f.write(f"{header}: {value}\n")
            
            f.write("\n" + "-" * 60 + "\n")
            f.write("MISSING HEADERS\n")
            f.write("-" * 60 + "\n")
            
            # Write missing required headers
            if analysis.get('missing_required'):
                f.write("\n[CRITICAL - Required Headers Missing]:\n")
                for header in analysis['missing_required']:
                    f.write(f"  ✗ {header} (REQUIRED)\n")
            
            # Write missing recommended headers
            if analysis.get('missing_recommended'):
                f.write("\n[RECOMMENDED - Best Practice Headers Missing]:\n")
                for header in analysis['missing_recommended']:
                    f.write(f"  ? {header} (recommended)\n")
            
            if not analysis.get('missing_required') and not analysis.get('missing_recommended'):
                f.write("✓ All required and recommended headers present\n")
            
            # Deprecated headers
            if analysis.get('deprecated_found'):
                f.write("\n[DEPRECATED HEADERS FOUND]:\n")
                for header in analysis['deprecated_found']:
                    f.write(f"  ⚠ {header} (should be replaced with modern alternative)\n")
            
            f.write("\n" + "-" * 60 + "\n")
            f.write("VULNERABILITIES\n")
            f.write("-" * 60 + "\n")
            if analysis['vulnerabilities']:
                for vuln in analysis['vulnerabilities']:
                    if vuln['severity'] != 'info':  # Skip informational only
                        f.write(f"[{vuln['severity'].upper()}] {vuln['description']}\n")
            else:
                f.write("✓ No vulnerabilities found\n")
            
            f.write("\n" + "-" * 60 + "\n")
            f.write(f"RECOMMENDATIONS ({len(analysis['recommendations'])})\n")
            f.write("-" * 60 + "\n")
            
            if analysis['recommendations']:
                # Categorize by priority
                critical = [r for r in analysis['recommendations'] if 'CRITICAL:' in r]
                high = [r for r in analysis['recommendations'] if 'HIGH:' in r]
                medium = [r for r in analysis['recommendations'] if 'MEDIUM:' in r]
                low = [r for r in analysis['recommendations'] if r not in critical + high + medium]
                
                if critical:
                    f.write("\n[CRITICAL PRIORITY] - Immediate Action Required:\n")
                    f.write("-" * 40 + "\n")
                    for i, rec in enumerate(critical, 1):
                        clean_rec = rec.replace('CRITICAL:', '').strip()
                        f.write(f"{i}. {clean_rec}\n")
                
                if high:
                    f.write("\n[HIGH PRIORITY] - Important Security Improvements:\n")
                    f.write("-" * 40 + "\n")
                    for i, rec in enumerate(high, 1):
                        clean_rec = rec.replace('HIGH:', '').strip()
                        f.write(f"{i}. {clean_rec}\n")
                
                if medium:
                    f.write("\n[MEDIUM PRIORITY] - Recommended Enhancements:\n")
                    f.write("-" * 40 + "\n")
                    for i, rec in enumerate(medium, 1):
                        clean_rec = rec.replace('MEDIUM:', '').strip()
                        f.write(f"{i}. {clean_rec}\n")
                
                if low:
                    f.write("\n[LOW PRIORITY] - Best Practices:\n")
                    f.write("-" * 40 + "\n")
                    for i, rec in enumerate(low, 1):
                        f.write(f"{i}. {rec}\n")
                
                # Implementation summary
                f.write("\n" + "-" * 60 + "\n")
                f.write("IMPLEMENTATION SUMMARY\n")
                f.write("-" * 60 + "\n")
                f.write(f"Total Recommendations: {len(analysis['recommendations'])}\n")
                f.write(f"Priority Breakdown: {len(critical)} Critical, {len(high)} High, "
                    f"{len(medium)} Medium, {len(low)} Low\n")
            else:
                f.write("✓ No recommendations needed - All configurations are optimal\n")
            
            # Improvement summary
            improvement = self._get_improvement_summary(analysis)
            f.write("\n" + "-" * 60 + "\n")
            f.write("IMPROVEMENT SUMMARY\n")
            f.write("-" * 60 + "\n")
            f.write(f"Current Score: {analysis['security_score']}/100 ({analysis['grade']})\n")
            f.write(f"Potential Score: {improvement['potential_score']}/100\n")
            f.write(f"Key Areas: {improvement['key_areas']}\n")
        
        return filepath
    
    def _generate_json_report(self, analysis: Dict[str, Any], filename_base: str) -> str:
        """Generate JSON report with enhanced recommendations section"""
        filepath = os.path.join(self.output_dir, f"{filename_base}.json")
        
        # Enhance the analysis with categorized recommendations
        enhanced_analysis = analysis.copy()
        
        # Categorize recommendations
        recommendations_categorized = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'all': analysis['recommendations']
        }
        
        for rec in analysis['recommendations']:
            if rec.startswith('CRITICAL:'):
                recommendations_categorized['critical'].append(rec)
            elif rec.startswith('HIGH:'):
                recommendations_categorized['high'].append(rec)
            elif rec.startswith('MEDIUM:'):
                recommendations_categorized['medium'].append(rec)
            else:
                recommendations_categorized['low'].append(rec)
        
        # Add categorized recommendations
        enhanced_analysis['recommendations_categorized'] = recommendations_categorized
        
        # Add improvement summary
        enhanced_analysis['improvement_summary'] = self._get_improvement_summary(analysis)
        
        # Add implementation estimate
        enhanced_analysis['implementation_estimate'] = {
            'time_estimate': self._get_estimated_implementation_time(
                len(recommendations_categorized['critical']),
                len(recommendations_categorized['high'])
            ),
            'total_recommendations': len(analysis['recommendations']),
            'by_priority': {
                'critical': len(recommendations_categorized['critical']),
                'high': len(recommendations_categorized['high']),
                'medium': len(recommendations_categorized['medium']),
                'low': len(recommendations_categorized['low'])
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(enhanced_analysis, f, indent=2, default=str)
        
        return filepath

    def _generate_csv_report(self, analysis: Dict[str, Any], filename_base: str) -> str:
        """Generate comprehensive CSV report"""
        filepath = os.path.join(self.output_dir, f"{filename_base}.csv")
        
        total_missing = self._get_total_missing(analysis)
        all_missing = self._get_all_missing_headers(analysis)
        
        # 1. Summary Sheet
        summary_data = {
            'Metric': [
                'URL',
                'Scan Date',
                'Security Score',
                'Security Grade',
                'Total Headers Found',
                'Missing Required Headers',
                'Missing Recommended Headers',
                'Deprecated Headers Found',
                'Total Vulnerabilities',
                'Critical Vulnerabilities',
                'High Vulnerabilities',
                'Medium Vulnerabilities',
                'Low Vulnerabilities',
                'Recommendations Count'
            ],
            'Value': [
                analysis['url'],
                analysis['scan_date'],
                analysis['security_score'],
                analysis['grade'],
                len(analysis['headers_found']),
                len(analysis.get('missing_required', [])),
                len(analysis.get('missing_recommended', [])),
                len(analysis.get('deprecated_found', [])),
                len(analysis['vulnerabilities']),
                sum(1 for v in analysis['vulnerabilities'] if v['severity'] == 'critical'),
                sum(1 for v in analysis['vulnerabilities'] if v['severity'] == 'high'),
                sum(1 for v in analysis['vulnerabilities'] if v['severity'] == 'medium'),
                sum(1 for v in analysis['vulnerabilities'] if v['severity'] == 'low'),
                len(analysis['recommendations'])
            ]
        }
        
        summary_df = pd.DataFrame(summary_data)
        
        # 2. Headers Analysis Sheet
        required_headers = self.config['security_headers']['required']
        recommended_headers = self.config['security_headers']['recommended']
        vulnerable_headers = self.config['security_headers']['vulnerable']
        infrastructure_headers = self.config['security_headers'].get('infrastructure', [])
        deprecated_headers = self.config['security_headers'].get('deprecated', [])
        
        all_check_headers = required_headers + recommended_headers + vulnerable_headers + infrastructure_headers + deprecated_headers
        
        headers_data = []
        for header in all_check_headers:
            header_lower = header.lower()
            status = 'Present' if header_lower in analysis['headers_found'] else 'Missing'
            
            if header_lower in analysis['headers_found']:
                value = analysis['headers_found'][header_lower]
                if len(value) > 200:
                    value = value[:197] + '...'
            else:
                value = ''
            
            if header in required_headers:
                category = 'Required'
            elif header in recommended_headers:
                category = 'Recommended'
            elif header in vulnerable_headers:
                category = 'Vulnerable'
            elif header in infrastructure_headers:
                category = 'Infrastructure'
            elif header in deprecated_headers:
                category = 'Deprecated'
            else:
                category = 'Other'
            
            if header in required_headers and status == 'Missing':
                risk_level = 'High'
            elif header in vulnerable_headers and status == 'Present':
                risk_level = 'Medium'
            elif header in deprecated_headers and status == 'Present':
                risk_level = 'Low'
            elif header in infrastructure_headers and status == 'Present':
                risk_level = 'Info'
            else:
                risk_level = 'None'
            
            headers_data.append({
                'Header': header,
                'Category': category,
                'Status': status,
                'Risk Level': risk_level,
                'Value': value,
                'Recommendation': self._get_header_recommendation(header, status, value)
            })
        
        headers_df = pd.DataFrame(headers_data)
        
        # 3. Vulnerabilities Sheet
        vulnerabilities_data = []
        for vuln in analysis['vulnerabilities']:
            if vuln['severity'] != 'info':  # Skip info-level items
                vulnerabilities_data.append({
                    'Severity': vuln['severity'].upper(),
                    'Type': vuln['type'].replace('_', ' ').title(),
                    'Header': vuln.get('header', 'N/A'),
                    'Description': vuln['description'],
                    'Impact': self._get_vulnerability_impact(vuln['severity']),
                    'Remediation': self._get_vulnerability_remediation(vuln)
                })
        
        vulnerabilities_df = pd.DataFrame(vulnerabilities_data) if vulnerabilities_data else pd.DataFrame({
            'Severity': ['NONE'],
            'Type': ['No Vulnerabilities'],
            'Header': ['N/A'],
            'Description': ['No security vulnerabilities found'],
            'Impact': ['None'],
            'Remediation': ['No action required']
        })
        
        # Write all sections to CSV
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow(['=' * 80])
            writer.writerow(['Security Header Analysis Report - Generated by ChSecurityHeaderAnalyzer'])
            writer.writerow([f'Scan Date: {analysis["scan_date"]}'])
            writer.writerow(['=' * 80])
            writer.writerow([])
            
            # 1. EXECUTIVE SUMMARY
            writer.writerow(['SECTION 1: EXECUTIVE SUMMARY'])
            writer.writerow(['=' * 60])
            for metric, value in zip(summary_data['Metric'], summary_data['Value']):
                writer.writerow([metric, value])
            writer.writerow([])
            
            # 2. SCORE BREAKDOWN
            writer.writerow(['SECTION 2: SECURITY SCORE BREAKDOWN'])
            writer.writerow(['=' * 60])
            if 'score_breakdown' in analysis:
                writer.writerow(['Component', 'Count/Details'])
                writer.writerow(['-' * 60])
                for key, value in analysis['score_breakdown'].items():
                    writer.writerow([key.replace('_', ' ').title(), str(value)])
            writer.writerow([])
            
            # 3. HEADERS ANALYSIS
            writer.writerow(['SECTION 3: HEADERS ANALYSIS'])
            writer.writerow(['=' * 60])
            writer.writerow(['Header', 'Category', 'Status', 'Risk Level', 'Value', 'Recommendation'])
            writer.writerow(['-' * 60])
            for _, row in headers_df.iterrows():
                writer.writerow([
                    row['Header'],
                    row['Category'],
                    row['Status'],
                    row['Risk Level'],
                    str(row['Value'])[:100],
                    row['Recommendation']
                ])
            writer.writerow([])
            
            # 4. VULNERABILITIES
            writer.writerow(['SECTION 4: VULNERABILITIES'])
            writer.writerow(['=' * 60])
            if vulnerabilities_data:
                writer.writerow(['Severity', 'Type', 'Header', 'Description', 'Impact', 'Remediation'])
                writer.writerow(['-' * 60])
                for _, row in vulnerabilities_df.iterrows():
                    writer.writerow([
                        row['Severity'], row['Type'], row['Header'],
                        row['Description'], row['Impact'], row['Remediation']
                    ])
            else:
                writer.writerow(['No vulnerabilities found'])
            writer.writerow([])
            
            # 5. RECOMMENDATIONS
            writer.writerow(['SECTION 5: RECOMMENDATIONS'])
            writer.writerow(['=' * 60])
            if analysis['recommendations']:
                for i, rec in enumerate(analysis['recommendations'], 1):
                    writer.writerow([f"{i}. {rec}"])
            else:
                writer.writerow(['No recommendations needed'])
            writer.writerow([])
            
            # 6. IMPROVEMENT SUMMARY
            writer.writerow(['SECTION 6: IMPROVEMENT SUMMARY'])
            writer.writerow(['=' * 60])
            improvement = self._get_improvement_summary(analysis)
            writer.writerow(['Current Score:', f"{analysis['security_score']}/100"])
            writer.writerow(['Current Grade:', analysis['grade']])
            writer.writerow(['Potential Score:', f"{improvement['potential_score']}/100"])
            writer.writerow(['Key Areas:', improvement['key_areas']])
            writer.writerow([])
            
            # Footer
            writer.writerow(['=' * 80])
            writer.writerow(['END OF REPORT'])
            writer.writerow(['=' * 80])
        
        return filepath

    def _get_header_recommendation(self, header: str, status: str, value: str) -> str:
        """Get recommendation for a specific header"""
        if status == 'Missing':
            if header in self.config['security_headers']['required']:
                return f'IMPLEMENT: Add {header} header with secure configuration'
            elif header in self.config['security_headers']['recommended']:
                return f'RECOMMENDED: Consider adding {header} header'
            else:
                return 'No action required'
        elif status == 'Present':
            if header in self.config['security_headers'].get('deprecated', []):
                return f'WARNING: {header} is deprecated, consider upgrading'
            elif header in self.config['security_headers'].get('vulnerable', []):
                return f'WARNING: {header} may leak sensitive information'
            elif header in self.config['security_headers'].get('infrastructure', []):
                return 'INFO: Infrastructure header, typically acceptable'
        return 'Configuration appears adequate'

    def _get_vulnerability_impact(self, severity: str) -> str:
        """Get impact description for vulnerability severity"""
        impacts = {
            'critical': 'Critical - Immediate compromise possible',
            'high': 'High - Significant security risk',
            'medium': 'Medium - Moderate security risk',
            'low': 'Low - Minor security concern'
        }
        return impacts.get(severity.lower(), 'Unknown impact')

    def _get_vulnerability_remediation(self, vulnerability: Dict[str, Any]) -> str:
        """Get remediation steps for a vulnerability"""
        vuln_type = vulnerability['type']
        
        if vuln_type.startswith('missing_'):
            return f"Implement the {vulnerability.get('header')} header with secure directives"
        elif 'hsts' in vuln_type:
            return "Increase HSTS max-age to at least 31536000 seconds (1 year)"
        elif 'csp' in vuln_type:
            return "Remove unsafe-inline and unsafe-eval from CSP directives"
        elif 'information_disclosure' in vuln_type:
            return f"Remove or obfuscate the {vulnerability.get('header')} header"
        elif 'deprecated' in vuln_type:
            return f"Replace {vulnerability.get('header')} with modern alternative"
        elif 'infrastructure' in vuln_type:
            return "No action required (infrastructure header)"
        else:
            return "Review and fix the header configuration"

    def _get_improvement_summary(self, analysis: Dict[str, Any]) -> Dict[str, str]:
        """Get improvement summary for the report"""
        missing_count = self._get_total_missing(analysis)
        vuln_count = len(analysis.get('vulnerabilities', []))
        
        # Calculate potential score if all issues were fixed
        potential_score = min(100, analysis['security_score'] + (missing_count * 5) + (vuln_count * 3))
        
        # Identify key areas for improvement
        key_areas = []
        if analysis.get('missing_required'):
            key_areas.append(f"Add {len(analysis['missing_required'])} missing required headers")
        if analysis.get('missing_recommended'):
            key_areas.append(f"Consider {len(analysis['missing_recommended'])} recommended headers")
        if analysis.get('deprecated_found'):
            key_areas.append("Replace deprecated headers")
        if vuln_count > 0:
            key_areas.append(f"Fix {vuln_count} vulnerabilities")
        if analysis.get('cookie_analysis'):
            insecure_cookies = sum(1 for c in analysis['cookie_analysis'] if c.get('issues'))
            if insecure_cookies > 0:
                key_areas.append(f"Secure {insecure_cookies} cookies")
        
        if not key_areas:
            key_areas = ["No significant improvements needed"]
        
        return {
            'potential_score': potential_score,
            'key_areas': ', '.join(key_areas[:3]) + ('...' if len(key_areas) > 3 else '')
        }

    def _get_estimated_implementation_time(self, critical_count: int, high_count: int) -> str:
        """Get estimated implementation time for recommendations"""
        total_time = (critical_count * 2) + (high_count * 4)
        if total_time <= 4:
            return "2-4 hours"
        elif total_time <= 8:
            return "1 business day"
        elif total_time <= 16:
            return "2-3 business days"
        else:
            return "1 week or more"

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

    def _calculate_potential_grade(self, score: int) -> str:
        """Calculate potential grade based on score"""
        if score >= 85:
            return 'A (Excellent)'
        elif score >= 70:
            return 'B (Good)'
        elif score >= 55:
            return 'C (Fair)'
        elif score >= 35:
            return 'D (Poor)'
        else:
            return 'F (Critical)'

    # ====== HTML Report Generation ======
    def _generate_html_report(self, analysis: Dict[str, Any], filename_base: str) -> str:
        """Generate HTML report"""
        filepath = os.path.join(self.output_dir, f"{filename_base}.html")
        
        total_missing = self._get_total_missing(analysis)
        all_missing = self._get_all_missing_headers(analysis)
        
        grade_class = f"grade-{analysis['grade'].lower()}"
        grade_display = f"{analysis['grade']} - {self._get_grade_text(analysis['grade'])}"
        
        # Count vulnerabilities by severity (excluding info)
        vuln_count = {
            'critical': sum(1 for v in analysis['vulnerabilities'] if v['severity'] == 'critical'),
            'high': sum(1 for v in analysis['vulnerabilities'] if v['severity'] == 'high'),
            'medium': sum(1 for v in analysis['vulnerabilities'] if v['severity'] == 'medium'),
            'low': sum(1 for v in analysis['vulnerabilities'] if v['severity'] == 'low'),
        }
        total_vulns = sum(vuln_count.values())
        
        headers_rows = self._prepare_headers_rows_html(analysis)
        vulnerabilities_rows = self._prepare_vulnerabilities_rows_html(analysis)
        recommendations_list = self._prepare_recommendations_html(analysis)
        raw_headers = {k: v for k, v in analysis['headers_found'].items() if not k.startswith('_')}
        improvement = self._get_improvement_summary(analysis)
        
        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ch4120N Security Header Analysis Report</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root{{--primary-color:#2c3e50;--secondary-color:#3498db;--success-color:#27ae60;--warning-color:#f39c12;--danger-color:#e74c3c;--dark-color:#2c3e50;--light-color:#ecf0f1;--border-radius:10px;--box-shadow:0 4px 12px rgba(0,0,0,0.1);--transition:all 0.3s ease}}
        *{{margin:0;padding:0;box-sizing:border-box}}
        body{{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;line-height:1.6;color:#333;background:linear-gradient(135deg,#f5f7fa 0%,#c3cfe2 100%);min-height:100vh;padding:20px}}
        .container{{max-width:1200px;margin:0 auto}}
        .header{{background:linear-gradient(135deg,var(--primary-color) 0%,#1a252f 100%);color:#fff;padding:30px;border-radius:var(--border-radius);margin-bottom:30px;box-shadow:var(--box-shadow)}}
        .header h1{{font-size:2.5rem;margin-bottom:10px}}
        .summary-cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px;margin-bottom:30px}}
        .card{{background:#fff;border-radius:var(--border-radius);padding:25px;box-shadow:var(--box-shadow);transition:var(--transition)}}
        .card:hover{{transform:translateY(-5px);box-shadow:0 8px 20px rgba(0,0,0,0.15)}}
        .score{{font-size:4rem;font-weight:800;margin:20px 0;text-align:center}}
        .grade{{display:inline-block;padding:8px 25px;border-radius:50px;font-weight:700;font-size:1.5rem}}
        .grade-a{{background-color:#d5f4e6;color:var(--success-color)}}
        .grade-b{{background-color:#fff3cd;color:#e6a700}}
        .grade-c{{background-color:#ffeaa7;color:#e67e22}}
        .grade-d{{background-color:#fadbd8;color:#e74c3c}}
        .grade-f{{background-color:var(--danger-color);color:#fff}}
        .section{{background:#fff;border-radius:var(--border-radius);padding:30px;margin-bottom:30px;box-shadow:var(--box-shadow)}}
        .section h2{{color:var(--primary-color);margin-bottom:25px;border-left:5px solid var(--secondary-color);padding-left:15px}}
        table{{width:100%;border-collapse:collapse;margin:15px 0}}
        th{{background-color:var(--primary-color);color:#fff;padding:15px;text-align:left}}
        td{{padding:12px 15px;border-bottom:1px solid #eee}}
        tr:hover{{background-color:#f9f9f9}}
        .present{{background-color:#d5f4e6;color:var(--success-color);padding:5px 12px;border-radius:20px;font-weight:600}}
        .missing{{background-color:#fadbd8;color:var(--danger-color);padding:5px 12px;border-radius:20px;font-weight:600}}
        .vuln-critical{{background-color:#e74c3c;color:#fff;padding:5px 12px;border-radius:20px;font-weight:600}}
        .vuln-high{{background-color:#fadbd8;color:var(--danger-color);padding:5px 12px;border-radius:20px;font-weight:600}}
        .vuln-medium{{background-color:#ffeaa7;color:#e67e22;padding:5px 12px;border-radius:20px;font-weight:600}}
        .vuln-low{{background-color:#fff3cd;color:#f39c12;padding:5px 12px;border-radius:20px;font-weight:600}}
        .recommendation-list li{{background:#f8f9fa;padding:15px;border-radius:8px;margin-bottom:10px;border-left:4px solid var(--secondary-color);list-style:none}}
        .priority-critical{{border-left-color:#e74c3c;background:#fdf2f2}}
        .priority-high{{border-left-color:#f39c12;background:#fff8e6}}
        .priority-medium{{border-left-color:#3498db;background:#f0f8ff}}
        .priority-low{{border-left-color:#27ae60;background:#f2f9f5}}
        pre{{background-color:#2c3e50;color:#ecf0f1;padding:20px;border-radius:var(--border-radius);overflow-x:auto}}
        .footer{{text-align:center;margin-top:40px;padding:20px;color:#95a5a6}}
        @media(max-width:768px){{.header h1{{font-size:2rem}}.summary-cards{{grid-template-columns:1fr}}table{{display:block;overflow-x:auto}}}}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> Ch4120N Security Header Analysis Report</h1>
            <p><i class="far fa-calendar-alt"></i> Generated: {analysis['scan_date']}</p>
        </div>
        
        <div class="summary-cards">
            <div class="card" style="text-align:center">
                <h3><i class="fas fa-chart-line"></i> Security Score</h3>
                <div class="score">{analysis['security_score']}/100</div>
                <div class="grade {grade_class}">{grade_display}</div>
            </div>
            <div class="card">
                <h3><i class="fas fa-globe"></i> Target</h3>
                <p style="word-break:break-all"><i class="fas fa-link"></i> {analysis['url']}</p>
                <div style="margin-top:15px;padding:15px;background:#f8f9fa;border-radius:8px">
                    <p><strong>Headers Analyzed:</strong> {len(analysis['headers_found'])}</p>
                    <p><strong>Missing Required:</strong> {len(analysis.get('missing_required', []))}</p>
                    <p><strong>Missing Recommended:</strong> {len(analysis.get('missing_recommended', []))}</p>
                    <p><strong>Vulnerabilities:</strong> {total_vulns}</p>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2><i class="fas fa-search"></i> Headers Analysis</h2>
            <table>
                <thead><tr><th>Header</th><th>Status</th><th>Value</th></tr></thead>
                <tbody>{headers_rows}</tbody>
            </table>
        </div>
        
        <div class="section">
            <h2><i class="fas fa-exclamation-triangle"></i> Vulnerabilities ({total_vulns})</h2>
            {'<table><thead><tr><th>Severity</th><th>Description</th></tr></thead><tbody>' + vulnerabilities_rows + '</tbody></table>' if vulnerabilities_rows else '<p style="color:var(--success-color)"><i class="fas fa-check-circle"></i> No vulnerabilities found!</p>'}
        </div>
        
        <div class="section">
            <h2><i class="fas fa-lightbulb"></i> Recommendations ({len(analysis['recommendations'])})</h2>
            <div class="recommendation-list">{recommendations_list}</div>
        </div>
        
        <div class="section">
            <h2><i class="fas fa-rocket"></i> Improvement Summary</h2>
            <p><strong>Current:</strong> {analysis['security_score']}/100 ({analysis['grade']})</p>
            <p><strong>Potential:</strong> {improvement['potential_score']}/100</p>
            <p><strong>Key Areas:</strong> {improvement['key_areas']}</p>
        </div>
        
        <div class="section">
            <h2><i class="fas fa-code"></i> Raw Headers</h2>
            <pre>{json.dumps(raw_headers, indent=2, default=str)}</pre>
        </div>
        
        <div class="footer">
            <p>Report generated by Ch4120N Security Header Analyzer v2.0.0</p>
        </div>
    </div>
</body>
</html>"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_template)
        
        return filepath

    def _prepare_headers_rows_html(self, analysis: Dict[str, Any]) -> str:
        """Prepare HTML rows for headers table"""
        rows = []
        required = self.config['security_headers']['required']
        recommended = self.config['security_headers']['recommended']
        
        for header in required + recommended:
            present = header.lower() in analysis['headers_found']
            status_html = '<span class="present"><i class="fas fa-check-circle"></i> Present</span>' if present else '<span class="missing"><i class="fas fa-times-circle"></i> Missing</span>'
            value = analysis['headers_found'].get(header.lower(), '')[:80] if present else '<span style="color:var(--danger-color)">Not implemented</span>'
            rows.append(f'<tr><td><strong>{header}</strong></td><td>{status_html}</td><td>{value}</td></tr>')
        
        return '\n'.join(rows)

    def _prepare_vulnerabilities_rows_html(self, analysis: Dict[str, Any]) -> str:
        """Prepare HTML rows for vulnerabilities (excluding info)"""
        rows = []
        for vuln in analysis['vulnerabilities']:
            if vuln['severity'] == 'info':
                continue
            severity_class = f"vuln-{vuln['severity']}"
            rows.append(f'<tr><td><span class="{severity_class}">{vuln["severity"].upper()}</span></td><td>{vuln["description"]}</td></tr>')
        return '\n'.join(rows)

    def _prepare_recommendations_html(self, analysis: Dict[str, Any]) -> str:
        """Prepare HTML list for recommendations with priority"""
        if not analysis['recommendations']:
            return '<p>No recommendations needed.</p>'
        
        items = []
        for rec in analysis['recommendations']:
            if rec.startswith('CRITICAL:'):
                cls = 'priority-critical'
                clean = rec.replace('CRITICAL:', '').strip()
            elif rec.startswith('HIGH:'):
                cls = 'priority-high'
                clean = rec.replace('HIGH:', '').strip()
            elif rec.startswith('MEDIUM:'):
                cls = 'priority-medium'
                clean = rec.replace('MEDIUM:', '').strip()
            else:
                cls = 'priority-low'
                clean = rec
            items.append(f'<li class="{cls}">{clean}</li>')
        
        return '\n'.join(items)

    # ====== Combined Reports (simplified) ======
    def _generate_combined_txt(self, analyses: List[Dict[str, Any]], filename_base: str) -> str:
        filepath = os.path.join(self.output_dir, f"{filename_base}.txt")
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\nCOMBINED SECURITY HEADER ANALYSIS REPORT\n" + "=" * 60 + "\n\n")
            f.write(f"Total Websites: {len(analyses)}\n")
            f.write(f"Report Date: {datetime.now().isoformat()}\n\n")
            f.write(f"{'URL':<40} {'Score':<6} {'Grade':<6}\n" + "-" * 60 + "\n")
            for a in analyses:
                url = a['url'][:38] + '..' if len(a['url']) > 40 else a['url']
                f.write(f"{url:<40} {a['security_score']:<6} {a['grade']:<6}\n")
        return filepath

    def _generate_combined_json(self, analyses: List[Dict[str, Any]], filename_base: str) -> str:
        filepath = os.path.join(self.output_dir, f"{filename_base}.json")
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump({
                'report_date': datetime.now().isoformat(),
                'total_websites': len(analyses),
                'analyses': analyses,
                'statistics': self._calculate_statistics(analyses)
            }, f, indent=2, default=str)
        return filepath

    def _generate_combined_csv(self, analyses: List[Dict[str, Any]], filename_base: str) -> str:
        filepath = os.path.join(self.output_dir, f"{filename_base}.csv")
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['COMBINED SECURITY HEADER ANALYSIS REPORT'])
            writer.writerow([f'Total Websites: {len(analyses)}'])
            writer.writerow([])
            writer.writerow(['URL', 'Score', 'Grade', 'Missing Required', 'Missing Recommended', 'Vulnerabilities'])
            for a in sorted(analyses, key=lambda x: x['security_score'], reverse=True):
                writer.writerow([
                    a['url'],
                    a['security_score'],
                    a['grade'],
                    len(a.get('missing_required', [])),
                    len(a.get('missing_recommended', [])),
                    len(a['vulnerabilities'])
                ])
        return filepath

    def _generate_combined_html(self, analyses: List[Dict[str, Any]], filename_base: str) -> str:
        filepath = os.path.join(self.output_dir, f"{filename_base}.html")
        stats = self._calculate_statistics(analyses)
        
        rows = []
        for a in analyses:
            grade_class = f"grade-{a['grade'].lower()}"
            rows.append(f'<tr class="{grade_class}"><td>{a["url"][:60]}</td><td>{a["security_score"]}</td><td>{a["grade"]}</td><td>{len(a.get("missing_required",[]))}</td><td>{len(a["vulnerabilities"])}</td></tr>')
        
        html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Combined Report</title>
        <style>body{{font-family:sans-serif;padding:20px;background:#f5f7fa}}
        table{{width:100%;border-collapse:collapse;background:#fff}}
        th{{background:#2c3e50;color:#fff;padding:12px}}
        td{{padding:10px;border-bottom:1px solid #eee}}
        .grade-a{{background:#d5f4e6}}.grade-b{{background:#fff3cd}}.grade-c{{background:#ffeaa7}}.grade-d{{background:#fadbd8}}.grade-f{{background:#e74c3c;color:#fff}}
        </style></head><body><h1>Combined Security Report</h1><p>Total: {len(analyses)} websites | Average Score: {stats['average_score']:.1f}</p>
        <table><thead><tr><th>URL</th><th>Score</th><th>Grade</th><th>Missing Required</th><th>Vulnerabilities</th></tr></thead><tbody>{''.join(rows)}</tbody></table></body></html>"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        return filepath

    def _calculate_statistics(self, analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not analyses:
            return {}
        stats = {
            'average_score': sum(a['security_score'] for a in analyses) / len(analyses),
            'grade_distribution': {},
            'total_missing_required': sum(len(a.get('missing_required', [])) for a in analyses),
            'total_vulnerabilities': sum(len(a['vulnerabilities']) for a in analyses)
        }
        for a in analyses:
            stats['grade_distribution'][a['grade']] = stats['grade_distribution'].get(a['grade'], 0) + 1
        return stats