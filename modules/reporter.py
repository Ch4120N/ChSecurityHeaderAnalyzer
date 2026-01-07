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
        origin = cors_analysis.get('access_control_allow_origin', 'Not set')
        credentials = cors_analysis.get('access_control_allow_credentials', 'Not set')
        
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
            checks.append(f"Server: {banner.get('disclosure', 'unknown')} disclosure")
        
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
        """Generate comprehensive CSV report"""
        filepath = os.path.join(self.output_dir, f"{filename_base}.csv")
        
        # Prepare data for CSV with multiple sheets (using pandas)
        import pandas as pd
        
        # 1. Summary Sheet
        summary_data = {
            'Metric': [
                'URL',
                'Scan Date',
                'Security Score',
                'Security Grade',
                'Total Headers Found',
                'Missing Required Headers',
                'Weak Headers',
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
                len(analysis['missing_headers']),
                len(analysis['weak_headers']),
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
        vulnerable_headers = self.config['security_headers']['vulnerable_headers']
        
        headers_data = []
        for header in required_headers + recommended_headers + vulnerable_headers:
            header_lower = header.lower()
            status = 'Present' if header_lower in analysis['headers_found'] else 'Missing'
            
            if header_lower in analysis['headers_found']:
                value = analysis['headers_found'][header_lower]
                # Truncate long values
                if len(value) > 200:
                    value = value[:197] + '...'
            else:
                value = ''
            
            category = 'Required' if header in required_headers else \
                    'Recommended' if header in recommended_headers else \
                    'Vulnerable' if header in vulnerable_headers else 'Other'
            
            risk_level = 'High' if header in required_headers and status == 'Missing' else \
                        'Medium' if header in recommended_headers and status == 'Missing' else \
                        'Low' if header in vulnerable_headers and status == 'Present' else 'None'
            
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
        
        # 4. Detailed Header Analysis Sheet
        detailed_headers_data = []
        for header, value in analysis['headers_found'].items():
            if header.startswith('_'):
                continue
            
            header_type = 'Security' if header in [h.lower() for h in required_headers + recommended_headers] else \
                        'Informational' if header in ['server', 'date', 'content-type'] else \
                        'Other'
            
            # Check for security issues
            security_issue = ''
            if header == 'strict-transport-security':
                if 'max-age=' in value.lower():
                    import re
                    match = re.search(r'max-age=(\d+)', value.lower())
                    if match and int(match.group(1)) < 31536000:
                        security_issue = 'HSTS max-age too low'
            
            detailed_headers_data.append({
                'Header Name': header,
                'Header Type': header_type,
                'Value': value[:500],  # Limit value length
                'Security Issue': security_issue,
                'Risk': 'High' if header in ['server', 'x-powered-by'] and value != '' else \
                    'Medium' if security_issue else 'Low'
            })
        
        detailed_headers_df = pd.DataFrame(detailed_headers_data)
        
        # 5. Recommendations Sheet
        recommendations_data = []
        for i, rec in enumerate(analysis['recommendations'], 1):
            priority = 'High' if any(word in rec.lower() for word in ['critical', 'missing required', 'immediate']) else \
                    'Medium' if any(word in rec.lower() for word in ['strengthen', 'weak', 'consider']) else 'Low'
            
            category = 'Missing Header' if 'missing header' in rec.lower() else \
                    'Configuration' if 'configuration' in rec.lower() or 'strengthen' in rec.lower() else \
                    'Information Disclosure' if 'remove' in rec.lower() or 'obfuscate' in rec.lower() else \
                    'Enhancement'
            
            recommendations_data.append({
                'Priority': priority,
                'Category': category,
                'Recommendation': rec,
                'Estimated Effort': self._get_estimated_effort(priority, category),
                'Timeline': self._get_recommendation_timeline(priority)
            })
        
        recommendations_df = pd.DataFrame(recommendations_data) if recommendations_data else pd.DataFrame({
            'Priority': ['NONE'],
            'Category': ['No Recommendations'],
            'Recommendation': ['All security headers are properly configured'],
            'Estimated Effort': ['N/A'],
            'Timeline': ['N/A']
        })
        
        # 6. Risk Assessment Sheet
        risk_data = {
            'Risk Category': [
                'Missing Required Headers',
                'Weak Security Configurations',
                'Information Disclosure',
                'Deprecated Headers',
                'Misconfigured Headers'
            ],
            'Risk Level': [
                'High' if len(analysis['missing_headers']) > 0 else 'Low',
                'High' if len(analysis['weak_headers']) > 0 else 'Low',
                'Medium' if any(h in [vh.lower() for vh in vulnerable_headers] 
                            for h in analysis['headers_found']) else 'Low',
                'Low',  # Placeholder - could be enhanced
                'Medium' if any('weak' in v.get('type', '') for v in analysis['vulnerabilities']) else 'Low'
            ],
            'Count': [
                len(analysis['missing_headers']),
                len(analysis['weak_headers']),
                sum(1 for h in analysis['headers_found'] 
                    if h in [vh.lower() for vh in vulnerable_headers]),
                0,  # Placeholder
                sum(1 for v in analysis['vulnerabilities'] if 'weak' in v.get('type', ''))
            ],
            'Description': [
                f'Missing {len(analysis["missing_headers"])} required security headers',
                f'{len(analysis["weak_headers"])} headers have weak configurations',
                'Server information exposed through headers',
                'No deprecated headers detected',
                'Some headers may be misconfigured'
            ]
        }
        
        risk_df = pd.DataFrame(risk_data)
        
        # 7. Compliance Sheet (Industry Standards)
        compliance_data = {
            'Standard': [
                'OWASP Top 10',
                'CIS Controls',
                'PCI DSS',
                'GDPR',
                'ISO 27001'
            ],
            'Requirement': [
                'Security Headers Implementation',
                'Secure Configuration',
                'Protect Cardholder Data',
                'Data Protection by Design',
                'Information Security Controls'
            ],
            'Compliance Status': [
                'Compliant' if analysis['security_score'] >= 80 else 'Partially Compliant',
                'Compliant' if analysis['security_score'] >= 70 else 'Partially Compliant',
                'Compliant' if len(analysis['missing_headers']) == 0 else 'Non-Compliant',
                'Compliant' if analysis['security_score'] >= 60 else 'Partially Compliant',
                'Compliant' if analysis['security_score'] >= 75 else 'Partially Compliant'
            ],
            'Notes': [
                f'Score: {analysis["security_score"]}/100',
                f'Missing headers: {len(analysis["missing_headers"])}',
                'Requires all security headers',
                'Adequate security measures',
                'Security controls assessment'
            ]
        }
        
        compliance_df = pd.DataFrame(compliance_data)
        
        # Write all sheets to a single CSV with clear separation
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header with tool info
            writer.writerow(['=' * 80])
            writer.writerow(['Security Header Analysis Report - Generated by ChSecurityHeaderAnalyzer'])
            writer.writerow([f'Scan Date: {analysis["scan_date"]}'])
            writer.writerow(['=' * 80])
            writer.writerow([])
            
            # 1. SUMMARY SECTION
            writer.writerow(['SECTION 1: EXECUTIVE SUMMARY'])
            writer.writerow(['=' * 60])
            for metric, value in zip(summary_data['Metric'], summary_data['Value']):
                writer.writerow([metric, value])
            writer.writerow([])
            
            # 2. SECURITY SCORE BREAKDOWN
            writer.writerow(['SECTION 2: SECURITY SCORE BREAKDOWN'])
            writer.writerow(['=' * 60])
            writer.writerow(['Component', 'Max Points', 'Score', 'Percentage'])
            
            components = [
                ('Required Headers', 60, max(0, 60 - (len(analysis['missing_headers']) * 10))),
                ('Header Security', 20, max(0, 20 - (len(analysis['weak_headers']) * 5))),
                ('Information Disclosure', 10, max(0, 10 - (sum(1 for v in analysis['vulnerabilities'] 
                                                            if v['severity'] in ['high', 'critical']) * 5))),
                ('Best Practices', 10, max(0, 10 - (sum(1 for v in analysis['vulnerabilities'] 
                                                        if v['severity'] in ['medium', 'low']) * 3)))
            ]
            
            for component, max_points, score in components:
                percentage = (score / max_points * 100) if max_points > 0 else 0
                writer.writerow([component, max_points, score, f'{percentage:.1f}%'])
            
            writer.writerow(['-' * 60])
            writer.writerow(['TOTAL SCORE', 100, analysis['security_score'], 
                            f'{analysis["security_score"]}%'])
            writer.writerow(['SECURITY GRADE', '', analysis['grade'], 
                            self._get_grade_description(analysis['grade'])])
            writer.writerow([])
            
            # 3. HEADERS ANALYSIS
            writer.writerow(['SECTION 3: HEADERS ANALYSIS'])
            writer.writerow(['=' * 60])
            writer.writerow(['Header', 'Category', 'Status', 'Risk Level', 'Value (truncated)', 'Recommendation'])
            writer.writerow(['-' * 60])
            
            for _, row in headers_df.iterrows():
                writer.writerow([
                    row['Header'],
                    row['Category'],
                    row['Status'],
                    row['Risk Level'],
                    str(row['Value'])[:100] + ('...' if len(str(row['Value'])) > 100 else ''),
                    row['Recommendation']
                ])
            writer.writerow([])
            
            # 4. VULNERABILITIES DETAILED
            writer.writerow(['SECTION 4: VULNERABILITIES DETAILED'])
            writer.writerow(['=' * 60])
            if vulnerabilities_data:
                writer.writerow(['Severity', 'Type', 'Affected Header', 'Description', 'Impact', 'Remediation'])
                writer.writerow(['-' * 60])
                for _, row in vulnerabilities_df.iterrows():
                    writer.writerow([
                        row['Severity'],
                        row['Type'],
                        row['Header'],
                        row['Description'],
                        row['Impact'],
                        row['Remediation']
                    ])
            else:
                writer.writerow(['No vulnerabilities found - Excellent security configuration'])
            writer.writerow([])
            
            # 5. PRIORITIZED RECOMMENDATIONS
            writer.writerow(['SECTION 5: PRIORITIZED RECOMMENDATIONS'])
            writer.writerow(['=' * 60])
            if recommendations_data:
                # Sort by priority
                recommendations_df_sorted = recommendations_df.sort_values(
                    by='Priority', 
                    key=lambda x: x.map({'High': 1, 'Medium': 2, 'Low': 3})
                )
                
                writer.writerow(['Priority', 'Category', 'Recommendation', 'Estimated Effort', 'Timeline'])
                writer.writerow(['-' * 60])
                for _, row in recommendations_df_sorted.iterrows():
                    writer.writerow([
                        row['Priority'],
                        row['Category'],
                        row['Recommendation'],
                        row['Estimated Effort'],
                        row['Timeline']
                    ])
            else:
                writer.writerow(['No recommendations needed - All configurations are optimal'])
            writer.writerow([])
            
            # 6. RISK ASSESSMENT MATRIX
            writer.writerow(['SECTION 6: RISK ASSESSMENT MATRIX'])
            writer.writerow(['=' * 60])
            writer.writerow(['Risk Category', 'Risk Level', 'Count', 'Description'])
            writer.writerow(['-' * 60])
            for _, row in risk_df.iterrows():
                writer.writerow([row['Risk Category'], row['Risk Level'], row['Count'], row['Description']])
            writer.writerow([])
            
            # 7. COMPLIANCE STATUS
            writer.writerow(['SECTION 7: COMPLIANCE STATUS'])
            writer.writerow(['=' * 60])
            writer.writerow(['Standard', 'Requirement', 'Compliance Status', 'Notes'])
            writer.writerow(['-' * 60])
            for _, row in compliance_df.iterrows():
                writer.writerow([row['Standard'], row['Requirement'], row['Compliance Status'], row['Notes']])
            writer.writerow([])
            
            # 8. TECHNICAL DETAILS
            writer.writerow(['SECTION 8: TECHNICAL DETAILS'])
            writer.writerow(['=' * 60])
            writer.writerow(['Header Name', 'Header Type', 'Value', 'Security Issue', 'Risk'])
            writer.writerow(['-' * 60])
            for _, row in detailed_headers_df.iterrows():
                writer.writerow([
                    row['Header Name'],
                    row['Header Type'],
                    str(row['Value'])[:150] + ('...' if len(str(row['Value'])) > 150 else ''),
                    row['Security Issue'],
                    row['Risk']
                ])
            writer.writerow([])
            
            # 9. ACTION PLAN
            writer.writerow(['SECTION 9: ACTION PLAN'])
            writer.writerow(['=' * 60])
            
            # Immediate actions (High priority)
            high_priority = [r for r in analysis['recommendations'] 
                            if any(word in r.lower() for word in ['critical', 'missing required', 'immediate'])]
            
            if high_priority:
                writer.writerow(['IMMEDIATE ACTIONS (Next 24-48 hours):'])
                writer.writerow(['-' * 40])
                for action in high_priority[:5]:  # Limit to top 5
                    writer.writerow([f'• {action}'])
                writer.writerow([])
            
            # Short-term actions
            medium_priority = [r for r in analysis['recommendations'] 
                            if any(word in r.lower() for word in ['strengthen', 'weak', 'consider'])]
            
            if medium_priority:
                writer.writerow(['SHORT-TERM ACTIONS (Next 7 days):'])
                writer.writerow(['-' * 40])
                for action in medium_priority[:5]:
                    writer.writerow([f'• {action}'])
                writer.writerow([])
            
            # Long-term actions
            low_priority = [r for r in analysis['recommendations'] 
                        if r not in high_priority and r not in medium_priority]
            
            if low_priority:
                writer.writerow(['LONG-TERM ACTIONS (Next 30 days):'])
                writer.writerow(['-' * 40])
                for action in low_priority[:5]:
                    writer.writerow([f'• {action}'])
                writer.writerow([])
            
            # 10. SCAN METADATA
            writer.writerow(['SECTION 10: SCAN METADATA'])
            writer.writerow(['=' * 60])
            writer.writerow(['Field', 'Value'])
            writer.writerow(['-' * 60])
            writer.writerow(['Scan Timestamp', analysis['scan_date']])
            writer.writerow(['Tool Version', 'ChSecurityHeaderAnalyzer v1.0.0'])
            writer.writerow(['Tool Owner', 'Ch4120N'])
            writer.writerow(['Generated On', datetime.now().isoformat()])
            writer.writerow(['Report Format', 'CSV'])
            writer.writerow(['Total Sections', '10'])
            writer.writerow(['Report File', filename_base + '.csv'])
            
            # Footer
            writer.writerow([])
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
        else:
            if header == 'Strict-Transport-Security':
                if 'max-age=' in value.lower():
                    import re
                    match = re.search(r'max-age=(\d+)', value.lower())
                    if match:
                        max_age = int(match.group(1))
                        if max_age < 31536000:
                            return f'INCREASE max-age to at least 31536000 (currently {max_age})'
            return 'Configuration appears secure'

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
        
        if vuln_type == 'missing_header':
            return f"Implement the {vulnerability.get('header')} header with secure directives"
        elif vuln_type == 'weak_hsts':
            return "Increase HSTS max-age to at least 31536000 seconds (1 year)"
        elif vuln_type == 'weak_csp':
            return "Remove unsafe-inline and unsafe-eval from CSP directives"
        elif vuln_type == 'information_disclosure':
            return f"Remove or obfuscate the {vulnerability.get('header')} header"
        else:
            return "Review and fix the header configuration"

    def _get_estimated_effort(self, priority: str, category: str) -> str:
        """Get estimated effort for implementing a recommendation"""
        if priority == 'High':
            return 'Low effort (configuration change)'
        elif category == 'Missing Header':
            return 'Medium effort (implementation required)'
        else:
            return 'Low effort'

    def _get_recommendation_timeline(self, priority: str) -> str:
        """Get timeline for implementing a recommendation"""
        if priority == 'High':
            return 'Immediate (24-48 hours)'
        elif priority == 'Medium':
            return 'Short-term (1 week)'
        else:
            return 'Long-term (1 month)'

    def _get_grade_description(self, grade: str) -> str:
        """Get description for security grade"""
        descriptions = {
            'A': 'Excellent - Strong security posture',
            'B': 'Good - Minor improvements needed',
            'C': 'Fair - Several improvements needed',
            'D': 'Poor - Significant improvements required',
            'F': 'Critical - Immediate action required'
        }
        return descriptions.get(grade, 'Unknown')

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
    <title>Ch4120N Security Header Analysis Report</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root{{--primary-color:#2c3e50;--secondary-color:#3498db;--success-color:#27ae60;--warning-color:#f39c12;--danger-color:#e74c3c;--dark-color:#2c3e50;--light-color:#ecf0f1;--gray-color:#95a5a6;--border-radius:10px;--box-shadow:0 4px 12px rgba(0, 0, 0, 0.1);--transition:all 0.3s ease}}
        *{{margin:0;padding:0;box-sizing:border-box}}
        body{{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;line-height:1.6;color:#333;background:linear-gradient(135deg,#f5f7fa 0%,#c3cfe2 100%);min-height:100vh;padding:20px}}
        .container{{max-width:1200px;margin:0 auto}}
        .header{{background:linear-gradient(135deg,var(--primary-color) 0%,#1a252f 100%);color:#fff;padding:30px;border-radius:var(--border-radius);margin-bottom:30px;box-shadow:var(--box-shadow);position:relative;overflow:hidden}}
        .header::before{{content:'';position:absolute;top:-50%;right:-50%;width:200px;height:200px;background:rgb(255 255 255 / .05);border-radius:50%}}
        .header h1{{font-size:2.5rem;margin-bottom:10px;display:flex;align-items:center;gap:15px}}
        .header h1 i{{color:var(--secondary-color)}}
        .header p{{font-size:1.1rem;opacity:.9}}
        .summary-cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px;margin-bottom:30px}}
        .card{{background:#fff;border-radius:var(--border-radius);padding:25px;box-shadow:var(--box-shadow);transition:var(--transition)}}
        .card:hover{{transform:translateY(-5px);box-shadow:0 8px 20px rgb(0 0 0 / .15)}}
        .card h3{{color:var(--primary-color);margin-bottom:15px;font-size:1.3rem;border-bottom:2px solid var(--light-color);padding-bottom:10px;display:flex;align-items:center;gap:10px}}
        .score-card{{text-align:center;background:linear-gradient(135deg,#fff 0%,#f8f9fa 100%)}}
        .score{{font-size:4rem;font-weight:800;margin:20px 0}}
        .grade{{display:inline-block;padding:8px 25px;border-radius:50px;font-weight:700;font-size:1.5rem;letter-spacing:1px}}
        .grade-a{{background-color:#d5f4e6;color:var(--success-color)}}
        .grade-b{{background-color:#fff3cd;color:#e6a700}}
        .grade-c{{background-color:#ffeaa7;color:#e67e22}}
        .grade-d{{background-color:#fadbd8;color:#e74c3c}}
        .grade-f{{background-color:var(--danger-color);color:#fff}}
        .section{{background:#fff;border-radius:var(--border-radius);padding:30px;margin-bottom:30px;box-shadow:var(--box-shadow)}}
        .section h2{{color:var(--primary-color);margin-bottom:25px;font-size:1.8rem;border-left:5px solid var(--secondary-color);padding-left:15px;display:flex;align-items:center;gap:12px}}
        table{{width:100%;border-collapse:collapse;margin:15px 0;border-radius:var(--border-radius);overflow:hidden;box-shadow:0 2px 8px rgb(0 0 0 / .05)}}
        th{{background-color:var(--primary-color);color:#fff;font-weight:600;padding:18px 15px;text-align:left}}
        td{{padding:16px 15px;border-bottom:1px solid #eee}}
        tr:hover{{background-color:#f9f9f9}}
        .present,.missing{{font-weight:600;display:inline-flex;align-items:center;gap:8px;padding:6px 15px;border-radius:50px}}
        .present{{background-color:#d5f4e6;color:var(--success-color)}}
        .missing{{background-color:#fadbd8;color:var(--danger-color)}}
        .vuln-high,.vuln-medium,.vuln-low,.vuln-critical{{font-weight:700;display:inline-block;padding:6px 15px;border-radius:50px;text-align:center;min-width:100px}}
        .vuln-critical{{background-color:#f44;color:#fff}}
        .vuln-high{{background-color:#fadbd8;color:var(--danger-color)}}
        .vuln-medium{{background-color:#ffeaa7;color:#e67e22}}
        .vuln-low{{background-color:#fff3cd;color:#f39c12}}
        ul{{padding-left:20px}}
        li{{margin-bottom:12px;padding-left:10px;position:relative}}
        li:before{{content:'→';position:absolute;left:-15px;color:var(--secondary-color);font-weight:700}}
        pre{{background-color:#2c3e50;color:#ecf0f1;padding:20px;border-radius:var(--border-radius);overflow-x:auto;font-family:'Courier New',monospace;font-size:.9rem;line-height:1.5;margin-top:15px;box-shadow:inset 0 2px 10px rgb(0 0 0 / .3)}}
        .status-badge{{display:flex;align-items:center;gap:10px}}
        .footer{{text-align:center;margin-top:40px;padding:20px;color:var(--gray-color);font-size:.9rem;border-top:1px solid #eee}}
        .recommendation-list li{{background:#f8f9fa;padding:15px;border-radius:8px;margin-bottom:10px;border-left:4px solid var(--secondary-color)}}
        @media (max-width:768px){{.header h1{{font-size:2rem}}.summary-cards{{grid-template-columns:1fr}}.score{{font-size:3rem}}table{{display:block;overflow-x:auto}}.section{{padding:20px}}}}
        @keyframes pulse{{0%{{transform:scale(1)}}50%{{transform:scale(1.05)}}100%{{transform:scale(1)}}}}
        .grade-f{{animation:pulse 2s infinite}}

    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> Ch4120N Security Header Analysis Report</h1>
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
            <p><i class="fas fa-info-circle"></i> Report generated by Ch4120N Security Header Analyzer</p>
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
        """Generate comprehensive combined CSV report for multiple analyses"""
        filepath = os.path.join(self.output_dir, f"{filename_base}.csv")
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow(['=' * 100])
            writer.writerow(['COMBINED SECURITY HEADER ANALYSIS REPORT - MULTIPLE WEBSITES'])
            writer.writerow([f'Generated: {datetime.now().isoformat()}'])
            writer.writerow([f'Total Websites Analyzed: {len(analyses)}'])
            writer.writerow(['=' * 100])
            writer.writerow([])
            
            # EXECUTIVE SUMMARY
            writer.writerow(['EXECUTIVE SUMMARY'])
            writer.writerow(['=' * 60])
            
            # Calculate statistics
            avg_score = sum(a['security_score'] for a in analyses) / len(analyses)
            grade_dist = {}
            total_vulnerabilities = 0
            total_missing = 0
            
            for analysis in analyses:
                grade = analysis['grade']
                grade_dist[grade] = grade_dist.get(grade, 0) + 1
                total_vulnerabilities += len(analysis['vulnerabilities'])
                total_missing += len(analysis['missing_headers'])
            
            writer.writerow(['Overall Security Score (Average):', f'{avg_score:.1f}/100'])
            writer.writerow(['Total Vulnerabilities Found:', total_vulnerabilities])
            writer.writerow(['Total Missing Headers:', total_missing])
            writer.writerow(['Grade Distribution:', 
                            ', '.join(f'{grade}: {count}' for grade, count in sorted(grade_dist.items()))])
            writer.writerow([])
            
            # WEBSITE COMPARISON MATRIX
            writer.writerow(['WEBSITE COMPARISON MATRIX'])
            writer.writerow(['=' * 60])
            writer.writerow(['Rank', 'URL', 'Score', 'Grade', 'Missing', 'Vulnerabilities', 'Status'])
            
            # Sort by score (descending)
            sorted_analyses = sorted(analyses, key=lambda x: x['security_score'], reverse=True)
            
            for i, analysis in enumerate(sorted_analyses, 1):
                status = 'Secure' if analysis['security_score'] >= 80 else \
                        'Needs Improvement' if analysis['security_score'] >= 60 else \
                        'Critical'
                
                writer.writerow([
                    i,
                    analysis['url'][:50] + ('...' if len(analysis['url']) > 50 else ''),
                    analysis['security_score'],
                    analysis['grade'],
                    len(analysis['missing_headers']),
                    len(analysis['vulnerabilities']),
                    status
                ])
            writer.writerow([])
            
            # DETAILED ANALYSIS PER WEBSITE
            writer.writerow(['DETAILED ANALYSIS PER WEBSITE'])
            writer.writerow(['=' * 60])
            
            for i, analysis in enumerate(sorted_analyses, 1):
                writer.writerow([f'Website #{i}: {analysis["url"]}'])
                writer.writerow(['-' * 40])
                writer.writerow(['Score:', analysis['security_score']])
                writer.writerow(['Grade:', analysis['grade']])
                writer.writerow(['Missing Headers:', ', '.join(analysis['missing_headers']) or 'None'])
                
                if analysis['vulnerabilities']:
                    writer.writerow(['Critical Issues:', 
                                    str(sum(1 for v in analysis['vulnerabilities'] if v['severity'] == 'critical'))])
                    writer.writerow(['High Issues:', 
                                    str(sum(1 for v in analysis['vulnerabilities'] if v['severity'] == 'high'))])
                else:
                    writer.writerow(['Vulnerabilities:', 'None'])
                
                writer.writerow([])
            
            # COMMON VULNERABILITIES ACROSS WEBSITES
            writer.writerow(['COMMON VULNERABILITIES ACROSS WEBSITES'])
            writer.writerow(['=' * 60])
            
            # Collect all vulnerabilities
            all_vulnerabilities = []
            for analysis in analyses:
                for vuln in analysis['vulnerabilities']:
                    all_vulnerabilities.append(vuln['description'])
            
            # Count frequency
            from collections import Counter
            vuln_counter = Counter(all_vulnerabilities)
            
            if vuln_counter:
                writer.writerow(['Vulnerability', 'Frequency', 'Affected Websites'])
                writer.writerow(['-' * 60])
                
                for vuln, count in vuln_counter.most_common(10):
                    # Find which websites have this vulnerability
                    affected = []
                    for analysis in analyses:
                        for v in analysis['vulnerabilities']:
                            if v['description'] == vuln:
                                affected.append(analysis['url'][:30] + '...')
                                break
                    
                    writer.writerow([
                        vuln[:80] + ('...' if len(vuln) > 80 else ''),
                        count,
                        ', '.join(affected[:3]) + ('...' if len(affected) > 3 else '')
                    ])
            else:
                writer.writerow(['No common vulnerabilities found across websites'])
            
            writer.writerow([])
            
            # RECOMMENDATIONS SUMMARY
            writer.writerow(['TOP RECOMMENDATIONS ACROSS ALL WEBSITES'])
            writer.writerow(['=' * 60])
            
            all_recommendations = []
            for analysis in analyses:
                all_recommendations.extend(analysis['recommendations'])
            
            rec_counter = Counter(all_recommendations)
            
            if rec_counter:
                writer.writerow(['Priority', 'Recommendation', 'Frequency', 'Affected Websites'])
                writer.writerow(['-' * 60])
                
                for rec, count in rec_counter.most_common(15):
                    # Determine priority
                    priority = 'HIGH' if any(word in rec.lower() for word in 
                                        ['critical', 'missing required', 'immediate']) else \
                            'MEDIUM' if any(word in rec.lower() for word in 
                                            ['strengthen', 'weak', 'consider']) else 'LOW'
                    
                    # Find affected websites
                    affected = []
                    for analysis in analyses:
                        if rec in analysis['recommendations']:
                            affected.append(analysis['url'][:30] + '...')
                    
                    writer.writerow([
                        priority,
                        rec[:100] + ('...' if len(rec) > 100 else ''),
                        count,
                        ', '.join(affected[:3]) + ('...' if len(affected) > 3 else '')
                    ])
            else:
                writer.writerow(['No recommendations needed - All websites are properly configured'])
            
            writer.writerow([])
            
            # SECURITY TRENDS
            writer.writerow(['SECURITY TRENDS ANALYSIS'])
            writer.writerow(['=' * 60])
            
            score_ranges = {
                'Excellent (90-100)': 0,
                'Good (80-89)': 0,
                'Fair (70-79)': 0,
                'Poor (60-69)': 0,
                'Critical (<60)': 0
            }
            
            for analysis in analyses:
                score = analysis['security_score']
                if score >= 90:
                    score_ranges['Excellent (90-100)'] += 1
                elif score >= 80:
                    score_ranges['Good (80-89)'] += 1
                elif score >= 70:
                    score_ranges['Fair (70-79)'] += 1
                elif score >= 60:
                    score_ranges['Poor (60-69)'] += 1
                else:
                    score_ranges['Critical (<60)'] += 1
            
            writer.writerow(['Score Range', 'Count', 'Percentage'])
            writer.writerow(['-' * 60])
            
            total = len(analyses)
            for range_name, count in score_ranges.items():
                percentage = (count / total * 100) if total > 0 else 0
                writer.writerow([range_name, count, f'{percentage:.1f}%'])
            
            writer.writerow([])
            
            # ACTION PLAN FOR IMPROVEMENT
            writer.writerow(['ACTION PLAN FOR IMPROVEMENT'])
            writer.writerow(['=' * 60])
            
            # Group by common issues
            common_missing = {}
            for analysis in analyses:
                for header in analysis['missing_headers']:
                    common_missing[header] = common_missing.get(header, 0) + 1
            
            if common_missing:
                writer.writerow(['MOST COMMON MISSING HEADERS (Prioritize these):'])
                writer.writerow(['Header', 'Frequency', 'Affected %'])
                writer.writerow(['-' * 60])
                
                for header, count in sorted(common_missing.items(), key=lambda x: x[1], reverse=True)[:5]:
                    percentage = (count / total * 100)
                    writer.writerow([header, count, f'{percentage:.1f}%'])
            else:
                writer.writerow(['No common missing headers across websites'])
            
            writer.writerow([])
            
            # Footer
            writer.writerow(['=' * 100])
            writer.writerow(['END OF COMBINED REPORT'])
            writer.writerow(['=' * 100])
        
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
        <title>Combined Ch4120N Security Header Analysis Report</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            :root{{--primary-color:#2c3e50;--secondary-color:#3498db;--success-color:#27ae60;--warning-color:#f39c12;--danger-color:#e74c3c;--dark-color:#2c3e50;--light-color:#ecf0f1;--gray-color:#95a5a6;--border-radius:10px;--box-shadow:0 4px 12px rgba(0, 0, 0, 0.1);--transition:all 0.3s ease}}
            *{{margin:0;padding:0;box-sizing:border-box}}
            body{{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;line-height:1.6;color:#333;background:linear-gradient(135deg,#f5f7fa 0%,#c3cfe2 100%);min-height:100vh;padding:20px}}
            .container{{max-width:1200px;margin:0 auto}}
            .header{{background:linear-gradient(135deg,var(--primary-color) 0%,#1a252f 100%);color:#fff;padding:30px;border-radius:var(--border-radius);margin-bottom:30px;box-shadow:var(--box-shadow);position:relative;overflow:hidden}}
            .header::before{{content:'';position:absolute;top:-50%;right:-50%;width:200px;height:200px;background:rgb(255 255 255 / .05);border-radius:50%}}
            .header h1{{font-size:2.5rem;margin-bottom:10px;display:flex;align-items:center;gap:15px}}
            .header h1 i{{color:var(--secondary-color)}}
            .header p{{font-size:1.1rem;opacity:.9}}
            .stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin:30px 0}}
            .stat-card{{background:#fff;padding:20px;border-radius:var(--border-radius);text-align:center;box-shadow:var(--box-shadow);transition:var(--transition)}}
            .stat-card:hover{{transform:translateY(-5px)}}
            .stat-value{{font-size:2em;font-weight:700;margin:10px 0}}
            table{{width:100%;border-collapse:collapse;margin:20px 0;border-radius:var(--border-radius);overflow:hidden;box-shadow:var(--box-shadow)}}
            th{{background-color:var(--primary-color);color:#fff;font-weight:600;padding:18px 15px;text-align:left}}
            td{{padding:16px 15px;border-bottom:1px solid #eee}}
            tr:hover{{background-color:#f9f9f9}}
            .grade-a{{background-color:#d5f4e6}}
            .grade-b{{background-color:#fff3cd}}
            .grade-c{{background-color:#ffeaa7}}
            .grade-d{{background-color:#fadbd8}}
            .grade-f{{background-color:#f5c6cb}}
            .grade{{display:inline-block;padding:4px 12px;border-radius:50px;font-weight:700;font-size:.9rem}}
            .grade-a .grade{{background-color:#27ae60;color:#fff}}
            .grade-b .grade{{background-color:#f39c12;color:#fff}}
            .grade-c .grade{{background-color:#e67e22;color:#fff}}
            .grade-d .grade{{background-color:#e74c3c;color:#fff}}
            .grade-f .grade{{background-color:#c0392b;color:#fff}}
            .analysis-section{{background:#fff;border-radius:var(--border-radius);padding:20px;margin-bottom:20px;box-shadow:var(--box-shadow)}}
            @media (max-width:768px){{.header h1{{font-size:2rem}}.stats{{grid-template-columns:1fr}}table{{display:block;overflow-x:auto}}}}
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
                <p><i class="fas fa-info-circle"></i> Report generated by Ch4120N Security Header Analyzer</p>
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

