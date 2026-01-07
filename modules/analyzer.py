"""
Header Analysis Module
"""

import re
from typing import Dict, List, Tuple, Any
from datetime import datetime


class HeaderAnalyzer:
    def __init__(self, config: Dict):
        self.config = config
        self.required_headers = config['security_headers']['required']
        self.recommended_headers = config['security_headers']['recommended']
        self.vulnerable_headers = config['security_headers']['vulnerable_headers']
    

    def analyze_headers(self, headers: Dict[str, str], url: str) -> Dict[str, Any]:
        """Analyze headers for security issues"""
        analysis = {
            'url': url,
            'scan_date': datetime.now().isoformat(),
            'headers_found': headers,
            'missing_headers': [],
            'weak_headers': [],
            'vulnerabilities': [],
            'security_score': 100,
            'grade': 'A',
            'recommendations': [],
            'detailed_analysis': {}
        }
        
        # Check for missing required headers
        for header in self.required_headers:
            header_lower = header.lower()
            if header_lower not in headers:
                analysis['missing_headers'].append(header)
                analysis['security_score'] -= 10
                analysis['vulnerabilities'].append({
                    'type': 'missing_header',
                    'header': header,
                    'severity': 'high',
                    'description': f'Missing required security header: {header}'
                })
        
        # Check for vulnerable headers
        for header in self.vulnerable_headers:
            header_lower = header.lower()
            if header_lower in headers:
                analysis['vulnerabilities'].append({
                    'type': 'information_disclosure',
                    'header': header,
                    'value': headers[header_lower],
                    'severity': 'medium',
                    'description': f'Potential information disclosure: {header} reveals {headers[header_lower]}'
                })
                analysis['security_score'] -= 5
        
        # Analyze specific headers
        self._analyze_hsts(headers, analysis)
        self._analyze_csp(headers, analysis)
        self._analyze_x_frame_options(headers, analysis)
        self._analyze_content_type_options(headers, analysis)
        self._analyze_referrer_policy(headers, analysis)
        self._analyze_permissions_policy(headers, analysis)
        
        # Update grade based on score
        analysis['grade'] = self._calculate_grade(analysis['security_score'])
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        return analysis
    
    def _analyze_hsts(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Analyze HSTS header"""
        hsts = headers.get('strict-transport-security')
        if not hsts:
            return
        
        analysis['detailed_analysis']['hsts'] = {
            'header': hsts,
            'max_age': None,
            'include_subdomains': False,
            'preload': False
        }
        
        # Extract max-age
        max_age_match = re.search(r'max-age=(\d+)', hsts)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            analysis['detailed_analysis']['hsts']['max_age'] = max_age
            
            if max_age < self.config['vulnerabilities']['weak_configurations']['hsts']['max_age_minimum']:
                analysis['weak_headers'].append('Strict-Transport-Security')
                analysis['vulnerabilities'].append({
                    'type': 'weak_hsts',
                    'header': 'Strict-Transport-Security',
                    'severity': 'medium',
                    'description': f'HSTS max-age is too low: {max_age} seconds'
                })
                analysis['security_score'] -= 5
        
        # Check for includeSubDomains
        if 'includesubdomains' in hsts.lower():
            analysis['detailed_analysis']['hsts']['include_subdomains'] = True
        
        # Check for preload
        if 'preload' in hsts.lower():
            analysis['detailed_analysis']['hsts']['preload'] = True

    def _analyze_csp(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Analyze Content Security Policy header"""
        csp = headers.get('content-security-policy')
        if not csp:
            return
        
        analysis['detailed_analysis']['csp'] = {
            'header': csp,
            'has_unsafe_inline': False,
            'has_unsafe_eval': False,
            'uses_https': True
        }
        
        csp_lower = csp.lower()
        
        # Check for unsafe directives
        if 'unsafe-inline' in csp_lower:
            analysis['detailed_analysis']['csp']['has_unsafe_inline'] = True
            analysis['weak_headers'].append('Content-Security-Policy')
            analysis['vulnerabilities'].append({
                'type': 'weak_csp',
                'header': 'Content-Security-Policy',
                'severity': 'medium',
                'description': 'CSP contains unsafe-inline directive'
            })
            analysis['security_score'] -= 5
        
        if 'unsafe-eval' in csp_lower:
            analysis['detailed_analysis']['csp']['has_unsafe_eval'] = True
            analysis['weak_headers'].append('Content-Security-Policy')
            analysis['vulnerabilities'].append({
                'type': 'weak_csp',
                'header': 'Content-Security-Policy',
                'severity': 'medium',
                'description': 'CSP contains unsafe-eval directive'
            })
            analysis['security_score'] -= 5
        
        # Check if HTTPS is enforced
        if 'http:' in csp and not self.config['vulnerabilities']['weak_configurations']['csp']['https_required']:
            analysis['detailed_analysis']['csp']['uses_https'] = False
            analysis['vulnerabilities'].append({
                'type': 'weak_csp',
                'header': 'Content-Security-Policy',
                'severity': 'high',
                'description': 'CSP allows HTTP sources'
            })
            analysis['security_score'] -= 10
    
    def _analyze_x_frame_options(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Analyze X-Frame-Options header"""
        xfo = headers.get('x-frame-options')
        if not xfo:
            return
        
        xfo_lower = xfo.lower()
        analysis['detailed_analysis']['x_frame_options'] = {
            'header': xfo,
            'value': xfo_lower
        }
        
        if xfo_lower not in ['deny', 'sameorigin']:
            analysis['weak_headers'].append('X-Frame-Options')
            analysis['vulnerabilities'].append({
                'type': 'weak_xfo',
                'header': 'X-Frame-Options',
                'severity': 'medium',
                'description': f'X-Frame-Options has weak value: {xfo}'
            })
            analysis['security_score'] -= 5
    
    