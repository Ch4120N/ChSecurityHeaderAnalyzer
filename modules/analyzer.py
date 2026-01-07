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