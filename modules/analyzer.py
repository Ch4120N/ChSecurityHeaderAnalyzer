"""
Header Analysis Module - Updated for Comprehensive Configuration
"""

import re
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime
import ssl
import socket
import json

class HeaderAnalyzer:
    def __init__(self, config: Dict):
        self.config = config
        self.required_headers = config['security_headers']['required']
        self.recommended_headers = config['security_headers']['recommended']
        self.vulnerable_headers = config['security_headers']['vulnerable_headers']
        self.grading_config = config.get('grading', {})
        self.additional_checks = config.get('additional_checks', {})
        
    def analyze_headers(self, headers: Dict[str, str], url: str) -> Dict[str, Any]:
        """Analyze headers for security issues with comprehensive checks"""
        analysis = {
            'url': url,
            'scan_date': datetime.now().isoformat(),
            'headers_found': headers,
            'missing_headers': [],
            'weak_headers': [],
            'vulnerabilities': [],
            'security_score': 100,  # Start with perfect score
            'grade': 'A',
            'recommendations': [],
            'detailed_analysis': {},
            'additional_checks': {},
            'cookie_analysis': [],
            'cors_analysis': {},
            'cache_analysis': {}
        }
        
        # Check for missing required headers with severity levels
        self._check_missing_headers(headers, analysis)
        
        # Check for vulnerable headers
        self._check_vulnerable_headers(headers, analysis)
        
        # Check for recommended headers
        self._check_recommended_headers(headers, analysis)
        
        # Analyze specific security headers
        self._analyze_hsts(headers, analysis)
        self._analyze_csp(headers, analysis)
        self._analyze_cookies(headers, analysis)
        self._analyze_cors(headers, analysis)
        self._analyze_cache_control(headers, analysis)
        self._analyze_x_frame_options(headers, analysis)
        self._analyze_content_type_options(headers, analysis)
        self._analyze_referrer_policy(headers, analysis)
        self._analyze_permissions_policy(headers, analysis)
        self._analyze_content_type(headers, analysis)
        self._analyze_dns_prefetch_control(headers, analysis)
        self._analyze_x_xss_protection(headers, analysis)
        
        # Additional checks if enabled
        if self.additional_checks.get('check_ssl_certificate', True):
            self._check_ssl_certificate(url, analysis)
        
        if self.additional_checks.get('check_server_banner', True):
            self._check_server_banner(headers, analysis)
        
        # Calculate final score with weights
        self._calculate_security_score(analysis)
        
        # Update grade based on score
        analysis['grade'] = self._calculate_grade(analysis['security_score'])
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        return analysis
    
    def _check_missing_headers(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Check for missing headers with severity levels - with realistic expectations"""
        critical_headers = self.config['vulnerabilities']['missing_headers']['critical']
        high_headers = self.config['vulnerabilities']['missing_headers']['high']
        medium_headers = self.config['vulnerabilities']['missing_headers']['medium']
        
        for header in critical_headers:
            header_lower = header.lower()
            
            # Special handling for Set-Cookie - not all pages need to set cookies
            if header == 'Set-Cookie':
                # Check if it's actually needed (login pages, etc.)
                # For now, we'll still mark it missing but with a note
                if header_lower not in headers:
                    analysis['missing_headers'].append(header)
                    analysis['vulnerabilities'].append({
                        'type': 'missing_header_critical',
                        'header': header,
                        'severity': 'critical',
                        'description': f'Critical security header missing: {header} (note: not all pages need to set cookies)'
                    })
            else:
                if header_lower not in headers:
                    analysis['missing_headers'].append(header)
                    analysis['vulnerabilities'].append({
                        'type': 'missing_header_critical',
                        'header': header,
                        'severity': 'critical',
                        'description': f'Critical security header missing: {header}'
                    })
        
        for header in high_headers:
            header_lower = header.lower()
            
            # Special handling for CORS headers - not all pages need CORS
            if header in ['Access-Control-Allow-Origin', 'Access-Control-Allow-Credentials']:
                # These are only needed for cross-origin requests
                # We'll still check but note they're context-dependent
                if header_lower not in headers:
                    analysis['missing_headers'].append(header)
                    analysis['vulnerabilities'].append({
                        'type': 'missing_header_high',
                        'header': header,
                        'severity': 'high',
                        'description': f'High priority CORS header missing: {header} (only needed for cross-origin requests)'
                    })
            else:
                if header_lower not in headers:
                    analysis['missing_headers'].append(header)
                    analysis['vulnerabilities'].append({
                        'type': 'missing_header_high',
                        'header': header,
                        'severity': 'high',
                        'description': f'High priority security header missing: {header}'
                    })
        
        for header in medium_headers:
            header_lower = header.lower()
            if header_lower not in headers:
                analysis['missing_headers'].append(header)
                analysis['vulnerabilities'].append({
                    'type': 'missing_header_medium',
                    'header': header,
                    'severity': 'medium',
                    'description': f'Medium priority security header missing: {header}'
                })
                
    def _check_vulnerable_headers(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Check for vulnerable headers that disclose information - with realistic approach"""
        for header in self.vulnerable_headers:
            header_lower = header.lower()
            if header_lower in headers:
                value = headers[header_lower]
                
                # Special handling for X-XSS-Protection
                if header.lower() == 'x-xss-protection':
                    if value.lower() == '0':  # X-XSS-Protection disabled
                        analysis['vulnerabilities'].append({
                            'type': 'xss_protection_disabled',
                            'header': header,
                            'value': value,
                            'severity': 'medium',
                            'description': f'X-XSS-Protection is disabled (value: 0) - note: deprecated but still useful'
                        })
                    elif '1' in value and 'mode=block' in value.lower():
                        # This is actually good - X-XSS-Protection enabled with block mode
                        # Don't add as vulnerability
                        continue
                    else:
                        # Not optimal but not critical
                        analysis['vulnerabilities'].append({
                            'type': 'weak_xss_protection',
                            'header': header,
                            'severity': 'low',
                            'description': f'X-XSS-Protection has suboptimal configuration: {value}'
                        })
                
                # Common load balancer/proxy headers that are often necessary
                elif header_lower in ['via', 'x-varnish', 'x-amz-cf-id', 'cf-ray', 'x-forwarded-proto']:
                    # These are often necessary for infrastructure and not always a security issue
                    analysis['vulnerabilities'].append({
                        'type': 'infrastructure_header',
                        'header': header,
                        'value': value,
                        'severity': 'low',
                        'description': f'Infrastructure header present: {header} = "{value}" (common in production environments)'
                    })
                
                # Server version headers
                elif any(x in header_lower for x in ['server', 'x-powered-by', 'x-aspnet', 'x-php', 'x-drupal']):
                    analysis['vulnerabilities'].append({
                        'type': 'information_disclosure',
                        'header': header,
                        'value': value,
                        'severity': 'low',  # Reduced from medium
                        'description': f'Server information disclosed: {header} reveals "{value}"'
                    })
                
                # Other headers - very low severity
                else:
                    analysis['vulnerabilities'].append({
                        'type': 'information_disclosure_minor',
                        'header': header,
                        'value': value,
                        'severity': 'low',
                        'description': f'Minor information disclosure: {header} = "{value}"'
                    })    

    def _check_recommended_headers(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Check for missing recommended headers"""
        for header in self.recommended_headers:
            if header.lower() not in headers:
                # Don't add to vulnerabilities, but track for recommendations
                if header not in analysis['missing_headers']:
                    analysis['missing_headers'].append(header)
    
    def _analyze_hsts(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Analyze HSTS header with comprehensive checks"""
        hsts = headers.get('strict-transport-security')
        if not hsts:
            return
        
        analysis['detailed_analysis']['hsts'] = {
            'header': hsts,
            'max_age': None,
            'include_subdomains': False,
            'preload': False,
            'issues': []
        }
        
        hsts_lower = hsts.lower()
        
        # Extract max-age
        max_age_match = re.search(r'max-age=(\d+)', hsts_lower)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            analysis['detailed_analysis']['hsts']['max_age'] = max_age
            
            min_age = self.config['vulnerabilities']['weak_configurations']['hsts']['max_age_minimum']
            if max_age < min_age:
                analysis['detailed_analysis']['hsts']['issues'].append(
                    f'Max-age too low: {max_age} (should be >= {min_age})'
                )
                analysis['weak_headers'].append('Strict-Transport-Security')
                analysis['vulnerabilities'].append({
                    'type': 'weak_hsts',
                    'header': 'Strict-Transport-Security',
                    'severity': 'medium',
                    'description': f'HSTS max-age is too low: {max_age} seconds (minimum: {min_age})'
                })
        
        # Check for includeSubDomains
        if 'includesubdomains' in hsts_lower:
            analysis['detailed_analysis']['hsts']['include_subdomains'] = True
        else:
            analysis['detailed_analysis']['hsts']['issues'].append(
                'Missing includeSubDomains directive'
            )
        
        # Check for preload
        if 'preload' in hsts_lower:
            analysis['detailed_analysis']['hsts']['preload'] = True
        elif self.additional_checks.get('check_hsts_preload_status', False):
            analysis['detailed_analysis']['hsts']['issues'].append(
                'Missing preload directive'
            )
    
    def _analyze_csp(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Analyze Content Security Policy header"""
        csp = headers.get('content-security-policy')
        csp_report_only = headers.get('content-security-policy-report-only')
        
        if csp:
            analysis['detailed_analysis']['csp'] = self._analyze_csp_directives(csp, 'enforced')
        if csp_report_only:
            analysis['detailed_analysis']['csp_report_only'] = self._analyze_csp_directives(csp_report_only, 'report-only')
        
        # Check for weak CSP configurations
        if csp and self.additional_checks.get('check_csp_directives', True):
            csp_lower = csp.lower()
            config = self.config['vulnerabilities']['weak_configurations']['csp']
            
            # Note: config values are True when unsafe directives are NOT allowed
            # So we check if unsafe-inline is present when it should be False (not allowed)
            if not config['unsafe_inline'] and 'unsafe-inline' in csp_lower:
                analysis['weak_headers'].append('Content-Security-Policy')
                analysis['vulnerabilities'].append({
                    'type': 'weak_csp',
                    'header': 'Content-Security-Policy',
                    'severity': 'medium',
                    'description': 'CSP contains unsafe-inline directive'
                })
            
            if not config['unsafe_eval'] and 'unsafe-eval' in csp_lower:
                analysis['weak_headers'].append('Content-Security-Policy')
                analysis['vulnerabilities'].append({
                    'type': 'weak_csp',
                    'header': 'Content-Security-Policy',
                    'severity': 'medium',
                    'description': 'CSP contains unsafe-eval directive'
                })
            
            if config['https_required'] and 'http:' in csp and 'https:' not in csp:
                analysis['vulnerabilities'].append({
                    'type': 'weak_csp',
                    'header': 'Content-Security-Policy',
                    'severity': 'high',
                    'description': 'CSP allows HTTP sources without HTTPS fallback'
                })
    
    def _analyze_csp_directives(self, csp: str, policy_type: str) -> Dict[str, Any]:
        """Analyze CSP directives in detail"""
        analysis = {
            'policy_type': policy_type,
            'header': csp,
            'directives': {},
            'issues': []
        }
        
        # Parse CSP directives
        directives = csp.lower().split(';')
        for directive in directives:
            directive = directive.strip()
            if not directive:
                continue
            
            parts = directive.split()
            if len(parts) > 0:
                dir_name = parts[0]
                dir_values = parts[1:] if len(parts) > 1 else []
                analysis['directives'][dir_name] = dir_values
        
        return analysis
    
    def _analyze_cookies(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Analyze Set-Cookie headers for security flags"""
        set_cookie_headers = []
        
        # Collect all Set-Cookie headers
        for key, value in headers.items():
            if key.lower() == 'set-cookie':
                if isinstance(value, list):
                    set_cookie_headers.extend(value)
                else:
                    set_cookie_headers.append(value)
        
        if not set_cookie_headers:
            if 'Set-Cookie' in self.required_headers:
                # Set-Cookie is required but not present
                return
            else:
                return
        
        analysis['cookie_analysis'] = []
        config = self.config['vulnerabilities']['weak_configurations']['cookie']
        
        for cookie in set_cookie_headers:
            cookie_analysis = {
                'raw': cookie,
                'flags': {},
                'issues': []
            }
            
            cookie_lower = cookie.lower()
            
            # Check for Secure flag
            if 'secure' in cookie_lower:
                cookie_analysis['flags']['secure'] = True
            elif config['secure_required']:
                cookie_analysis['issues'].append('Missing Secure flag')
                analysis['vulnerabilities'].append({
                    'type': 'insecure_cookie',
                    'header': 'Set-Cookie',
                    'severity': 'high',
                    'description': 'Cookie missing Secure flag'
                })
            
            # Check for HttpOnly flag
            if 'httponly' in cookie_lower:
                cookie_analysis['flags']['httponly'] = True
            elif config['httponly_required']:
                cookie_analysis['issues'].append('Missing HttpOnly flag')
                analysis['vulnerabilities'].append({
                    'type': 'insecure_cookie',
                    'header': 'Set-Cookie',
                    'severity': 'medium',
                    'description': 'Cookie missing HttpOnly flag'
                })
            
            # Check for SameSite attribute
            samesite_match = re.search(r'samesite=(\w+)', cookie_lower)
            if samesite_match:
                samesite_value = samesite_match.group(1)
                cookie_analysis['flags']['samesite'] = samesite_value
                
                required = config['samesite_required'].lower()
                if required != 'none' and samesite_value != required:
                    cookie_analysis['issues'].append(f'SameSite should be {required}, got {samesite_value}')
                    analysis['vulnerabilities'].append({
                        'type': 'weak_cookie',
                        'header': 'Set-Cookie',
                        'severity': 'medium',
                        'description': f'Cookie SameSite attribute should be {required}'
                    })
            elif config['samesite_required'].lower() != 'none':
                cookie_analysis['issues'].append(f'Missing SameSite attribute (should be {config["samesite_required"]})')
            
            analysis['cookie_analysis'].append(cookie_analysis)
    
    def _analyze_cors(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Analyze CORS headers"""
        analysis['cors_analysis'] = {
            'access_control_allow_origin': headers.get('access-control-allow-origin'),
            'access_control_allow_credentials': headers.get('access-control-allow-credentials'),
            'access_control_allow_methods': headers.get('access-control-allow-methods'),
            'access_control_allow_headers': headers.get('access-control-allow-headers'),
            'access_control_expose_headers': headers.get('access-control-expose-headers'),
            'access_control_max_age': headers.get('access-control-max-age'),
            'issues': []
        }
        
        if not self.additional_checks.get('check_cors_configuration', True):
            return
        
        cors = analysis['cors_analysis']
        config = self.config['vulnerabilities']['weak_configurations']['cors']
        
        # Check for wildcard in Access-Control-Allow-Origin
        if cors['access_control_allow_origin'] == '*':
            if not config['wildcard_allowed']:
                cors['issues'].append('Wildcard (*) in Access-Control-Allow-Origin')
                analysis['vulnerabilities'].append({
                    'type': 'weak_cors',
                    'header': 'Access-Control-Allow-Origin',
                    'severity': 'high',
                    'description': 'CORS allows wildcard origin (*)'
                })
            
            # Check if credentials are allowed with wildcard
            if cors['access_control_allow_credentials'] and cors['access_control_allow_credentials'].lower() == 'true':
                if not config['credentials_with_wildcard']:
                    cors['issues'].append('Credentials allowed with wildcard origin')
                    analysis['vulnerabilities'].append({
                        'type': 'weak_cors',
                        'header': 'Access-Control-Allow-Credentials',
                        'severity': 'high',
                        'description': 'CORS allows credentials with wildcard origin'
                    })
        
        # Check exposed methods
        if cors['access_control_allow_methods']:
            methods = [m.strip().upper() for m in cors['access_control_allow_methods'].split(',')]
            safe_methods = [m.upper() for m in config['methods_exposed']]
            
            dangerous_methods = set(methods) - set(safe_methods)
            if dangerous_methods:
                cors['issues'].append(f'Potentially dangerous methods exposed: {", ".join(dangerous_methods)}')
                analysis['vulnerabilities'].append({
                    'type': 'weak_cors',
                    'header': 'Access-Control-Allow-Methods',
                    'severity': 'medium',
                    'description': f'CORS exposes potentially dangerous methods: {", ".join(dangerous_methods)}'
                })
    
    def _analyze_cache_control(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Analyze Cache-Control header"""
        cache_control = headers.get('cache-control')
        if not cache_control:
            return
        
        analysis['cache_analysis'] = {
            'header': cache_control,
            'directives': {},
            'issues': []
        }
        
        cache_lower = cache_control.lower()
        config = self.config['vulnerabilities']['weak_configurations']['cache']
        
        # Parse directives
        directives = [d.strip() for d in cache_lower.split(',')]
        for directive in directives:
            if '=' in directive:
                key, value = directive.split('=', 1)
                analysis['cache_analysis']['directives'][key.strip()] = value.strip()
            else:
                analysis['cache_analysis']['directives'][directive] = True
        
        # Check configurations
        if config['no_store_required'] and 'no-store' not in cache_lower:
            analysis['cache_analysis']['issues'].append('Missing no-store directive')
        
        if config['no_cache_required'] and 'no-cache' not in cache_lower:
            analysis['cache_analysis']['issues'].append('Missing no-cache directive')
        
        if config['private_required'] and 'private' not in cache_lower:
            analysis['cache_analysis']['issues'].append('Missing private directive')
        
        if config['must_revalidate_required'] and 'must-revalidate' not in cache_lower:
            analysis['cache_analysis']['issues'].append('Missing must-revalidate directive')
        
        # Add vulnerability if issues found
        if analysis['cache_analysis']['issues']:
            analysis['vulnerabilities'].append({
                'type': 'weak_cache',
                'header': 'Cache-Control',
                'severity': 'low',
                'description': f'Cache-Control header has issues: {", ".join(analysis["cache_analysis"]["issues"])}'
            })
    
    def _analyze_x_frame_options(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Analyze X-Frame-Options header"""
        xfo = headers.get('x-frame-options')
        if not xfo:
            return
        
        analysis['detailed_analysis']['x_frame_options'] = {
            'header': xfo,
            'value': xfo.lower()
        }
        
        if xfo.lower() not in ['deny', 'sameorigin']:
            analysis['weak_headers'].append('X-Frame-Options')
            analysis['vulnerabilities'].append({
                'type': 'weak_xfo',
                'header': 'X-Frame-Options',
                'severity': 'medium',
                'description': f'X-Frame-Options has weak value: {xfo} (should be DENY or SAMEORIGIN)'
            })
    
    def _analyze_content_type_options(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Analyze X-Content-Type-Options header"""
        xcto = headers.get('x-content-type-options')
        if not xcto:
            return
        
        analysis['detailed_analysis']['content_type_options'] = {
            'header': xcto
        }
        
        if xcto.lower() != 'nosniff':
            analysis['weak_headers'].append('X-Content-Type-Options')
            analysis['vulnerabilities'].append({
                'type': 'weak_xcto',
                'header': 'X-Content-Type-Options',
                'severity': 'medium',
                'description': f'X-Content-Type-Options should be "nosniff", got: {xcto}'
            })
    
    def _analyze_referrer_policy(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Analyze Referrer-Policy header"""
        rp = headers.get('referrer-policy')
        if not rp:
            return
        
        weak_policies = ['unsafe-url', 'no-referrer-when-downgrade', '']
        if rp.lower() in weak_policies:
            analysis['weak_headers'].append('Referrer-Policy')
            analysis['vulnerabilities'].append({
                'type': 'weak_referrer_policy',
                'header': 'Referrer-Policy',
                'severity': 'low',
                'description': f'Referrer-Policy has weak value: {rp}'
            })
        
        analysis['detailed_analysis']['referrer_policy'] = {
            'header': rp
        }
    
    def _analyze_permissions_policy(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Analyze Permissions-Policy header (formerly Feature-Policy)"""
        pp = headers.get('permissions-policy')
        fp = headers.get('feature-policy')  # Legacy header
        
        if pp:
            analysis['detailed_analysis']['permissions_policy'] = {
                'header': pp,
                'type': 'permissions-policy'
            }
        elif fp:
            analysis['detailed_analysis']['permissions_policy'] = {
                'header': fp,
                'type': 'feature-policy'
            }
        else:
            return
        
        # Check for overly permissive settings
        policy_header = pp or fp
        if 'camera=*' in policy_header or 'microphone=*' in policy_header or 'geolocation=*' in policy_header:
            analysis['vulnerabilities'].append({
                'type': 'permissive_permissions',
                'header': 'Permissions-Policy' if pp else 'Feature-Policy',
                'severity': 'low',
                'description': 'Permissions/Feature-Policy allows sensitive features globally'
            })
    
    def _analyze_content_type(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Analyze Content-Type header"""
        content_type = headers.get('content-type')
        if not content_type:
            return
        
        analysis['detailed_analysis']['content_type'] = {
            'header': content_type
        }
        
        # Check for charset
        if 'charset=' not in content_type.lower():
            analysis['vulnerabilities'].append({
                'type': 'missing_charset',
                'header': 'Content-Type',
                'severity': 'low',
                'description': 'Content-Type header missing charset specification'
            })
    
    def _analyze_dns_prefetch_control(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Analyze X-DNS-Prefetch-Control header"""
        dns_prefetch = headers.get('x-dns-prefetch-control')
        if not dns_prefetch:
            return
        
        analysis['detailed_analysis']['dns_prefetch_control'] = {
            'header': dns_prefetch
        }
        
        if dns_prefetch.lower() != 'off':
            analysis['vulnerabilities'].append({
                'type': 'dns_prefetch_enabled',
                'header': 'X-DNS-Prefetch-Control',
                'severity': 'low',
                'description': 'DNS prefetching is enabled (privacy concern)'
            })
    
    def _analyze_x_xss_protection(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Analyze X-XSS-Protection header (deprecated but still analyzed)"""
        x_xss = headers.get('x-xss-protection')
        if not x_xss:
            return
        
        analysis['detailed_analysis']['x_xss_protection'] = {
            'header': x_xss
        }
        
        # X-XSS-Protection is deprecated but we still analyze it
        if x_xss.lower() == '0':
            analysis['vulnerabilities'].append({
                'type': 'xss_protection_disabled',
                'header': 'X-XSS-Protection',
                'severity': 'medium',
                'description': 'X-XSS-Protection is disabled (deprecated header)'
            })
    
    def _check_ssl_certificate(self, url: str, analysis: Dict[str, Any]):
        """Check SSL certificate validity"""
        try:
            from urllib.parse import urlparse
            import ssl
            import socket
            
            parsed = urlparse(url)
            hostname = parsed.hostname
            
            if not hostname or parsed.scheme != 'https':
                return
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    analysis['additional_checks']['ssl_certificate'] = {
                        'valid': True,
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter')
                    }
                    
        except Exception as e:
            analysis['additional_checks']['ssl_certificate'] = {
                'valid': False,
                'error': str(e)
            }
            # Only add vulnerability if SSL certificate check actually fails for HTTPS sites
            if 'https://' in url:
                analysis['vulnerabilities'].append({
                    'type': 'ssl_certificate_error',
                    'severity': 'high',
                    'description': f'SSL certificate error: {str(e)}'
                })
    
    def _check_server_banner(self, headers: Dict[str, str], analysis: Dict[str, Any]):
        """Check server banner for information disclosure"""
        server = headers.get('server')
        if server:
            analysis['additional_checks']['server_banner'] = {
                'value': server,
                'disclosure': 'full' if len(server) > 10 else 'partial'
            }
            
            # Check for specific server versions in banner
            version_patterns = [
                r'Apache/(\d+\.\d+(\.\d+)?)',
                r'nginx/(\d+\.\d+(\.\d+)?)',
                r'IIS/(\d+\.\d+)',
                r'Microsoft-IIS/(\d+\.\d+)'
            ]
            
            for pattern in version_patterns:
                match = re.search(pattern, server, re.IGNORECASE)
                if match:
                    analysis['vulnerabilities'].append({
                        'type': 'server_version_disclosure',
                        'header': 'Server',
                        'severity': 'low',
                        'description': f'Server version disclosed: {match.group(0)}'
                    })
                    break
    
    def _calculate_security_score(self, analysis: Dict[str, Any]):
        """Calculate security score with a balanced approach for comprehensive configuration"""
        score = 100  # Start with perfect score
        
        # 1. Calculate deductions for missing headers (using severity levels from config)
        critical_headers = self.config['vulnerabilities']['missing_headers']['critical']
        high_headers = self.config['vulnerabilities']['missing_headers']['high']
        medium_headers = self.config['vulnerabilities']['missing_headers']['medium']
        
        missing_critical = 0
        missing_high = 0
        missing_medium = 0
        
        # Check critical headers
        for header in critical_headers:
            if header.lower() not in analysis['headers_found']:
                missing_critical += 1
        
        # Check high priority headers
        for header in high_headers:
            if header.lower() not in analysis['headers_found']:
                missing_high += 1
        
        # Check medium priority headers
        for header in medium_headers:
            if header.lower() not in analysis['headers_found']:
                missing_medium += 1
        
        # Apply deductions (scaled to be less harsh)
        score -= missing_critical * 8    # -8 for each missing critical header (was -15)
        score -= missing_high * 5        # -5 for each missing high header (was -10)
        score -= missing_medium * 3      # -3 for each missing medium header (was -5)
        
        # 2. Give bonus points for headers that ARE present
        required_headers = self.config['security_headers']['required']
        recommended_headers = self.config['security_headers']['recommended']
        
        present_required = 0
        for header in required_headers:
            if header.lower() in analysis['headers_found']:
                present_required += 1
        
        present_recommended = 0
        for header in recommended_headers:
            if header.lower() in analysis['headers_found']:
                present_recommended += 1
        
        # Add points for present headers (encourage good practices)
        score += min(present_required * 3, 30)     # +3 for each required header, max +30
        score += min(present_recommended * 2, 20)  # +2 for each recommended header, max +20
        
        # 3. Special bonuses for strong configurations
        # Bonus for HSTS with proper max-age
        if 'strict-transport-security' in analysis['headers_found']:
            hsts = analysis['headers_found']['strict-transport-security'].lower()
            if 'max-age=31536000' in hsts or 'max-age=63072000' in hsts:
                score += 10  # Good HSTS configuration bonus
        
        # Bonus for CSP without unsafe directives
        if 'content-security-policy' in analysis['headers_found']:
            csp = analysis['headers_found']['content-security-policy'].lower()
            if 'unsafe-inline' not in csp and 'unsafe-eval' not in csp:
                score += 10  # Strong CSP bonus
        
        # Bonus for secure cookies
        if analysis.get('cookie_analysis'):
            secure_cookies = 0
            for cookie in analysis['cookie_analysis']:
                if cookie.get('flags', {}).get('secure') and cookie.get('flags', {}).get('httponly'):
                    secure_cookies += 1
            
            if secure_cookies > 0:
                score += min(secure_cookies * 2, 10)  # +2 for each secure cookie, max +10
        
        # 4. Deductions for vulnerabilities (scaled based on severity)
        critical_vulns = sum(1 for v in analysis['vulnerabilities'] if v['severity'] == 'critical')
        high_vulns = sum(1 for v in analysis['vulnerabilities'] if v['severity'] == 'high')
        medium_vulns = sum(1 for v in analysis['vulnerabilities'] if v['severity'] == 'medium')
        low_vulns = sum(1 for v in analysis['vulnerabilities'] if v['severity'] == 'low')
        
        # Apply scaled deductions
        score -= critical_vulns * 12     # -12 for critical
        score -= high_vulns * 8          # -8 for high
        score -= medium_vulns * 4        # -4 for medium
        score -= low_vulns * 2           # -2 for low
        
        # 5. Penalty for information disclosure (vulnerable headers)
        vulnerable_headers = self.config['security_headers']['vulnerable_headers']
        vulnerable_found = 0
        
        for header in vulnerable_headers:
            if header.lower() in analysis['headers_found']:
                # Skip X-XSS-Protection as it's not always a vulnerability
                if header.lower() != 'x-xss-protection':
                    vulnerable_found += 1
        
        # Reduced penalty for vulnerable headers
        score -= min(vulnerable_found * 1, 15)  # -1 for each, max -15
        
        # 6. Adjust for unrealistic expectations
        # Many legitimate sites don't have all CORS headers or Set-Cookie headers on initial response
        # Give partial credit for attempts
        
        # If no Set-Cookie header but it's in critical list, reduce penalty
        if 'set-cookie' not in analysis['headers_found'] and 'Set-Cookie' in critical_headers:
            score += 5  # Partial credit - not all pages need to set cookies
        
        # If no CORS headers but they're expected, reduce penalty
        if ('access-control-allow-origin' not in analysis['headers_found'] and 
            'Access-Control-Allow-Origin' in high_headers):
            score += 3  # Partial credit - CORS not always needed
        
        if ('access-control-allow-credentials' not in analysis['headers_found'] and 
            'Access-Control-Allow-Credentials' in high_headers):
            score += 3  # Partial credit
        
        # 7. Ensure score is within bounds
        score = max(0, min(100, score))
        
        # Round to nearest integer
        analysis['security_score'] = int(round(score))
        
        # Store score breakdown for debugging
        analysis['score_breakdown'] = {
            'base_score': 100,
            'missing_critical': f"{missing_critical} (-{missing_critical * 8})",
            'missing_high': f"{missing_high} (-{missing_high * 5})",
            'missing_medium': f"{missing_medium} (-{missing_medium * 3})",
            'bonus_required': f"{present_required} (+{min(present_required * 3, 30)})",
            'bonus_recommended': f"{present_recommended} (+{min(present_recommended * 2, 20)})",
            'critical_vulns': f"{critical_vulns} (-{critical_vulns * 12})",
            'high_vulns': f"{high_vulns} (-{high_vulns * 8})",
            'medium_vulns': f"{medium_vulns} (-{medium_vulns * 4})",
            'low_vulns': f"{low_vulns} (-{low_vulns * 2})",
            'vulnerable_headers': f"{vulnerable_found} (-{min(vulnerable_found * 1, 15)})",
            'adjustments': 'CORS/Set-Cookie adjustments applied'
        }
    
    def _calculate_grade(self, score: int) -> str:
        """Calculate security grade based on configured thresholds"""
        thresholds = self.grading_config.get('grade_thresholds', {
            'A': 90,
            'B': 75,
            'C': 60,
            'D': 40,
            'F': 0
        })
        
        if score >= thresholds.get('A', 90):
            return 'A'
        elif score >= thresholds.get('B', 75):
            return 'B'
        elif score >= thresholds.get('C', 60):
            return 'C'
        elif score >= thresholds.get('D', 40):
            return 'D'
        else:
            return 'F'
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on comprehensive analysis"""
        recommendations = []
        
        # Missing headers recommendations
        for header in analysis['missing_headers']:
            if header in self.config['vulnerabilities']['missing_headers']['critical']:
                recommendations.append(f'CRITICAL: Add missing header: {header}')
            elif header in self.config['vulnerabilities']['missing_headers']['high']:
                recommendations.append(f'HIGH PRIORITY: Add missing header: {header}')
            elif header in self.config['vulnerabilities']['missing_headers']['medium']:
                recommendations.append(f'MEDIUM PRIORITY: Add missing header: {header}')
            else:
                recommendations.append(f'Consider adding recommended header: {header}')
        
        # Weak headers recommendations
        for header in analysis['weak_headers']:
            recommendations.append(f'Strengthen configuration for: {header}')
        
        # Cookie recommendations
        if analysis.get('cookie_analysis'):
            for cookie in analysis['cookie_analysis']:
                for issue in cookie.get('issues', []):
                    recommendations.append(f'Fix cookie security: {issue}')
        
        # CORS recommendations
        if analysis.get('cors_analysis', {}).get('issues'):
            for issue in analysis['cors_analysis']['issues']:
                recommendations.append(f'Fix CORS configuration: {issue}')
        
        # Cache recommendations
        if analysis.get('cache_analysis', {}).get('issues'):
            for issue in analysis['cache_analysis']['issues']:
                recommendations.append(f'Improve cache control: {issue}')
        
        # Additional checks recommendations
        if not analysis.get('additional_checks', {}).get('ssl_certificate', {}).get('valid'):
            recommendations.append('Fix SSL certificate configuration')
        
        # Remove duplicate recommendations
        unique_recommendations = []
        seen = set()
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations