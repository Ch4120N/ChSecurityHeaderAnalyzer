"""
Header Analysis Module - Excellent Edition (Full)
"""

import re
from typing import Dict, List, Any
from datetime import datetime
import ssl
import socket
import json

class HeaderAnalyzer:
    def __init__(self, config: Dict):
        self.config = config
        self.required_headers = config['security_headers']['required']
        self.recommended_headers = config['security_headers']['recommended']
        self.deprecated_headers = config['security_headers'].get('deprecated', [])
        self.vulnerable_headers = config['security_headers']['vulnerable']
        self.infrastructure_headers = config['security_headers'].get('infrastructure', [])
        self.grading_config = config.get('grading', {})
        self.additional_checks = config.get('additional_checks', {})
        self.missing_weights = config.get('vulnerabilities', {}).get('missing_headers', {})
        # These are not required, just recommended; missing them doesn't penalize much
        self.optional_headers = ['Referrer-Policy', 'Permissions-Policy']

    def analyze_headers(self, headers: Dict[str, str], url: str) -> Dict[str, Any]:
        analysis = {
            'url': url,
            'scan_date': datetime.now().isoformat(),
            'headers_found': headers,
            'missing_required': [],
            'missing_recommended': [],
            'deprecated_found': [],
            'vulnerabilities': [],
            'security_score': 100,
            'grade': 'A',
            'recommendations': [],
            'detailed_analysis': {},
            'additional_checks': {},
            'cookie_analysis': [],
            'cors_analysis': {},
            'cache_analysis': {}
        }

        self._check_missing_headers(headers, analysis)
        self._check_vulnerable_headers(headers, analysis)
        self._check_deprecated_headers(headers, analysis)
        self._check_recommended_headers(headers, analysis)

        self._analyze_hsts(headers, analysis, url)
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

        if self.additional_checks.get('check_ssl_certificate', True):
            self._check_ssl_certificate(url, analysis)
        if self.additional_checks.get('check_server_banner', True):
            self._check_server_banner(headers, analysis)

        self._calculate_security_score(analysis)
        analysis['grade'] = self._calculate_grade(analysis['security_score'])
        analysis['recommendations'] = self._generate_recommendations(analysis)
        return analysis

    # ----- Missing headers with realistic severity -----
    def _check_missing_headers(self, headers: Dict, analysis: Dict):
        crit = self.missing_weights.get('critical', [])
        high = self.missing_weights.get('high', [])
        med  = self.missing_weights.get('medium', [])

        for header in crit:
            if header.lower() not in headers:
                severity = 'critical'
                desc = f'Critical security header missing: {header}'
                # Downgrade HSTS if HTTPS (likely preloaded)
                if header == 'Strict-Transport-Security' and analysis['url'].startswith('https://'):
                    severity = 'high'
                    desc += ' (site is HTTPS, may rely on HSTS preload)'
                analysis['missing_required'].append(header)
                analysis['vulnerabilities'].append({
                    'type': 'missing_critical',
                    'header': header,
                    'severity': severity,
                    'description': desc
                })

        for header in high:
            if header.lower() not in headers:
                severity = 'high'
                desc = f'High priority security header missing: {header}'
                # X-Content-Type-Options less critical if Content-Type present
                if header == 'X-Content-Type-Options' and 'content-type' in headers:
                    severity = 'medium'
                    desc += ' (but Content-Type header is present)'
                analysis['missing_required'].append(header)
                analysis['vulnerabilities'].append({
                    'type': 'missing_high',
                    'header': header,
                    'severity': severity,
                    'description': desc
                })

        for header in med:
            if header.lower() not in headers:
                if header in self.optional_headers:
                    # Don't mark as missing_required, just note for recommendations later
                    continue
                analysis['missing_required'].append(header)
                analysis['vulnerabilities'].append({
                    'type': 'missing_medium',
                    'header': header,
                    'severity': 'medium',
                    'description': f'Medium priority security header missing: {header}'
                })

    def _check_recommended_headers(self, headers: Dict, analysis: Dict):
        for header in self.recommended_headers:
            if header.lower() not in headers:
                analysis['missing_recommended'].append(header)

    def _check_deprecated_headers(self, headers: Dict, analysis: Dict):
        for header in self.deprecated_headers:
            if header.lower() in headers:
                analysis['deprecated_found'].append(header)
                analysis['vulnerabilities'].append({
                    'type': 'deprecated_header',
                    'header': header,
                    'severity': 'low',
                    'description': f'Deprecated header present: {header}'
                })

    def _check_vulnerable_headers(self, headers: Dict, analysis: Dict):
        for header in self.vulnerable_headers:
            if header.lower() in headers:
                value = headers[header.lower()]
                # Server header without version number is not a real disclosure
                if header == 'Server' and not re.search(r'\d+\.\d+', value):
                    continue
                analysis['vulnerabilities'].append({
                    'type': 'information_disclosure',
                    'header': header,
                    'severity': 'medium',
                    'description': f'Sensitive header present: {header} = "{value}"'
                })
        for header in self.infrastructure_headers:
            if header.lower() in headers:
                value = headers[header.lower()]
                analysis['vulnerabilities'].append({
                    'type': 'infrastructure_header',
                    'header': header,
                    'severity': 'info',
                    'description': f'Infrastructure header detected: {header} = "{value}" (not a vulnerability)'
                })

    # ---------- Detailed header analyses ----------
    def _analyze_hsts(self, headers, analysis, url):
        hsts = headers.get('strict-transport-security')
        if not hsts:
            return
        analysis['detailed_analysis']['hsts'] = {
            'header': hsts, 'max_age': None, 'include_subdomains': False,
            'preload': False, 'issues': []
        }
        hsts_lower = hsts.lower()
        m = re.search(r'max-age=(\d+)', hsts_lower)
        if m:
            max_age = int(m.group(1))
            analysis['detailed_analysis']['hsts']['max_age'] = max_age
            min_age = self.config['vulnerabilities']['weak_configurations']['hsts']['max_age_minimum']
            if max_age < min_age:
                analysis['detailed_analysis']['hsts']['issues'].append(f'Max-age too low: {max_age}')
                analysis['vulnerabilities'].append({
                    'type': 'weak_hsts', 'header': 'Strict-Transport-Security',
                    'severity': 'medium',
                    'description': f'HSTS max-age is {max_age} (<{min_age})'
                })
        if 'includesubdomains' in hsts_lower:
            analysis['detailed_analysis']['hsts']['include_subdomains'] = True
        else:
            analysis['detailed_analysis']['hsts']['issues'].append('Missing includeSubDomains')
        if 'preload' in hsts_lower:
            analysis['detailed_analysis']['hsts']['preload'] = True

    def _analyze_csp(self, headers, analysis):
        csp = headers.get('content-security-policy')
        csp_report = headers.get('content-security-policy-report-only')
        if csp:
            analysis['detailed_analysis']['csp'] = self._parse_csp(csp, 'enforced')
        if csp_report:
            analysis['detailed_analysis']['csp_report_only'] = self._parse_csp(csp_report, 'report-only')
        # If no enforced CSP but report-only is present, give partial credit
        if not csp and csp_report:
            analysis['vulnerabilities'].append({
                'type': 'csp_report_only',
                'header': 'Content-Security-Policy',
                'severity': 'medium',
                'description': 'Only CSP-Report-Only header found, no enforced policy'
            })
        if csp and self.additional_checks.get('check_csp_directives', True):
            csp_lower = csp.lower()
            conf = self.config['vulnerabilities']['weak_configurations']['csp']
            if not conf['unsafe_inline'] and 'unsafe-inline' in csp_lower:
                analysis['vulnerabilities'].append({
                    'type': 'weak_csp', 'header': 'Content-Security-Policy',
                    'severity': 'medium', 'description': 'CSP contains unsafe-inline'
                })
            if not conf['unsafe_eval'] and 'unsafe-eval' in csp_lower:
                analysis['vulnerabilities'].append({
                    'type': 'weak_csp', 'header': 'Content-Security-Policy',
                    'severity': 'medium', 'description': 'CSP contains unsafe-eval'
                })
            if conf['https_required'] and 'http:' in csp_lower and 'https:' not in csp_lower:
                analysis['vulnerabilities'].append({
                    'type': 'weak_csp', 'header': 'Content-Security-Policy',
                    'severity': 'high', 'description': 'CSP allows HTTP without HTTPS fallback'
                })

    def _parse_csp(self, csp: str, ptype: str) -> Dict:
        directives = {}
        for part in csp.lower().split(';'):
            part = part.strip()
            if not part: continue
            dirs = part.split()
            directives[dirs[0]] = dirs[1:] if len(dirs) > 1 else []
        return {'policy_type': ptype, 'header': csp, 'directives': directives, 'issues': []}

    def _analyze_cookies(self, headers, analysis):
        set_cookies = []
        for k, v in headers.items():
            if k.lower() == 'set-cookie':
                if isinstance(v, list): set_cookies.extend(v)
                else: set_cookies.append(v)
        if not set_cookies: return
        analysis['cookie_analysis'] = []
        conf = self.config['vulnerabilities']['weak_configurations']['cookie']
        # SameSite strength ordering: none < lax < strict
        samesite_order = {'none': 0, 'lax': 1, 'strict': 2}
        required_level = samesite_order.get(conf['samesite_required'].lower(), 1)

        for cookie in set_cookies:
            ca = {'raw': cookie, 'flags': {}, 'issues': []}
            cl = cookie.lower()
            if 'secure' in cl:
                ca['flags']['secure'] = True
            elif conf['secure_required']:
                ca['issues'].append('Missing Secure flag')
                analysis['vulnerabilities'].append({
                    'type': 'insecure_cookie', 'header': 'Set-Cookie',
                    'severity': 'high', 'description': 'Cookie missing Secure flag'
                })
            if 'httponly' in cl:
                ca['flags']['httponly'] = True
            elif conf['httponly_required']:
                ca['issues'].append('Missing HttpOnly flag')
                analysis['vulnerabilities'].append({
                    'type': 'insecure_cookie', 'header': 'Set-Cookie',
                    'severity': 'medium', 'description': 'Cookie missing HttpOnly flag'
                })
            samesite_match = re.search(r'samesite=(\w+)', cl)
            if samesite_match:
                samesite = samesite_match.group(1)
                ca['flags']['samesite'] = samesite
                actual_level = samesite_order.get(samesite.lower(), 0)
                if actual_level < required_level:
                    ca['issues'].append(f'SameSite should be at least {conf["samesite_required"]}, got {samesite}')
                    analysis['vulnerabilities'].append({
                        'type': 'weak_cookie', 'header': 'Set-Cookie',
                        'severity': 'medium',
                        'description': f'SameSite attribute is {samesite}, weaker than required {conf["samesite_required"]}'
                    })
                # If it's strict and required is lax, it's fine (no issue)
            else:
                if required_level > 0:
                    ca['issues'].append('Missing SameSite attribute')
                    analysis['vulnerabilities'].append({
                        'type': 'weak_cookie', 'header': 'Set-Cookie',
                        'severity': 'medium', 'description': 'Cookie missing SameSite attribute'
                    })
            analysis['cookie_analysis'].append(ca)

    def _analyze_cors(self, headers, analysis):
        cors = {
            'origin': headers.get('access-control-allow-origin'),
            'credentials': headers.get('access-control-allow-credentials'),
            'methods': headers.get('access-control-allow-methods'),
            'headers': headers.get('access-control-allow-headers'),
            'expose': headers.get('access-control-expose-headers'),
            'max_age': headers.get('access-control-max-age'),
            'issues': []
        }
        analysis['cors_analysis'] = cors
        if not self.additional_checks.get('check_cors_configuration', True):
            return
        conf = self.config['vulnerabilities']['weak_configurations']['cors']
        if cors['origin'] == '*':
            if not conf['wildcard_allowed']:
                cors['issues'].append('Wildcard origin not allowed')
                analysis['vulnerabilities'].append({
                    'type': 'weak_cors', 'header': 'Access-Control-Allow-Origin',
                    'severity': 'high', 'description': 'CORS allows wildcard origin'
                })
            if cors['credentials'] and cors['credentials'].lower() == 'true' and not conf['credentials_with_wildcard']:
                cors['issues'].append('Credentials with wildcard')
                analysis['vulnerabilities'].append({
                    'type': 'weak_cors', 'header': 'Access-Control-Allow-Credentials',
                    'severity': 'high', 'description': 'CORS allows credentials with wildcard origin'
                })
        if cors['methods']:
            methods = [m.strip().upper() for m in cors['methods'].split(',')]
            safe = [m.upper() for m in conf['methods_exposed']]
            dangerous = set(methods) - set(safe)
            if dangerous:
                cors['issues'].append(f'Dangerous methods exposed: {", ".join(dangerous)}')
                analysis['vulnerabilities'].append({
                    'type': 'weak_cors', 'header': 'Access-Control-Allow-Methods',
                    'severity': 'medium', 'description': f'Exposes dangerous methods: {", ".join(dangerous)}'
                })

    def _analyze_cache_control(self, headers, analysis):
        cc = headers.get('cache-control')
        if not cc: return
        analysis['cache_analysis'] = {'header': cc, 'directives': {}, 'issues': []}
        conf = self.config['vulnerabilities']['weak_configurations']['cache']
        directives = [d.strip() for d in cc.lower().split(',')]
        for d in directives:
            if '=' in d:
                k, v = d.split('=', 1)
                analysis['cache_analysis']['directives'][k.strip()] = v.strip()
            else:
                analysis['cache_analysis']['directives'][d] = True
        # Only flag issues if the config says it's required (currently all false)
        if conf['no_store_required'] and 'no-store' not in cc.lower():
            analysis['cache_analysis']['issues'].append('Missing no-store')
        if conf['no_cache_required'] and 'no-cache' not in cc.lower():
            analysis['cache_analysis']['issues'].append('Missing no-cache')
        if conf['private_required'] and 'private' not in cc.lower():
            analysis['cache_analysis']['issues'].append('Missing private')
        if conf['must_revalidate_required'] and 'must-revalidate' not in cc.lower():
            analysis['cache_analysis']['issues'].append('Missing must-revalidate')
        if analysis['cache_analysis']['issues']:
            analysis['vulnerabilities'].append({
                'type': 'weak_cache', 'header': 'Cache-Control',
                'severity': 'low',
                'description': f'Cache issues: {", ".join(analysis["cache_analysis"]["issues"])}'
            })

    def _analyze_x_frame_options(self, headers, analysis):
        xfo = headers.get('x-frame-options')
        if not xfo: return
        analysis['detailed_analysis']['x_frame_options'] = {'header': xfo}
        if xfo.lower() not in ['deny', 'sameorigin']:
            analysis['vulnerabilities'].append({
                'type': 'weak_xfo', 'header': 'X-Frame-Options',
                'severity': 'medium', 'description': f'Weak value: {xfo}'
            })

    def _analyze_content_type_options(self, headers, analysis):
        xcto = headers.get('x-content-type-options')
        if not xcto: return
        analysis['detailed_analysis']['content_type_options'] = {'header': xcto}
        if xcto.lower() != 'nosniff':
            analysis['vulnerabilities'].append({
                'type': 'weak_xcto', 'header': 'X-Content-Type-Options',
                'severity': 'medium', 'description': f'Should be nosniff, got {xcto}'
            })

    def _analyze_referrer_policy(self, headers, analysis):
        rp = headers.get('referrer-policy')
        if not rp: return
        weak = ['unsafe-url', 'no-referrer-when-downgrade', '']
        if rp.lower() in weak:
            analysis['vulnerabilities'].append({
                'type': 'weak_referrer', 'header': 'Referrer-Policy',
                'severity': 'low', 'description': f'Weak policy: {rp}'
            })
        analysis['detailed_analysis']['referrer_policy'] = {'header': rp}

    def _analyze_permissions_policy(self, headers, analysis):
        pp = headers.get('permissions-policy') or headers.get('feature-policy')
        if not pp: return
        analysis['detailed_analysis']['permissions_policy'] = {'header': pp}
        if 'camera=*' in pp or 'microphone=*' in pp or 'geolocation=*' in pp:
            analysis['vulnerabilities'].append({
                'type': 'permissive_permissions', 'header': 'Permissions-Policy',
                'severity': 'low', 'description': 'Allows sensitive features globally'
            })

    def _analyze_content_type(self, headers, analysis):
        ct = headers.get('content-type')
        if not ct: return
        analysis['detailed_analysis']['content_type'] = {'header': ct}
        if 'charset=' not in ct.lower():
            analysis['vulnerabilities'].append({
                'type': 'missing_charset', 'header': 'Content-Type',
                'severity': 'low', 'description': 'Missing charset'
            })

    def _analyze_dns_prefetch_control(self, headers, analysis):
        dns = headers.get('x-dns-prefetch-control')
        if dns:
            analysis['detailed_analysis']['dns_prefetch'] = {'header': dns}
            if dns.lower() != 'off':
                analysis['vulnerabilities'].append({
                    'type': 'dns_prefetch', 'header': 'X-DNS-Prefetch-Control',
                    'severity': 'low', 'description': 'DNS prefetching enabled'
                })

    def _check_ssl_certificate(self, url, analysis):
        try:
            from urllib.parse import urlparse
            hostname = urlparse(url).hostname
            if not hostname or not url.startswith('https://'): return
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ss:
                    cert = ss.getpeercert()
                    analysis['additional_checks']['ssl_certificate'] = {
                        'valid': True,
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'notAfter': cert.get('notAfter')
                    }
        except Exception as e:
            analysis['additional_checks']['ssl_certificate'] = {'valid': False, 'error': str(e)}
            analysis['vulnerabilities'].append({
                'type': 'ssl_error', 'severity': 'high',
                'description': f'SSL certificate error: {str(e)}'
            })

    def _check_server_banner(self, headers, analysis):
        server = headers.get('server')
        if server and re.search(r'\d+\.\d+', server):
            analysis['additional_checks']['server_banner'] = {'value': server}
            analysis['vulnerabilities'].append({
                'type': 'server_version', 'header': 'Server',
                'severity': 'low', 'description': f'Server version disclosed: {server}'
            })

    # ---------- Scoring ----------
    def _calculate_security_score(self, analysis: Dict):
        score = 100.0
        gc = self.grading_config

        crit = sum(1 for v in analysis['vulnerabilities'] if v['severity'] == 'critical')
        high = sum(1 for v in analysis['vulnerabilities'] if v['severity'] == 'high')
        med  = sum(1 for v in analysis['vulnerabilities'] if v['severity'] == 'medium')
        low  = sum(1 for v in analysis['vulnerabilities'] if v['severity'] == 'low')

        score += crit * gc.get('missing_critical', -10)
        score += high * gc.get('missing_high', -7)
        score += med  * gc.get('missing_medium', -4)
        score += low  * gc.get('weak_configuration', -5)

        info_disc = sum(1 for v in analysis['vulnerabilities'] if v['type'] == 'information_disclosure')
        score += info_disc * gc.get('vulnerable_header_found', -8)

        present_req = sum(1 for h in self.required_headers if h.lower() in analysis['headers_found'])
        score += min(present_req * gc.get('bonus_present_required', 3), 30)

        hsts = analysis['headers_found'].get('strict-transport-security', '')
        if hsts and re.search(r'max-age=(\d+)', hsts.lower()):
            if int(re.search(r'max-age=(\d+)', hsts.lower()).group(1)) >= 31536000:
                score += gc.get('bonus_strong_hsts', 10)

        csp = analysis['headers_found'].get('content-security-policy', '')
        if csp and 'unsafe-inline' not in csp.lower() and 'unsafe-eval' not in csp.lower():
            score += gc.get('bonus_strong_csp', 10)
        elif not csp and analysis['headers_found'].get('content-security-policy-report-only'):
            score += 5  # partial credit for report-only

        # Bonus for having all required headers
        if len(analysis['missing_required']) == 0:
            score += 5

        score = max(0, min(100, int(round(score))))
        analysis['security_score'] = score
        analysis['score_breakdown'] = {
            'critical': crit,
            'high': high,
            'medium': med,
            'low': low,
            'info_disclosure': info_disc,
            'present_required': present_req,
        }

    def _calculate_grade(self, score: int) -> str:
        th = self.grading_config.get('grade_thresholds', {})
        if score >= th.get('A', 85): return 'A'
        if score >= th.get('B', 70): return 'B'
        if score >= th.get('C', 55): return 'C'
        if score >= th.get('D', 35): return 'D'
        return 'F'

    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        recs = []
        for v in analysis['vulnerabilities']:
            if v['type'].startswith('missing_'):
                recs.append(f"CRITICAL: Add missing header {v['header']}")
            elif v['type'] == 'information_disclosure':
                recs.append(f"HIGH: Remove sensitive header {v['header']}")
            elif v['type'] == 'deprecated_header':
                recs.append(f"MEDIUM: Replace deprecated header {v['header']}")
            elif v['type'].startswith('weak_') or v['type'] == 'csp_report_only':
                recs.append(f"MEDIUM: Strengthen {v['header']} – {v['description']}")
        for h in analysis['missing_recommended']:
            recs.append(f"LOW: Consider adding recommended header {h}")
        for h in self.optional_headers:
            if h.lower() not in analysis['headers_found'] and h not in analysis['missing_required']:
                recs.append(f"LOW: Consider adding header {h} (modern browsers have safe defaults)")
        return sorted(set(recs))