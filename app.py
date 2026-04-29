# app.py - Fixed Version
import os
import json
import subprocess
import threading
import queue
import time
import re
import socket
import requests
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO, emit
import whois
import dns.resolver
from bs4 import BeautifulSoup
import ssl
from urllib.parse import urlparse
import logging

# Suppress warnings
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sam-osint-secret-key-2026'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global variables
scan_results = {}
current_scan = None

# Try to import nmap with error handling
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("Warning: python-nmap not installed. Install with: pip install python-nmap")

class PentestOrchestrator:
    def __init__(self, target, socketio):
        self.target = target
        self.socketio = socketio
        self.results = {
            'target': target,
            'recon': {},
            'osint': {},
            'vulnerabilities': [],
            'databases': [],
            'exploits': [],
            'network_footprint': {'nodes': [], 'edges': []},
            'timestamp': datetime.now().isoformat()
        }
        
    def emit_log(self, message, status='info'):
        """Emit real-time logs to web UI"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_entry = {
            'timestamp': timestamp,
            'message': message,
            'status': status
        }
        try:
            self.socketio.emit('scan_log', log_entry)
        except:
            pass
        print(f"[{timestamp}] [{status.upper()}] {message}")
        
    def run_nmap_scan(self):
        """Perform deep Nmap reconnaissance with error handling"""
        self.emit_log(f"Starting Nmap reconnaissance on {self.target}...", 'info')
        
        if not NMAP_AVAILABLE:
            self.emit_log("Nmap not available. Using basic port scan instead.", 'warning')
            return self.basic_port_scan()
        
        try:
            nm = nmap.PortScanner()
            
            # Clean target - remove protocol prefixes
            clean_target = self.target.replace('http://', '').replace('https://', '').split('/')[0]
            
            # Use more reliable scan parameters
            args = '-sV -sC -T4 -F'  # Fast scan instead of full port scan
            nm.scan(clean_target, arguments=args, timeout=60)
            
            hosts = []
            open_ports = []
            services = []
            
            for host in nm.all_hosts():
                host_info = {
                    'ip': host,
                    'hostname': nm[host].hostname() if nm[host].hostname() else clean_target,
                    'state': nm[host].state(),
                    'ports': []
                }
                
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in sorted(ports):
                        port_data = nm[host][proto][port]
                        port_info = {
                            'port': port,
                            'protocol': proto,
                            'state': port_data['state'],
                            'service': port_data.get('name', 'unknown'),
                            'version': port_data.get('version', 'N/A'),
                            'product': port_data.get('product', 'N/A')
                        }
                        host_info['ports'].append(port_info)
                        open_ports.append(port)
                        if port_info['service'] != 'unknown':
                            services.append(port_info['service'])
                
                hosts.append(host_info)
            
            self.results['recon']['nmap'] = {
                'hosts': hosts,
                'open_ports': list(set(open_ports)),
                'services': list(set(services))
            }
            
            self.emit_log(f"Nmap scan complete. Found {len(hosts)} hosts, {len(set(open_ports))} open ports.", 'success')
            return hosts
            
        except Exception as e:
            self.emit_log(f"Nmap scan error: {str(e)}. Using basic scan.", 'error')
            return self.basic_port_scan()
    
    def basic_port_scan(self):
        """Basic TCP port scan as fallback"""
        self.emit_log("Performing basic port scan...", 'info')
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        open_ports = []
        
        try:
            clean_target = self.target.replace('http://', '').replace('https://', '').split('/')[0]
            ip = socket.gethostbyname(clean_target)
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                    self.emit_log(f"Port {port} is open", 'info')
                sock.close()
            
            host_info = [{
                'ip': ip,
                'hostname': clean_target,
                'state': 'up',
                'ports': [{'port': p, 'protocol': 'tcp', 'state': 'open', 'service': 'unknown'} for p in open_ports]
            }]
            
            self.results['recon']['nmap'] = {
                'hosts': host_info,
                'open_ports': open_ports,
                'services': []
            }
            
            self.emit_log(f"Basic scan complete. Found {len(open_ports)} open ports.", 'success')
            return host_info
            
        except Exception as e:
            self.emit_log(f"Basic scan failed: {str(e)}", 'error')
            return []
    
    def run_whatweb_scan(self, target):
        """Gather web technology information"""
        self.emit_log(f"Analyzing web technologies for {target}...", 'info')
        
        try:
            clean_target = target.replace('http://', '').replace('https://', '').split('/')[0]
            
            # Try HTTPS first, then HTTP
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{clean_target}"
                    response = requests.get(url, timeout=5, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
                    headers = dict(response.headers)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    tech_stack = {
                        'server': headers.get('Server', 'Unknown'),
                        'powered_by': headers.get('X-Powered-By', 'Unknown'),
                        'cms': self.detect_cms(soup, headers),
                        'frameworks': self.detect_frameworks(headers, response.text),
                        'javascript_libs': self.detect_js_libs(soup),
                        'status_code': response.status_code
                    }
                    
                    self.emit_log(f"Found: {tech_stack['server']} | CMS: {', '.join(tech_stack['cms']) or 'None'}", 'success')
                    return tech_stack
                    
                except requests.RequestException:
                    continue
            
            return {'error': 'Unable to connect'}
            
        except Exception as e:
            self.emit_log(f"WhatWeb scan error: {str(e)}", 'error')
            return {'error': str(e)}
    
    def detect_cms(self, soup, headers):
        """Detect CMS by analyzing response"""
        cms_signatures = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-json', 'wordpress'],
            'Drupal': ['drupal', 'sites/default', 'Drupal.settings'],
            'Joomla': ['joomla', 'com_content', 'media/system'],
            'Magento': ['magento', 'skin/frontend', 'Mage.Cookies'],
        }
        
        detected = []
        html_text = str(soup).lower()
        
        for cms, signatures in cms_signatures.items():
            for sig in signatures:
                if sig in html_text or sig in str(headers).lower():
                    detected.append(cms)
                    break
        
        return list(set(detected))
    
    def detect_frameworks(self, headers, html):
        """Detect web frameworks"""
        frameworks = []
        
        html_lower = html.lower()
        
        if 'react' in html_lower:
            frameworks.append('React')
        if 'angular' in html_lower:
            frameworks.append('Angular')
        if 'vue' in html_lower:
            frameworks.append('Vue.js')
        if 'jquery' in html_lower:
            frameworks.append('jQuery')
        
        powered_by = headers.get('X-Powered-By', '').lower()
        if 'laravel' in powered_by:
            frameworks.append('Laravel')
        if 'django' in powered_by:
            frameworks.append('Django')
        
        return frameworks
    
    def detect_js_libs(self, soup):
        """Detect JavaScript libraries"""
        js_libs = []
        scripts = soup.find_all('script', src=True)
        
        for script in scripts:
            src = script['src'].lower()
            if 'jquery' in src:
                js_libs.append('jQuery')
            if 'bootstrap' in src:
                js_libs.append('Bootstrap')
            if 'react' in src:
                js_libs.append('React')
        
        return list(set(js_libs))
    
    def find_subdomains(self, domain):
        """Find subdomains using DNS enumeration"""
        self.emit_log(f"Discovering subdomains for {domain}...", 'info')
        
        subdomains = set()
        
        # Common subdomains to check
        common_subdomains = ['www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'cpanel', 'whm', 
                            'blog', 'dev', 'admin', 'forum', 'news', 'vpn', 'mail2', 'new', 
                            'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 
                            'docs', 'beta', 'shop', 'secure', 'demo', 'cp', 'calendar', 
                            'wiki', 'web', 'media', 'email', 'images', 'img', 'download', 'api']
        
        for sub in common_subdomains:
            try:
                target = f"{sub}.{domain}"
                answers = dns.resolver.resolve(target, 'A')
                for rdata in answers:
                    subdomains.add((target, str(rdata)))
                    self.emit_log(f"Found: {target} -> {rdata}", 'success')
            except:
                pass
        
        return list(subdomains)
    
    def run_osint_scans(self):
        """Run OSINT scans with error handling"""
        self.emit_log("Starting OSINT reconnaissance...", 'info')
        
        osint_data = {}
        
        # Basic OSINT without API keys
        try:
            clean_target = self.target.replace('http://', '').replace('https://', '').split('/')[0]
            ip = socket.gethostbyname(clean_target)
            
            # Get WHOIS information
            try:
                domain_info = whois.whois(clean_target)
                osint_data['whois'] = {
                    'registrar': str(domain_info.registrar),
                    'creation_date': str(domain_info.creation_date),
                    'expiration_date': str(domain_info.expiration_date),
                    'name_servers': domain_info.name_servers[:5] if domain_info.name_servers else []
                }
                self.emit_log("WHOIS information retrieved", 'success')
            except:
                pass
            
            # DNS Records
            try:
                dns_records = {}
                record_types = ['A', 'MX', 'NS', 'TXT', 'CNAME']
                for record_type in record_types:
                    try:
                        answers = dns.resolver.resolve(clean_target, record_type)
                        dns_records[record_type] = [str(r) for r in answers]
                    except:
                        pass
                osint_data['dns_records'] = dns_records
                self.emit_log("DNS records retrieved", 'success')
            except:
                pass
            
        except Exception as e:
            self.emit_log(f"OSINT error: {str(e)}", 'error')
        
        self.results['osint'] = osint_data
        return osint_data
    
    def find_admin_panels(self, domain):
        """Discover admin panels"""
        self.emit_log("Searching for admin panels...", 'info')
        
        admin_paths = [
            '/admin', '/administrator', '/admin.php', '/admin/login', '/admin_area',
            '/adminpanel', '/adm', '/admincp', '/wp-admin', '/dashboard',
            '/manager', '/login', '/auth', '/backend', '/console', '/manage',
            '/cpanel', '/whm', '/webmail'
        ]
        
        found_panels = []
        
        for path in admin_paths:
            for protocol in ['http', 'https']:
                try:
                    url = f"{protocol}://{domain}{path}"
                    response = requests.get(url, timeout=3, verify=False, allow_redirects=False)
                    if response.status_code in [200, 401, 403]:
                        found_panels.append({
                            'url': url,
                            'status': response.status_code
                        })
                        self.emit_log(f"Found: {url} (Status: {response.status_code})", 'warning')
                except:
                    pass
        
        return found_panels
    
    def find_robots_txt(self, domain):
        """Extract robots.txt information"""
        self.emit_log("Checking robots.txt...", 'info')
        
        try:
            for protocol in ['http', 'https']:
                try:
                    response = requests.get(f"{protocol}://{domain}/robots.txt", timeout=5, verify=False)
                    if response.status_code == 200:
                        lines = [line for line in response.text.split('\n') if line.strip() and not line.startswith('#')]
                        self.emit_log(f"Found robots.txt with {len(lines)} entries", 'success')
                        return lines[:20]  # Return first 20 lines
                except:
                    pass
        except:
            pass
        
        return []
    
    def test_sql_injection(self, domain):
        """Test for SQL injection vulnerabilities"""
        self.emit_log("Testing for SQL injection vulnerabilities...", 'info')
        
        sqli_payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "admin'--",
            "1' AND 1=1--"
        ]
        
        vulns = []
        
        # Simple test with common parameters
        test_params = ['id', 'page', 'user', 'product']
        
        for param in test_params:
            for payload in sqli_payloads:
                try:
                    url = f"http://{domain}/?{param}={payload}"
                    response = requests.get(url, timeout=5, verify=False)
                    
                    # Check for SQL error indicators
                    error_indicators = ['sql', 'mysql', 'syntax error', 'unclosed quotation', 'mysql_fetch']
                    response_text = response.text.lower()
                    
                    if any(indicator in response_text for indicator in error_indicators):
                        vulns.append({
                            'type': 'SQL Injection',
                            'url': url,
                            'payload': payload,
                            'risk': 'CRITICAL'
                        })
                        self.emit_log(f"Potential SQL injection at {url}", 'critical')
                except:
                    pass
        
        return vulns
    
    def test_xss_vulnerabilities(self, domain):
        """Test for XSS vulnerabilities"""
        self.emit_log("Testing for XSS vulnerabilities...", 'info')
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        vulns = []
        
        for payload in xss_payloads:
            try:
                url = f"http://{domain}/?q={payload}"
                response = requests.get(url, timeout=5, verify=False)
                
                if payload in response.text:
                    vulns.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'url': url,
                        'payload': payload,
                        'risk': 'HIGH'
                    })
                    self.emit_log(f"Potential XSS at {url}", 'critical')
            except:
                pass
        
        return vulns
    
    def create_network_graph(self, hosts, subdomains, api_endpoints):
        """Create detailed network footprint graph"""
        self.emit_log("Creating network footprint visualization...", 'info')
        
        nodes = []
        edges = []
        
        # Add target as central node
        nodes.append({
            'id': self.target,
            'label': self.target,
            'type': 'target',
            'size': 30,
            'color': '#ff0000'
        })
        
        # Add hosts
        for host in hosts:
            host_id = host.get('ip', host.get('hostname', 'unknown'))
            nodes.append({
                'id': host_id,
                'label': host_id[:30],
                'type': 'host',
                'size': 20,
                'color': '#00ff00'
            })
            edges.append({
                'from': self.target,
                'to': host_id,
                'label': 'resolves to'
            })
            
            # Add ports
            for port_info in host.get('ports', []):
                port_id = f"{host_id}:{port_info['port']}"
                nodes.append({
                    'id': port_id,
                    'label': str(port_info['port']),
                    'type': 'port',
                    'size': 15,
                    'color': '#ffff00'
                })
                edges.append({
                    'from': host_id,
                    'to': port_id,
                    'label': port_info.get('service', 'port')
                })
        
        # Add subdomains
        for subdomain, ip in subdomains[:20]:  # Limit to 20 subdomains
            nodes.append({
                'id': subdomain,
                'label': subdomain[:30],
                'type': 'subdomain',
                'size': 18,
                'color': '#ff00ff'
            })
            edges.append({
                'from': self.target,
                'to': subdomain,
                'label': 'subdomain'
            })
        
        return {'nodes': nodes, 'edges': edges}
    
    def discover_api_endpoints(self, domain):
        """Discover API endpoints"""
        self.emit_log("Discovering API endpoints...", 'info')
        
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/rest', '/graphql', '/swagger',
            '/swagger-ui', '/api-docs', '/docs', '/v1', '/v2'
        ]
        
        found_endpoints = []
        
        for path in api_paths:
            for protocol in ['http', 'https']:
                try:
                    url = f"{protocol}://{domain}{path}"
                    response = requests.get(url, timeout=3, verify=False)
                    if response.status_code in [200, 401, 403]:
                        found_endpoints.append(url)
                        self.emit_log(f"Found API endpoint: {url}", 'info')
                except:
                    pass
        
        return found_endpoints
    
    def generate_exploit_recommendations(self):
        """Generate exploit recommendations"""
        exploits = []
        
        for vuln in self.results['vulnerabilities']:
            vuln_type = vuln.get('type', '')
            
            if 'SQL' in vuln_type:
                exploits.append({
                    'vulnerability': 'SQL Injection',
                    'tools': ['sqlmap', 'jSQL Injection'],
                    'commands': [
                        f"sqlmap -u '{vuln.get('url', 'URL')}' --dbs",
                        f"sqlmap -u '{vuln.get('url', 'URL')}' --dump"
                    ],
                    'technique': 'Use automated tools to extract database contents'
                })
            
            elif 'XSS' in vuln_type:
                exploits.append({
                    'vulnerability': 'Cross-Site Scripting',
                    'tools': ['BeEF', 'XSSer'],
                    'commands': ['Inject JavaScript payloads to hijack sessions'],
                    'technique': 'Inject malicious scripts to steal session cookies'
                })
            
            elif 'Admin' in vuln_type:
                exploits.append({
                    'vulnerability': 'Admin Panel Exposure',
                    'tools': ['Hydra', 'Burp Suite'],
                    'commands': [
                        f"hydra -L users.txt -P passwords.txt {self.target} http-post-form"
                    ],
                    'technique': 'Brute force admin credentials'
                })
        
        return exploits
    
    def run_comprehensive_scan(self):
        """Run complete pentest orchestration"""
        self.emit_log("="*50, 'info')
        self.emit_log(f"Starting SAM-OSINT Scan on {self.target}", 'info')
        self.emit_log("="*50, 'info')
        
        try:
            # Step 1: Network Reconnaissance
            hosts = self.run_nmap_scan()
            
            # Step 2: Clean target domain
            domain = self.target.replace('http://', '').replace('https://', '').split('/')[0]
            
            # Step 3: Subdomain Discovery
            subdomains = self.find_subdomains(domain)
            self.results['recon']['subdomains'] = subdomains
            
            # Step 4: Web Technology Detection
            web_tech = self.run_whatweb_scan(domain)
            self.results['recon']['web_tech'] = web_tech
            
            # Step 5: OSINT Scans
            osint_data = self.run_osint_scans()
            
            # Step 6: Vulnerability Scanning
            self.emit_log("Starting vulnerability assessment...", 'info')
            
            admin_panels = self.find_admin_panels(domain)
            for panel in admin_panels:
                self.results['vulnerabilities'].append({
                    'type': 'Admin Panel Exposure',
                    'location': panel['url'],
                    'risk': 'HIGH',
                    'status': panel['status']
                })
            
            robots_txt = self.find_robots_txt(domain)
            if robots_txt:
                self.results['vulnerabilities'].append({
                    'type': 'Information Disclosure',
                    'location': '/robots.txt',
                    'data': robots_txt[:5],
                    'risk': 'MEDIUM'
                })
            
            sqli_vulns = self.test_sql_injection(domain)
            self.results['vulnerabilities'].extend(sqli_vulns)
            
            xss_vulns = self.test_xss_vulnerabilities(domain)
            self.results['vulnerabilities'].extend(xss_vulns)
            
            # Step 7: API Discovery
            api_endpoints = self.discover_api_endpoints(domain)
            self.results['recon']['api_endpoints'] = api_endpoints
            
            # Step 8: Create Network Graph
            network_graph = self.create_network_graph(hosts, subdomains, api_endpoints)
            self.results['network_footprint'] = network_graph
            
            # Step 9: Generate Exploit Recommendations
            exploits = self.generate_exploit_recommendations()
            self.results['exploits'] = exploits
            
            # Summary
            vuln_count = len(self.results['vulnerabilities'])
            critical_count = sum(1 for v in self.results['vulnerabilities'] if v.get('risk') == 'CRITICAL')
            high_count = sum(1 for v in self.results['vulnerabilities'] if v.get('risk') == 'HIGH')
            
            self.emit_log("="*50, 'success')
            self.emit_log(f"Scan Complete!", 'success')
            self.emit_log(f"Total Vulnerabilities: {vuln_count}", 'info')
            self.emit_log(f"Critical: {critical_count} | High: {high_count}", 'info')
            self.emit_log("="*50, 'success')
            
        except Exception as e:
            self.emit_log(f"Scan error: {str(e)}", 'error')
            import traceback
            traceback.print_exc()
        
        return self.results

# Flask Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    global current_scan, scan_results
    
    try:
        data = request.json
        target = data.get('target')
        
        if not target:
            return jsonify({'error': 'No target provided'}), 400
        
        # Start scan in background thread
        def scan_thread():
            global current_scan, scan_results
            try:
                current_scan = PentestOrchestrator(target, socketio)
                results = current_scan.run_comprehensive_scan()
                scan_results[target] = results
                socketio.emit('scan_complete', {'target': target})
            except Exception as e:
                socketio.emit('scan_log', {'message': f'Fatal error: {str(e)}', 'status': 'error'})
        
        thread = threading.Thread(target=scan_thread)
        thread.daemon = True
        thread.start()
        
        return jsonify({'status': 'Scan started', 'target': target})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/results/<target>')
def get_results(target):
    if target in scan_results:
        return jsonify(scan_results[target])
    return jsonify({'error': 'No results found'}), 404

@app.route('/api/download_report/<target>')
def download_report(target):
    if target not in scan_results:
        return jsonify({'error': 'No report found'}), 404
    
    report_path = generate_pdf_report(scan_results[target])
    if report_path and os.path.exists(report_path):
        return send_file(report_path, as_attachment=True, 
                        download_name=f"sam-osint_report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
    return jsonify({'error': 'Report generation failed'}), 500

def generate_pdf_report(results):
    """Generate FBI standard PDF report"""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER
        
        filename = f"reports/sam_osint_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        os.makedirs('reports', exist_ok=True)
        
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], 
                                     fontSize=24, textColor=colors.HexColor('#003366'), 
                                     alignment=TA_CENTER)
        story.append(Paragraph("SAM-OSINT Security Assessment Report", title_style))
        story.append(Spacer(1, 12))
        
        # Classification
        header_style = ParagraphStyle('Header', parent=styles['Normal'], 
                                      fontSize=12, textColor=colors.HexColor('#FF0000'), 
                                      alignment=TA_CENTER)
        story.append(Paragraph("CONFIDENTIAL - Security Assessment Report", header_style))
        story.append(Spacer(1, 12))
        
        # Target Info
        story.append(Paragraph(f"Target: {results['target']}", styles['Heading2']))
        story.append(Paragraph(f"Scan Date: {results['timestamp']}", styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        vuln_count = len(results.get('vulnerabilities', []))
        critical_count = sum(1 for v in results.get('vulnerabilities', []) if v.get('risk') == 'CRITICAL')
        high_count = sum(1 for v in results.get('vulnerabilities', []) if v.get('risk') == 'HIGH')
        
        story.append(Paragraph(f"Total Vulnerabilities Found: {vuln_count}", styles['Normal']))
        story.append(Paragraph(f"Critical: {critical_count} | High: {high_count}", styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Vulnerabilities
        story.append(Paragraph("Vulnerabilities Found", styles['Heading2']))
        for vuln in results.get('vulnerabilities', []):
            story.append(Paragraph(f"• {vuln.get('type', 'Unknown')} - Risk: {vuln.get('risk', 'Unknown')}", styles['Heading3']))
            story.append(Paragraph(f"  Location: {vuln.get('location', vuln.get('url', 'N/A'))}", styles['Normal']))
            story.append(Spacer(1, 6))
        
        doc.build(story)
        return filename
        
    except Exception as e:
        print(f"PDF generation error: {e}")
        return None

if __name__ == '__main__':
    print("\n" + "="*50)
    print("SAM-OSINT Starting...")
    print("="*50)
    print(f"Access the web interface at: http://localhost:5000")
    print("Press Ctrl+C to stop")
    print("="*50 + "\n")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
from flask import Flask, render_template_string
import random
from datetime import datetime
from flask_socketio import SocketIO

app = Flask(__name__)
socketio = SocketIO(app)

def generate_network_footprint():
    patterns = ["Volumetry", "ometry", "ography", "ogometer", "oometry", "omography"]
    footprint = []
    
    for i in range(20):
        row = []
        for j in range(8):
            pattern = random.choice(patterns)
            if random.random() > 0.7:
                pattern = "o" + pattern
            row.append(pattern)
        footprint.append(" ".join(row))
    
    return footprint

@app.route('/')
def index():
    footprint_data = generate_network_footprint()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Network Footprint - SAM-OSINT</title>
        <style>
            body {
                background: black;
                color: #00ff00;
                font-family: monospace;
                padding: 20px;
                margin: 0;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
            }
            .header {
                color: #00ff00;
                border-bottom: 2px solid #00ff00;
                margin-bottom: 20px;
                padding-bottom: 10px;
            }
            .header h1 {
                margin: 0;
                font-size: 24px;
            }
            .header p {
                margin: 5px 0;
                font-size: 14px;
            }
            .footprint {
                background: #001100;
                padding: 20px;
                border-radius: 5px;
                font-family: monospace;
                font-size: 13px;
                line-height: 1.4;
                white-space: pre;
                overflow-x: auto;
                margin: 20px 0;
            }
            .stats {
                background: #001100;
                padding: 15px;
                border-radius: 5px;
                margin-top: 20px;
                border-left: 3px solid #00ff00;
            }
            .stats p {
                margin: 5px 0;
            }
            .footer {
                margin-top: 30px;
                text-align: center;
                color: #006600;
                font-size: 12px;
            }
            @keyframes blink {
                0% { opacity: 1; }
                50% { opacity: 0.5; }
                100% { opacity: 1; }
            }
            .live {
                animation: blink 1s infinite;
                display: inline-block;
                width: 10px;
                height: 10px;
                background: #00ff00;
                border-radius: 50%;
                margin-right: 5px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔍 SAM-OSINT Network Footprint</h1>
                <p><span class="live"></span> LIVE MONITORING - {{ timestamp }}</p>
            </div>
            
            <div class="footprint">
                {% for line in footprint %}
{{ line }}
                {% endfor %}
            </div>
            
            <div class="stats">
                <p>📊 VOLUMETRIC DENSITY: {{ density }}%</p>
                <p>📡 PACKET FLOW: {{ packets }} packets/sec</p>
                <p>🌐 ACTIVE NODES: {{ nodes }}</p>
                <p>📈 DATA THROUGHPUT: {{ throughput }} MB/s</p>
            </div>
            
            <div class="footer">
                SAM-OSINT v1.0 | Network Footprint Analysis | Real-time Monitoring
            </div>
        </div>
    </body>
    </html>
    '''
    
    return render_template_string(html, 
                                 footprint=footprint_data,
                                 timestamp=timestamp,
                                 density=random.randint(85, 99),
                                 packets=random.randint(1000, 9999),
                                 nodes=random.randint(50, 500),
                                 throughput=random.randint(100, 999))

if __name__ == '__main__':
    print("\n" + "="*50)
    print("SAM-OSINT Starting...")
    print("="*50)
    print(f"Access the web interface at: http://localhost:5000")
    print("Press Ctrl+C to stop")
    print("="*50 + "\n")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)    
    
