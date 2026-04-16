import socket
import requests
import threading
import ssl
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ReconnaissanceEngine:
    def __init__(self, target):
        self.target = target
        self.results = {'dns': {}, 'ports': [], 'services': {}, 'technologies': {}}
        self.common_ports = [80, 443, 22, 21, 25, 3306, 5432, 8080, 8443, 3000, 5000, 8000]
        
    def run_recon(self, progress_callback=None):
        if progress_callback:
            progress_callback(10, "[*] DNS Enumeration...")
        self.dns_enumeration()
        
        if progress_callback:
            progress_callback(30, "[*] Port Scanning...")
        self.port_scan()
        
        if progress_callback:
            progress_callback(50, "[*] Service Detection...")
        self.service_detection()
        
        if progress_callback:
            progress_callback(70, "[*] Technology Detection...")
        self.detect_technologies()
        
        return self.results
    
    def dns_enumeration(self):
        try:
            ip = socket.gethostbyname(self.target)
            self.results['dns']['ip_address'] = ip
        except Exception as e:
            self.results['dns']['error'] = str(e)
    
    def port_scan(self):
        open_ports = []
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                if sock.connect_ex((self.target, port)) == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        threads = [threading.Thread(target=scan_port, args=(p,)) for p in self.common_ports]
        for t in threads: t.start()
        for t in threads: t.join()
        
        self.results['ports'] = sorted(open_ports)
    
    def service_detection(self):
        for port in self.results['ports']:
            try:
                service = socket.getservbyport(port)
                self.results['services'][port] = {'service': service, 'status': 'open'}
            except:
                self.results['services'][port] = {'service': 'unknown', 'status': 'open'}
    
    def detect_technologies(self):
        for port in [80, 443, 8080, 8443]:
            if port in self.results['ports']:
                protocol = 'https' if port in [443, 8443] else 'http'
                try:
                    resp = requests.get(f"{protocol}://{self.target}:{port}", timeout=5, verify=False)
                    if resp.headers.get('Server'):
                        self.results['technologies']['server'] = resp.headers['Server']
                    break
                except:
                    pass