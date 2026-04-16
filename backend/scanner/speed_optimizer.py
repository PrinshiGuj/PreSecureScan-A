import asyncio
import aiohttp
import socket
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import threading
from queue import Queue
import time

class SpeedOptimizer:
    """Optimizes scan speed using async and parallel processing"""
    
    def __init__(self, max_workers=50):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
    async def async_http_request(self, session, url, timeout=5):
        """Async HTTP request"""
        try:
            async with session.get(url, timeout=timeout, ssl=False) as response:
                return await response.text()
        except:
            return None
    
    async def scan_multiple_urls(self, urls):
        """Scan multiple URLs concurrently"""
        async with aiohttp.ClientSession() as session:
            tasks = [self.async_http_request(session, url) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    
    def parallel_port_scan(self, target, ports):
        """Parallel port scanning"""
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target, port))
                if result == 0:
                    return port
                sock.close()
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            results = executor.map(scan_port, ports)
            open_ports = [port for port in results if port]
        
        return open_ports
    
    def parallel_vulnerability_test(self, test_func, payloads, target):
        """Run vulnerability tests in parallel"""
        results = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(test_func, target, payload): payload 
                      for payload in payloads}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
        
        return results
    
    def optimize_scan_order(self, vulnerabilities):
        """Prioritize critical vulnerabilities first"""
        priority_order = ['Critical', 'High', 'Medium', 'Low']
        sorted_vulns = sorted(vulnerabilities, 
                             key=lambda x: priority_order.index(x.get('severity', 'Low')))
        return sorted_vulns

# Global instance
optimizer = SpeedOptimizer(max_workers=50)