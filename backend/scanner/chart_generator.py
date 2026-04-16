"""
Chart Generator for Visual Reports
"""

import matplotlib.pyplot as plt
import io
import base64
from datetime import datetime

class ChartGenerator:
    """Generate beautiful security charts"""
    
    def generate_radar_chart(self, vulnerabilities):
        """Generate radar chart for vulnerability distribution"""
        categories = ['SQLi', 'XSS', 'LFI', 'CMDi', 'Config', 'Auth']
        counts = []
        
        for cat in categories:
            count = sum(1 for v in vulnerabilities if cat.lower() in v.get('type', '').lower())
            counts.append(count)
        
        fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(projection='polar'))
        angles = [n / float(len(categories)) * 2 * 3.14159 for n in range(len(categories))]
        
        ax.plot(angles, counts, 'o-', linewidth=2, color='#667eea')
        ax.fill(angles, counts, alpha=0.25, color='#667eea')
        ax.set_xticks(angles)
        ax.set_xticklabels(categories)
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.getvalue()).decode()
        plt.close()
        
        return f"data:image/png;base64,{image_base64}"
    
    def generate_trend_chart(self, scan_history):
        """Generate security trend line chart"""
        dates = [h.get('date', datetime.now()) for h in scan_history]
        scores = [h.get('score', 0) for h in scan_history]
        
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.plot(dates, scores, marker='o', linewidth=2, color='#00ff88')
        ax.fill_between(dates, scores, alpha=0.3, color='#00ff88')
        ax.set_xlabel('Scan Date')
        ax.set_ylabel('Security Score')
        ax.set_title('Security Score Trend')
        ax.grid(True, alpha=0.3)
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.getvalue()).decode()
        plt.close()
        
        return f"data:image/png;base64,{image_base64}"