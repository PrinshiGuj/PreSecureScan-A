import json
from datetime import datetime
import os
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER

class ReportGenerator:
    def __init__(self, target, vulnerabilities, fixes, logs, target_type='website'):
        self.target = target
        self.vulnerabilities = vulnerabilities
        self.fixes = fixes
        self.logs = logs
        self.target_type = target_type
        self.report_dir = "reports"
        
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
    
    def calculate_security_score(self):
        if not self.vulnerabilities:
            return 100
        critical = sum(1 for v in self.vulnerabilities if v.get('severity') == 'Critical')
        high = sum(1 for v in self.vulnerabilities if v.get('severity') == 'High')
        medium = sum(1 for v in self.vulnerabilities if v.get('severity') == 'Medium')
        score = 100 - (critical * 15 + high * 8 + medium * 4)
        return max(0, min(100, score))
    
    def generate_pdf_report(self):
        """Generate PDF report"""
        score = self.calculate_security_score()
        filename = f"{self.report_dir}/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        doc = SimpleDocTemplate(filename, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        story.append(Paragraph("PreSecureScan A - Security Report", styles['Title']))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"Target: {self.target}", styles['Normal']))
        story.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Score
        story.append(Paragraph(f"Security Score: {score}/100", styles['Heading1']))
        story.append(Spacer(1, 20))
        
        # Vulnerabilities
        story.append(Paragraph("Vulnerabilities Found", styles['Heading2']))
        for v in self.vulnerabilities:
            story.append(Paragraph(f"<b>{v.get('name', 'Unknown')}</b> - Severity: {v.get('severity', 'Medium')}", styles['Normal']))
            story.append(Paragraph(f"Description: {v.get('description', 'N/A')}", styles['Normal']))
            story.append(Paragraph(f"Remediation: {v.get('remediation', 'Review security practices')}", styles['Normal']))
            story.append(Spacer(1, 10))
        
        doc.build(story)
        return filename
    
    def generate_html_report(self):
        # HTML generation code (same as before)
        score = self.calculate_security_score()
        html = f"""<!DOCTYPE html>
<html>
<head><title>Security Report</title></head>
<body>
<h1>PreSecureScan A - Security Report</h1>
<p>Target: {self.target}</p>
<p>Score: {score}/100</p>
<h2>Vulnerabilities ({len(self.vulnerabilities)})</h2>
"""
        for v in self.vulnerabilities:
            html += f"""
<div style="border:1px solid #ddd; margin:10px; padding:10px">
<h3>{v.get('name', 'Unknown')}</h3>
<p>Severity: {v.get('severity', 'Medium')}</p>
<p>Description: {v.get('description', 'N/A')}</p>
<p>Remediation: {v.get('remediation', 'Review security practices')}</p>
</div>
"""
        html += "</body></html>"
        
        filename = f"{self.report_dir}/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        return filename
    
    def generate_json(self):
        report = {
            'target': self.target,
            'scan_date': datetime.now().isoformat(),
            'security_score': self.calculate_security_score(),
            'vulnerabilities': self.vulnerabilities,
            'total_vulnerabilities': len(self.vulnerabilities)
        }
        filename = f"{self.report_dir}/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        return filename