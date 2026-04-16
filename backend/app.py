from flask import Flask, render_template, request, jsonify, Response, send_file
import json
import threading
import time
import sys
import os
import socket
import ipaddress

# Add scanner to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'scanner'))

from scanner.recon import ReconnaissanceEngine
from scanner.vuln_scanner import VulnerabilityScanner
from scanner.auto_fix import AutoFixEngine
from scanner.report_gen import ReportGenerator
from scanner.ip_scanner import IPScanner
from scanner.mobsf_scanner import mobsf_scanner

# Try to import optional features (create these files if you want)
try:
    from scanner.ai_risk_predictor import AIRiskPredictor
    from scanner.compliance_checker import ComplianceChecker
    from scanner.auto_remediation import AutoRemediation
    from scanner.threat_intel import ThreatIntelligence
    OPTIONAL_FEATURES = True
except ImportError:
    OPTIONAL_FEATURES = False
    print("[*] Optional features not available. Run 'pip install -r requirements.txt'")

app = Flask(__name__)
app.config['SECRET_KEY'] = 'presecurescan2024'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Store scan results
scan_results = {}
scan_status = {}
scan_logs = {}

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target', '')
    target_type = data.get('type', 'website')
    
    if not target:
        return jsonify({'error': 'Target required'}), 400
    
    scan_logs[target] = []
    scan_status[target] = 'running'
    
    thread = threading.Thread(target=run_scan, args=(target, target_type))
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'scan_started', 'target': target, 'type': target_type})

@app.route('/api/scan-mobile', methods=['POST'])
def scan_mobile():
    """Handle mobile APK/IPA file upload and scan"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Save uploaded file
    upload_dir = "uploads"
    if not os.path.exists(upload_dir):
        os.makedirs(upload_dir)
    
    filepath = os.path.join(upload_dir, file.filename)
    file.save(filepath)
    
    target = file.filename
    target_type = 'mobile'
    
    scan_logs[target] = []
    scan_status[target] = 'running'
    
    thread = threading.Thread(target=run_mobile_scan, args=(target, filepath))
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'scan_started', 'target': target, 'type': 'mobile'})

def run_mobile_scan(target, filepath):
    """Run mobile app scan"""
    try:
        add_log(target, "[+] Starting Mobile Security Scan for " + target, 5)
        
        if filepath.endswith('.apk'):
            add_log(target, "[*] Analyzing Android APK file...", 20)
            results = mobsf_scanner.scan_apk(filepath)
        elif filepath.endswith('.ipa'):
            add_log(target, "[*] Analyzing iOS IPA file...", 20)
            results = mobsf_scanner.scan_ipa(filepath)
        else:
            add_log(target, "[-] Unsupported file format. Use .apk or .ipa", -1)
            scan_status[target] = 'error'
            return
        
        vulnerabilities = results.get('vulnerabilities', [])
        score = results.get('security_score', 0)
        
        # Generate fixes for mobile vulnerabilities
        fix_engine = AutoFixEngine(vulnerabilities)
        fixes = fix_engine.generate_all_fixes()
        
        # Generate report
        report_gen = ReportGenerator(target, vulnerabilities, fixes, scan_logs.get(target, []), 'mobile')
        reports = {
            'html': report_gen.generate_html_report(),
            'pdf': report_gen.generate_pdf_report(),
            'json': report_gen.generate_json()
        }
        
        scan_results[target] = {
            'vulnerabilities': vulnerabilities,
            'fixes': fixes,
            'reports': reports,
            'score': score,
            'total_vulns': len(vulnerabilities),
            'mobile_info': {
                'file_name': results.get('file_name'),
                'file_size': results.get('file_size'),
                'file_hash': results.get('file_hash'),
                'recommendations': results.get('recommendations', [])
            }
        }
        
        scan_status[target] = 'completed'
        add_log(target, "[✓] Mobile Scan Complete! Security Score: " + str(score) + "/100", 100)
        
        # Cleanup uploaded file
        try:
            os.remove(filepath)
        except:
            pass
        
    except Exception as e:
        scan_status[target] = 'error'
        add_log(target, "[-] Error: " + str(e), -1)

@app.route('/api/status/<target>')
def get_status(target):
    if target in scan_status:
        return jsonify({
            'status': scan_status.get(target, 'unknown'),
            'logs': scan_logs.get(target, [])
        })
    return jsonify({'status': 'not_found'}), 404

def add_log(target, message, progress=None):
    log_entry = {'timestamp': time.time(), 'message': message, 'progress': progress}
    if target not in scan_logs:
        scan_logs[target] = []
    scan_logs[target].append(log_entry)

def run_scan(target, target_type):
    """Execute the complete scan process"""
    try:
        add_log(target, "[+] Starting " + target_type.upper() + " security scan on " + target, 5)
        
        if target_type == 'ip':
            add_log(target, "[*] Phase 1: IP Address Analysis", 10)
            ip_scanner = IPScanner(target)
            results = ip_scanner.scan(lambda p, m: add_log(target, m, p))
            
            vulnerabilities = results.get('vulnerabilities', [])
            score = results.get('security_score', 0)
            
            scan_results[target] = {
                'vulnerabilities': vulnerabilities,
                'fixes': [],
                'score': score,
                'total_vulns': len(vulnerabilities),
                'ip_info': results.get('ip_info', {}),
                'open_ports': results.get('open_ports', []),
                'services': results.get('services', {})
            }
            
        elif target_type == 'website':
            add_log(target, "[*] Phase 1: Reconnaissance", 10)
            recon = ReconnaissanceEngine(target)
            recon_results = recon.run_recon(lambda p, m: add_log(target, m, p))
            
            add_log(target, "[*] Phase 2: Vulnerability Discovery", 30)
            scanner = VulnerabilityScanner(target, recon_results)
            vulnerabilities = scanner.scan_all(lambda p, m: add_log(target, m, p))
            
            add_log(target, "[*] Phase 3: Generating Auto-Fixes", 70)
            fix_engine = AutoFixEngine(vulnerabilities)
            fixes = fix_engine.generate_all_fixes()
            
            add_log(target, "[*] Phase 4: Generating Security Report", 85)
            report_gen = ReportGenerator(target, vulnerabilities, fixes, scan_logs.get(target, []), 'website')
            reports = {
                'html': report_gen.generate_html_report(),
                'pdf': report_gen.generate_pdf_report(),
                'json': report_gen.generate_json()
            }
            score = report_gen.calculate_security_score()
            
            scan_results[target] = {
                'vulnerabilities': vulnerabilities,
                'fixes': fixes,
                'reports': reports,
                'score': score,
                'total_vulns': len(vulnerabilities)
            }
        
        scan_status[target] = 'completed'
        add_log(target, "[✓] Scan Complete! Security Score: " + str(score) + "/100", 100)
        
    except Exception as e:
        scan_status[target] = 'error'
        add_log(target, "[-] Error: " + str(e), -1)
        import traceback
        traceback.print_exc()

@app.route('/api/results/<target>')
def get_results(target):
    if target in scan_results:
        return jsonify(scan_results[target])
    return jsonify({'error': 'No results found'}), 404

@app.route('/api/report/<target>/<format>')
def download_report(target, format):
    """Download report in specified format (html, pdf, json)"""
    if target in scan_results and 'reports' in scan_results[target]:
        reports = scan_results[target]['reports']
        if format == 'pdf' and 'pdf' in reports:
            return send_file(reports['pdf'], as_attachment=True, download_name=f"security_report_{target}.pdf")
        elif format == 'html' and 'html' in reports:
            return send_file(reports['html'], as_attachment=True, download_name=f"security_report_{target}.html")
        elif format == 'json' and 'json' in reports:
            return send_file(reports['json'], as_attachment=True, download_name=f"security_report_{target}.json")
    
    return jsonify({'error': 'Report not found'}), 404

# Optional API endpoints (only if optional features are available)
if OPTIONAL_FEATURES:
    @app.route('/api/ai-predict', methods=['POST'])
    def ai_predict():
        try:
            data = request.json
            vulnerabilities = data.get('vulnerabilities', [])
            predictor = AIRiskPredictor()
            predictions = predictor.predict_future_risks(vulnerabilities)
            return jsonify({'success': True, 'predictions': predictions})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/compliance-check', methods=['POST'])
    def compliance_check():
        try:
            data = request.json
            vulnerabilities = data.get('vulnerabilities', [])
            target_type = data.get('target_type', 'website')
            checker = ComplianceChecker()
            results = checker.check_compliance(vulnerabilities, target_type)
            return jsonify({'success': True, 'compliance': results})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/remediation-script/<target>')
    def remediation_script(target):
        try:
            if target in scan_results:
                vulnerabilities = scan_results[target].get('vulnerabilities', [])
                remediator = AutoRemediation()
                script = remediator.generate_remediation_script(vulnerabilities)
                return Response(script, mimetype='text/plain',
                              headers={'Content-Disposition': f'attachment; filename=remediation_{target.replace(".", "_")}.sh'})
            return jsonify({'error': 'No scan results found'}), 404
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/threat-intel')
    def threat_intel():
        try:
            intel = ThreatIntelligence()
            threats = intel.get_latest_threats()
            return jsonify({'success': True, 'threats': threats})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/correlate-threats/<target>')
    def correlate_threats(target):
        try:
            if target in scan_results:
                vulnerabilities = scan_results[target].get('vulnerabilities', [])
                intel = ThreatIntelligence()
                correlations = intel.correlate_with_scan(vulnerabilities)
                return jsonify({'success': True, 'correlations': correlations})
            return jsonify({'error': 'No scan results found'}), 404
        except Exception as e:
            return jsonify({'error': str(e)}), 500
else:
    # Dummy endpoints when optional features not available
    @app.route('/api/ai-predict', methods=['POST'])
    def ai_predict_dummy():
        return jsonify({'success': True, 'predictions': []})

    @app.route('/api/compliance-check', methods=['POST'])
    def compliance_check_dummy():
        return jsonify({'success': True, 'compliance': {}})

    @app.route('/api/remediation-script/<target>')
    def remediation_script_dummy(target):
        return jsonify({'error': 'Optional features not installed'}), 501

    @app.route('/api/threat-intel')
    def threat_intel_dummy():
        return jsonify({'success': True, 'threats': {'critical_cves': [], 'exploited_vulnerabilities': [], 'ransomware_activity': {}}})

if __name__ == '__main__':
    print("""
    ============================================================
    
         PreSecureScan A - Enterprise VAPT v3.0
         AI-Powered Vulnerability Assessment Platform
    
    ============================================================
    
    [*] Server: http://localhost:5000
    [*] Press CTRL+C to stop
    [*] Features: Website | IP | Mobile | PDF Reports
    
    ============================================================
    """)
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)