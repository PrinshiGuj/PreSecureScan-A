"""
Compliance Checker Module
Checks against GDPR, PCI-DSS, HIPAA standards
"""

class ComplianceChecker:
    """Check compliance with security standards"""
    
    def __init__(self):
        self.standards = {
            'GDPR': {
                'name': 'General Data Protection Regulation',
                'requirements': [
                    {'id': 'GDPR-1', 'name': 'Data Protection by Design', 'weight': 15},
                    {'id': 'GDPR-2', 'name': 'Data Breach Notification', 'weight': 20},
                    {'id': 'GDPR-3', 'name': 'User Consent Management', 'weight': 15},
                    {'id': 'GDPR-4', 'name': 'Data Subject Rights', 'weight': 20},
                    {'id': 'GDPR-5', 'name': 'Data Processing Records', 'weight': 15},
                    {'id': 'GDPR-6', 'name': 'Data Protection Impact Assessment', 'weight': 15}
                ]
            },
            'PCI-DSS': {
                'name': 'Payment Card Industry Data Security Standard',
                'requirements': [
                    {'id': 'PCI-1', 'name': 'Secure Network Configuration', 'weight': 20},
                    {'id': 'PCI-2', 'name': 'Cardholder Data Protection', 'weight': 25},
                    {'id': 'PCI-3', 'name': 'Vulnerability Management', 'weight': 20},
                    {'id': 'PCI-4', 'name': 'Access Control Measures', 'weight': 20},
                    {'id': 'PCI-5', 'name': 'Regular Monitoring & Testing', 'weight': 15}
                ]
            },
            'HIPAA': {
                'name': 'Health Insurance Portability and Accountability Act',
                'requirements': [
                    {'id': 'HIPAA-1', 'name': 'Privacy Rule Compliance', 'weight': 25},
                    {'id': 'HIPAA-2', 'name': 'Security Rule Compliance', 'weight': 25},
                    {'id': 'HIPAA-3', 'name': 'Breach Notification Rule', 'weight': 20},
                    {'id': 'HIPAA-4', 'name': 'Administrative Safeguards', 'weight': 15},
                    {'id': 'HIPAA-5', 'name': 'Technical Safeguards', 'weight': 15}
                ]
            }
        }
    
    def check_compliance(self, vulnerabilities, target_type='website'):
        """Check compliance status based on vulnerabilities"""
        results = {}
        
        for standard_name, standard_info in self.standards.items():
            compliance_score = 100
            failed_requirements = []
            
            for req in standard_info['requirements']:
                # Simulate compliance check based on vulnerabilities
                if self.is_requirement_failed(req, vulnerabilities):
                    compliance_score -= req['weight']
                    failed_requirements.append(req)
            
            results[standard_name] = {
                'name': standard_info['name'],
                'score': max(0, compliance_score),
                'status': 'Compliant' if compliance_score >= 80 else 'Partially Compliant' if compliance_score >= 60 else 'Non-Compliant',
                'failed_requirements': failed_requirements,
                'recommendations': self.get_compliance_recommendations(standard_name, failed_requirements)
            }
        
        return results
    
    def is_requirement_failed(self, requirement, vulnerabilities):
        """Check if a compliance requirement is failed"""
        # Simulated logic - in real implementation, map vulns to requirements
        critical_vulns = sum(1 for v in vulnerabilities if v.get('severity') == 'Critical')
        high_vulns = sum(1 for v in vulnerabilities if v.get('severity') == 'High')
        
        if requirement['id'].startswith('GDPR'):
            return critical_vulns > 0 or high_vulns > 2
        elif requirement['id'].startswith('PCI'):
            return critical_vulns > 0
        elif requirement['id'].startswith('HIPAA'):
            return critical_vulns > 0 or high_vulns > 1
        
        return False
    
    def get_compliance_recommendations(self, standard, failed_reqs):
        """Get recommendations for compliance"""
        if not failed_reqs:
            return ["Maintain current security posture", "Conduct regular audits"]
        
        recommendations = []
        for req in failed_reqs:
            recommendations.append(f"Address {req['name']} - Implement appropriate controls")
        
        return recommendations