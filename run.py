#!/usr/bin/env python3
"""
PreSecureScan A - Enterprise VAPT Engine
Multi-Target Security Assessment Platform
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from backend.app import app

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║     ██▓███   ██▀███   ███████ ███████ ███████  ██████  ██████    ║
    ║    ▓██░  ██▒▓██ ▒ ██▒▓██   ▒▒███    ██      ▒██    ▒▒██    ▒     ║
    ║    ▓██░ ██▒▒▓██ ░▄█ ▒▒████ ░▒███   ██      ░ ▓██▄  ░ ▓██▄        ║
    ║    ▒██▄█▓▒ ▒▒██▀▀█▄ ░▓█▒  ░▒▓█▀  ░▓█▄      ▒   ██▒  ▒   ██▒      ║
    ║    ▒██▒ ░  ░░██▓ ▒██▒░▒█░   ░▒████▒░▒████▒▒██████▒▒▒██████▒▒     ║
    ║    ▒▓▒░ ░  ░░ ▒▓ ░▒▓░ ▒ ░   ░░ ▒░ ░░░ ▒░ ░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░     ║
    ║    ░▒ ░       ░▒ ░ ▒░ ░      ░ ░  ░ ░ ░  ░░ ░▒  ░ ░░ ░▒  ░ ░     ║
    ║    ░░         ░░   ░  ░ ░      ░      ░   ░  ░  ░  ░  ░  ░       ║
    ║                ░            ░      ░  ░      ░        ░          ║
    ║                                                                  ║
    ║         PreSecureScan A - Enterprise VAPT v3.0                  ║
    ║         AI-Powered Vulnerability Assessment Platform             ║
    ║                                                                  ║
    ║         Multi-Target: Website | IP Address | Mobile App         ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
    
    [*] Server: http://localhost:5000
    [*] Press CTRL+C to stop
    [*] Ready for enterprise security assessment!
    """)
    
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)