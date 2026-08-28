#!/usr/bin/env python3
"""
OsintPro - Web Server Runner
=============================
Start the web interface server.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from web.app import app

if __name__ == '__main__':
    print("=" * 60)
    print("OsintPro - Web Interface")
    print("=" * 60)
    print("Server starting...")
    print("Access: http://localhost:5000")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    
    app.run(debug=True, host='0.0.0.0', port=5000)