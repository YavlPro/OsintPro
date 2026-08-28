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

from dotenv import load_dotenv
load_dotenv()

from web.app import app

if __name__ == '__main__':
    import os
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    port = int(os.environ.get('PORT', 5000))
    
    print("=" * 60)
    print("OsintPro - Web Interface")
    print("=" * 60)
    print(f"Server starting on port {port}...")
    print(f"Debug mode: {debug}")
    print("=" * 60)
    
    app.run(debug=debug, host='0.0.0.0', port=port)