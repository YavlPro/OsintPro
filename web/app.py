"""
OsintPro Web Interface
======================
Flask web application for OSINT analysis with light/dark mode.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, jsonify
from src.crypto import WalletChecker
from src.phishing import URLChecker, EmailAnalyzer, DomainChecker
from src.domain_analysis import WHOISLookup, ProjectAnalyzer
from src.breach_monitor import BreachChecker

app = Flask(__name__)
app.secret_key = 'osintpro-secret-key-2024'

# Initialize analyzers
wallet_checker = WalletChecker()
url_checker = URLChecker()
email_analyzer = EmailAnalyzer()
domain_checker = DomainChecker()
whois_lookup = WHOISLookup()
project_analyzer = ProjectAnalyzer()
breach_checker = BreachChecker()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/crypto/check', methods=['POST'])
def crypto_check():
    data = request.get_json()
    address = data.get('address', '')
    if not address:
        return jsonify({'error': 'Address is required'}), 400
    
    result = wallet_checker.check_wallet(address)
    return jsonify(result)


@app.route('/api/phishing/url', methods=['POST'])
def phishing_url():
    data = request.get_json()
    url = data.get('url', '')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    result = url_checker.comprehensive_check(url)
    return jsonify(result)


@app.route('/api/phishing/email', methods=['POST'])
def phishing_email():
    data = request.get_json()
    email = data.get('email', '')
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    result = email_analyzer.comprehensive_analysis(email)
    return jsonify(result)


@app.route('/api/phishing/domain', methods=['POST'])
def phishing_domain():
    data = request.get_json()
    domain = data.get('domain', '')
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    result = domain_checker.comprehensive_check(domain)
    return jsonify(result)


@app.route('/api/domain/whois', methods=['POST'])
def domain_whois():
    data = request.get_json()
    domain = data.get('domain', '')
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    result = whois_lookup.lookup(domain)
    return jsonify(result)


@app.route('/api/domain/project', methods=['POST'])
def domain_project():
    data = request.get_json()
    name = data.get('name', '')
    website = data.get('website', '')
    github = data.get('github', '')
    
    if not name or not website:
        return jsonify({'error': 'Name and website are required'}), 400
    
    project_info = {'name': name, 'website': website, 'github': github}
    result = project_analyzer.analyze_crypto_project(project_info)
    return jsonify(result)


@app.route('/api/breach/check', methods=['POST'])
def breach_check():
    data = request.get_json()
    email = data.get('email', '')
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    result = breach_checker.comprehensive_check(email)
    return jsonify(result)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)