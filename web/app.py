"""
OsintPro Web Interface
======================
Flask web application for OSINT analysis with light/dark mode.
"""

import sys
import os
import time
from collections import defaultdict

from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load local .env file (no-op on Railway/Render where env vars are native)
load_dotenv()

from flask import Flask, render_template, request, jsonify
from src.crypto import WalletChecker
from src.phishing import URLChecker, EmailAnalyzer, DomainChecker
from src.domain_analysis import WHOISLookup, ProjectAnalyzer
from src.breach_monitor import BreachChecker

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

# API keys from environment (optional; features degrade gracefully without them)
ETHERSCAN_API_KEY = os.environ.get("ETHERSCAN_API_KEY", "").strip() or None
HIBP_API_KEY = os.environ.get("HIBP_API_KEY", "").strip() or None

# Initialize analyzers
wallet_checker = WalletChecker(etherscan_api_key=ETHERSCAN_API_KEY)
url_checker = URLChecker()
email_analyzer = EmailAnalyzer(hibp_api_key=HIBP_API_KEY)
domain_checker = DomainChecker()
whois_lookup = WHOISLookup()
project_analyzer = ProjectAnalyzer()
breach_checker = BreachChecker(hibp_api_key=HIBP_API_KEY)


# ---------------------------------------------------------------------------
# Simple in-memory rate limiting (per IP, sliding window per minute)
# ---------------------------------------------------------------------------
class RateLimiter:
    """Fixed-window rate limiter keyed by IP. Limits are read from env vars
    so they can be tuned per environment without code changes."""

    def __init__(self, window_seconds: int = 60, max_keys: int = 10_000):
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._hits = defaultdict(list)

    def allow(self, key: str, limit: int) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds

        # Opportunistic cleanup to keep memory bounded
        if len(self._hits) > self.max_keys:
            for k in list(self._hits):
                if not self._hits[k] or self._hits[k][-1] < cutoff:
                    del self._hits[k]

        bucket = [t for t in self._hits[key] if t > cutoff]
        if len(bucket) >= limit:
            self._hits[key] = bucket
            return False
        bucket.append(now)
        self._hits[key] = bucket
        return True


rate_limiter = RateLimiter()


def _client_ip() -> str:
    """Best-effort client IP, honoring proxy headers from Railway/Render."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip() or request.remote_addr or "unknown"
    return request.remote_addr or "unknown"


@app.before_request
def apply_rate_limit():
    is_api = request.path.startswith("/api/")
    if is_api:
        limit = int(os.environ.get("RATE_LIMIT_API", "30"))
    else:
        limit = int(os.environ.get("RATE_LIMIT_WEB", "10"))
    if not rate_limiter.allow(_client_ip(), limit):
        if is_api:
            return jsonify({"error": "Rate limit exceeded. Please try again later.", "status": 429}), 429
        return "Rate limit exceeded. Please try again later.", 429


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
    import os
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=debug, host='0.0.0.0', port=port)