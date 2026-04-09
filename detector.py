# detector.py
import re
import socket
import ssl
import whois
import dns.resolver
import tldextract
import requests
from datetime import datetime
from urllib.parse import urlparse

# ─── Load config ───────────────────────────────────────────────
from config import GOOGLE_SAFE_BROWSING_API_KEY, VIRUSTOTAL_API_KEY


# ─── 1. URL FEATURE EXTRACTOR ──────────────────────────────────
def extract_features(url):
    """Extract all phishing-related features from a URL."""
    features = {}
    parsed = urlparse(url)
    ext = tldextract.extract(url)

    # Basic URL properties
    features['url_length'] = len(url)
    features['domain'] = ext.registered_domain
    features['subdomain'] = ext.subdomain
    features['tld'] = ext.suffix
    features['path'] = parsed.path
    features['scheme'] = parsed.scheme

    # Suspicious character checks
    features['has_ip_address'] = bool(re.match(
        r'https?://\d{1,3}(\.\d{1,3}){3}', url))
    features['has_at_symbol'] = '@' in url
    features['has_double_slash'] = '//' in parsed.path
    features['hyphen_count'] = ext.registered_domain.count('-')
    features['dot_count'] = url.count('.')
    features['digit_count'] = sum(c.isdigit() for c in ext.registered_domain)
    features['url_length_suspicious'] = len(url) > 75

    # Suspicious keywords in URL
    # PHISHING_KEYWORDS = [
    #     'login', 'signin', 'verify', 'secure', 'account', 'update',
    #     'banking', 'confirm', 'password', 'credential', 'wallet',
    #     'paypal', 'amazon', 'apple', 'microsoft', 'google', 'netflix',
    #     'support', 'alert', 'suspend', 'urgent', 'free', 'winner'
    # ]
    PHISHING_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update',
    'banking', 'confirm', 'password', 'credential', 'wallet',
    'support', 'alert', 'suspend', 'urgent', 'free', 'winner',
    'webscr', 'cmd=', 'ebayisapi', 'onlinebanking'
]

# Brand names only flagged when used in a DIFFERENT domain
    BRAND_KEYWORDS = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'netflix', 'instagram', 'facebook']
        # url_lower = url.lower()
        # features['suspicious_keywords'] = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
        # features['keyword_count'] = len(features['suspicious_keywords'])
    url_lower = url.lower()
    domain_lower = ext.registered_domain.lower()

    # General keywords
    general_hits = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]

    # Brand keywords — only flag if brand name appears but domain isn't that brand
    brand_hits = [
        brand for brand in BRAND_KEYWORDS
        if brand in url_lower and brand not in domain_lower
    ]

    features['suspicious_keywords'] = general_hits + brand_hits
    features['keyword_count'] = len(features['suspicious_keywords'])

    # Subdomain depth (e.g. login.secure.bank.com = suspicious)
    features['subdomain_depth'] = len(ext.subdomain.split('.')) if ext.subdomain else 0

    return features


# ─── 2. SSL CERTIFICATE CHECK ──────────────────────────────────
def check_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            expire_date = datetime.strptime(
                cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
            days_left = (expire_date - datetime.utcnow()).days
            return {'valid': True, 'days_left': days_left, 'error': None}
    except Exception as e:
        return {'valid': False, 'days_left': None, 'error': str(e)}


# ─── 3. WHOIS DOMAIN AGE CHECK ─────────────────────────────────
# def check_domain_age(domain):
#     try:
#         w = whois.whois(domain)
#         creation = w.creation_date
#         if isinstance(creation, list):
#             creation = creation[0]
#         if creation:
#             age_days = (datetime.utcnow() - creation).days
#             return {'age_days': age_days, 'error': None}
#         return {'age_days': None, 'error': 'No creation date'}
#     except Exception as e:
#         return {'age_days': None, 'error': str(e)}
def check_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            # Strip timezone info to avoid offset-naive vs offset-aware error
            if hasattr(creation, 'tzinfo') and creation.tzinfo is not None:
                creation = creation.replace(tzinfo=None)
            age_days = (datetime.utcnow() - creation).days
            return {'age_days': age_days, 'error': None}
        return {'age_days': None, 'error': 'No creation date'}
    except Exception as e:
        return {'age_days': None, 'error': str(e)}


# ─── 4. DNS CHECK ──────────────────────────────────────────────
def check_dns(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ips = [r.address for r in answers]
        return {'resolves': True, 'ips': ips}
    except Exception:
        return {'resolves': False, 'ips': []}


# ─── 5. GOOGLE SAFE BROWSING ───────────────────────────────────
def check_google_safe_browsing(url):
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return {'safe': None, 'error': 'No API key'}
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        payload = {
            "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        r = requests.post(endpoint, json=payload, timeout=5)
        data = r.json()
        is_threat = bool(data.get('matches'))
        return {'safe': not is_threat, 'matches': data.get('matches', []), 'error': None}
    except Exception as e:
        return {'safe': None, 'error': str(e)}


# ─── 6. VIRUSTOTAL CHECK ───────────────────────────────────────
def check_virustotal(url):
    if not VIRUSTOTAL_API_KEY:
        return {'malicious': None, 'error': 'No API key'}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=5)
        if r.status_code == 200:
            stats = r.json()['data']['attributes']['last_analysis_stats']
            return {'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'error': None}
        return {'malicious': None, 'error': f'Status {r.status_code}'}
    except Exception as e:
        return {'malicious': None, 'error': str(e)}


# ─── 7. MAIN SCORING ENGINE ────────────────────────────────────
def analyze_url(url):
    """Run all checks and return a final risk score + verdict."""

    # Validate it's a URL first
    if not url.startswith(('http://', 'https://')):
        return {
            'verdict': 'NOT A URL',
            'score': 0,
            'color': 'gray',
            'message': f'"{url}" is not a valid URL. Please enter a URL starting with http:// or https://',
            'details': {}
        }

    features = extract_features(url)
    domain = features['domain']

    # Run all checks
    ssl_result    = check_ssl(domain)
    whois_result  = check_domain_age(domain)
    dns_result    = check_dns(domain)
    gsb_result    = check_google_safe_browsing(url)
    vt_result     = check_virustotal(url)

    # ── Scoring (higher = more suspicious) ──
    score = 0
    reasons = []

    if features['has_ip_address']:
        score += 30
        reasons.append('⚠️ URL uses raw IP address instead of domain name')

    if features['has_at_symbol']:
        score += 20
        reasons.append('⚠️ URL contains @ symbol (classic phishing trick)')

    if features['url_length_suspicious']:
        score += 10
        reasons.append(f'⚠️ Very long URL ({features["url_length"]} chars)')

    if features['hyphen_count'] >= 3:
        score += 15
        reasons.append(f'⚠️ Too many hyphens in domain ({features["hyphen_count"]})')

    if features['subdomain_depth'] >= 3:
        score += 15
        reasons.append(f'⚠️ Deep subdomain structure (depth {features["subdomain_depth"]})')

    if features['keyword_count'] > 0:
        score += min(features['keyword_count'] * 8, 24)
        reasons.append(f'⚠️ Suspicious keywords found: {", ".join(features["suspicious_keywords"])}')

    if not ssl_result['valid']:
        score += 20
        reasons.append('⚠️ No valid SSL certificate')
    elif ssl_result['days_left'] and ssl_result['days_left'] < 30:
        score += 10
        reasons.append(f'⚠️ SSL expires in {ssl_result["days_left"]} days')

    if whois_result['age_days'] is not None:
        if whois_result['age_days'] < 30:
            score += 25
            reasons.append(f'⚠️ Domain is very new ({whois_result["age_days"]} days old)')
        elif whois_result['age_days'] < 180:
            score += 10
            reasons.append(f'⚠️ Domain is relatively new ({whois_result["age_days"]} days old)')

    if not dns_result['resolves']:
        score += 20
        reasons.append('⚠️ Domain does not resolve (DNS failure)')

    if gsb_result['safe'] is False:
        score += 50
        reasons.append('🚨 FLAGGED by Google Safe Browsing!')

    if vt_result.get('malicious') and vt_result['malicious'] > 0:
        score += 40
        reasons.append(f'🚨 VirusTotal: {vt_result["malicious"]} engines flagged this URL')

    # ── Verdict ──
    score = min(score, 100)

    if score >= 70:
        verdict, color = 'PHISHING / DANGEROUS', 'red'
        message = '🚨 This URL is very likely a phishing or malicious site. Do NOT visit it.'
    elif score >= 40:
        verdict, color = 'SUSPICIOUS', 'orange'
        message = '⚠️ This URL has multiple suspicious signals. Proceed with extreme caution.'
    elif score >= 15:
        verdict, color = 'POTENTIALLY UNSAFE', 'yellow'
        message = '🔍 Some minor risk signals detected. Verify before trusting.'
    else:
        verdict, color = 'LIKELY SAFE', 'green'
        message = '✅ No major threats detected. This URL appears to be safe.'

    return {
        'url': url,
        'verdict': verdict,
        'score': score,
        'color': color,
        'message': message,
        'reasons': reasons,
        'details': {
            'features': features,
            'ssl': ssl_result,
            'whois': whois_result,
            'dns': dns_result,
            'google_safe_browsing': gsb_result,
            'virustotal': vt_result
        }
    }