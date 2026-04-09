# 🛡️ Phishing Detector

A real-world, production-grade phishing URL detection system built with Python & Flask. Analyzes any URL using multiple detection layers and gives an instant risk score.

## What the project does

Phishing Detector analyzes URLs in real-time using 6 detection layers to determine if a URL is safe, suspicious, or a phishing/malicious site. It provides a risk score from 0–100 with detailed reasoning for every flag raised.

## Why the project is useful

Most phishing detectors are black boxes. This tool shows you **exactly why** a URL is flagged — SSL issues, domain age, suspicious keywords, DNS failures, and real-time threat intelligence from Google and VirusTotal.

### Key Features:
- 🔍 **Single URL Scanner** — Instant analysis with risk score & detailed breakdown
- 📁 **Bulk Scanner** — Scan up to 10 URLs at once with a summary dashboard
- 📋 **Scan History** — Every scan saved to a local SQLite database
- 📊 **Detailed Report Page** — Full SSL, WHOIS, DNS, VirusTotal & Google Safe Browsing breakdown per URL
- 🌐 **6 Detection Layers:**
  - URL pattern & structure analysis
  - SSL certificate validation
  - Domain age via WHOIS
  - DNS resolution check
  - Google Safe Browsing API (real-time)
  - VirusTotal multi-engine scan (real-time)

## How users can get started

### Prerequisites
- Python 3.10 or higher
- Google Safe Browsing API key (free) → [Get it here](https://console.cloud.google.com/)
- VirusTotal API key (free) → [Get it here](https://www.virustotal.com)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/phishing-detector.git
cd phishing-detector
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Add your API keys in `config.py`:
```python
GOOGLE_SAFE_BROWSING_API_KEY = "your_key_here"
VIRUSTOTAL_API_KEY = "your_key_here"
```

4. Run the app:
```bash
python app.py
```

5. Open your browser at → http://127.0.0.1:5000

---

## Usage Example

### Single URL scan result: