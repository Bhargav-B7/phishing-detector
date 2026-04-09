# import sqlite3
# from flask import Flask, request, jsonify, render_template
# from detector import analyze_url
# from datetime import datetime

# app = Flask(__name__)
# DB = 'history.db'

# # ── Create DB table on startup ──────────────────────────────────
# def init_db():
#     with sqlite3.connect(DB) as conn:
#         conn.execute('''
#             CREATE TABLE IF NOT EXISTS scans (
#                 id        INTEGER PRIMARY KEY AUTOINCREMENT,
#                 url       TEXT NOT NULL,
#                 verdict   TEXT NOT NULL,
#                 score     INTEGER NOT NULL,
#                 color     TEXT NOT NULL,
#                 scanned_at TEXT NOT NULL
#             )
#         ''')
# init_db()

# # ── Save a scan result ──────────────────────────────────────────
# def save_scan(url, verdict, score, color):
#     with sqlite3.connect(DB) as conn:
#         conn.execute(
#             'INSERT INTO scans (url, verdict, score, color, scanned_at) VALUES (?,?,?,?,?)',
#             (url, verdict, score, color, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
#         )

# # ── Get last 20 scans ───────────────────────────────────────────
# def get_history():
#     with sqlite3.connect(DB) as conn:
#         conn.row_factory = sqlite3.Row
#         rows = conn.execute(
#             'SELECT * FROM scans ORDER BY id DESC LIMIT 20'
#         ).fetchall()
#         return [dict(r) for r in rows]


# @app.route('/')
# def index():
#     return render_template('index.html')

# @app.route('/analyze', methods=['POST'])
# def analyze():
#     data = request.get_json()
#     url = data.get('url', '').strip()
#     if not url:
#         return jsonify({'error': 'No URL provided'}), 400

#     result = analyze_url(url)

#     # Save to history only if it's a real URL
#     if result['verdict'] != 'NOT A URL':
#         save_scan(url, result['verdict'], result['score'], result['color'])

#     return jsonify(result)

# @app.route('/history', methods=['GET'])
# def history():
#     return jsonify(get_history())

# @app.route('/clear-history', methods=['POST'])
# def clear_history():
#     with sqlite3.connect(DB) as conn:
#         conn.execute('DELETE FROM scans')
#     return jsonify({'status': 'cleared'})

# if __name__ == '__main__':
#     app.run(debug=True)
# app.py
import sqlite3
import json
from flask import Flask, request, jsonify, render_template
from detector import analyze_url
from datetime import datetime

app = Flask(__name__)
# DB = 'history.db'
import os
DB = os.environ.get('DB_PATH', 'history.db')

def init_db():
    with sqlite3.connect(DB) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                url        TEXT NOT NULL,
                verdict    TEXT NOT NULL,
                score      INTEGER NOT NULL,
                color      TEXT NOT NULL,
                reasons    TEXT,
                details    TEXT,
                scanned_at TEXT NOT NULL
            )
        ''')
init_db()

def save_scan(url, verdict, score, color, reasons, details):
    with sqlite3.connect(DB) as conn:
        conn.execute(
            'INSERT INTO scans (url, verdict, score, color, reasons, details, scanned_at) VALUES (?,?,?,?,?,?,?)',
            (url, verdict, score, color,
             json.dumps(reasons),
             json.dumps(details),
             datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        )

def get_history():
    with sqlite3.connect(DB) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 20').fetchall()
        return [dict(r) for r in rows]

def get_scan(scan_id):
    with sqlite3.connect(DB) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone()
        if row:
            r = dict(row)
            r['reasons'] = json.loads(r['reasons'] or '[]')
            r['details'] = json.loads(r['details'] or '{}')
            return r
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/report/<int:scan_id>')
def report(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return "Report not found", 404
    return render_template('report.html', scan=scan)

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    result = analyze_url(url)
    if result['verdict'] != 'NOT A URL':
        save_scan(url, result['verdict'], result['score'],
                  result['color'], result.get('reasons', []), result.get('details', {}))
    return jsonify(result)

@app.route('/history')
def history():
    return jsonify(get_history())

@app.route('/clear-history', methods=['POST'])
def clear_history():
    with sqlite3.connect(DB) as conn:
        conn.execute('DELETE FROM scans')
    return jsonify({'status': 'cleared'})

@app.route('/bulk-analyze', methods=['POST'])
def bulk_analyze():
    data = request.get_json()
    urls = data.get('urls', [])
    if not urls:
        return jsonify({'error': 'No URLs provided'}), 400

    results = []
    for url in urls[:10]:  # max 10 at a time
        url = url.strip()
        if not url:
            continue
        result = analyze_url(url)
        if result['verdict'] != 'NOT A URL':
            save_scan(url, result['verdict'], result['score'],
                      result['color'], result.get('reasons', []), result.get('details', {}))
        results.append(result)

    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)