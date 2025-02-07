from flask import Flask, request, jsonify
import sqlite3
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Allows frontend requests

# Connect to SQLite database
def get_db_connection():
    conn = sqlite3.connect('scans.db')
    conn.row_factory = sqlite3.Row
    return conn

# Create table if not exists
def create_table():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    result TEXT)''')
    conn.commit()
    conn.close()

create_table()

# API to run a vulnerability scan (Mock)
@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    target = data.get('target', '')

    # Mock scan logic (replace with real pentesting logic)
    scan_result = f"Scan completed for {target}, no vulnerabilities found."

    # Store result in SQLite
    conn = get_db_connection()
    conn.execute("INSERT INTO scans (target, result) VALUES (?, ?)", (target, scan_result))
    conn.commit()
    conn.close()

    return jsonify({"message": "Scan completed", "result": scan_result})

# API to get scan results
@app.route('/results', methods=['GET'])
def get_results():
    conn = get_db_connection()
    scans = conn.execute("SELECT * FROM scans").fetchall()
    conn.close()

    return jsonify([dict(row) for row in scans])

if __name__ == '__main__':
    app.run(debug=True)
