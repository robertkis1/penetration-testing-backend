from flask import Flask, request, jsonify
import sqlite3
import bcrypt  # Library for hashing passwords
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Allow frontend requests

# Connect to SQLite database
def get_db_connection():
    conn = sqlite3.connect('scans.db')
    conn.row_factory = sqlite3.Row
    return conn

# Create users table
def create_user_table():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT)''')
    conn.commit()
    conn.close()

create_user_table()

# API for user signup
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username', '')
    password = data.get('password', '')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        conn = get_db_connection()
        conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        conn.close()
        return jsonify({"message": "User registered successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409

# API for user login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '')
    password = data.get('password', '')

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({"message": "Login successful"}), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 401

if __name__ == '__main__':
    app.run(debug=True)
