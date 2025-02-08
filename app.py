from flask import Flask, request, jsonify
import sqlite3
import bcrypt
import os
import logging
import traceback
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from functools import wraps

# Initialize Flask App
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Change this to a secure key
jwt = JWTManager(app)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)  # Updated CORS config

# Enable Logging for Debugging
logging.basicConfig(level=logging.DEBUG)

# Connect to SQLite database with better locking prevention
def get_db_connection():
    conn = sqlite3.connect('scans.db', check_same_thread=False, timeout=10)  # Prevents database locking
    conn.row_factory = sqlite3.Row
    return conn

# Create users table if it doesn't exist
def create_user_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT,
                    name TEXT,
                    email TEXT UNIQUE,
                    role TEXT CHECK(role IN ('user', 'admin')) DEFAULT 'user'
                    )''')
    conn.commit()
    conn.close()

# Create scan_reports table if it doesn't exist
def create_reports_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS scan_reports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT,
                        description TEXT,
                        status TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                      )''')
    conn.commit()
    conn.close()

# Ensure the database and tables are set up correctly
create_user_table()
create_reports_table()

# Middleware to check if user is admin
def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        current_user = get_jwt_identity()
        logging.info(f"Checking admin access for user: {current_user}")  # Log user role

        if isinstance(current_user, dict) and current_user.get("role") != "admin":
            logging.warning(f"Access denied for non-admin user: {current_user}")
            return jsonify({"error": "Access denied. Admins only."}), 403

        return fn(*args, **kwargs)
    return wrapper

# API for user signup
@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.json
        logging.info(f"Received signup request: {data}")  # Debugging log

        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        name = data.get('name', '').strip()
        email = data.get('email', '').strip()
        role = data.get('role', 'user').strip()  # Default role is 'user'

        if not username or not password or not name or not email:
            logging.warning("Signup failed: Missing fields")
            return jsonify({"error": "All fields are required"}), 400

        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = get_db_connection()
        cursor = conn.cursor()

        # Insert user safely
        cursor.execute("INSERT INTO users (username, password, name, email, role) VALUES (?, ?, ?, ?, ?)",
                     (username, hashed_password, name, email, role))
        conn.commit()

        cursor.close()
        conn.close()

        # Generate JWT Token
        access_token = create_access_token(identity={"username": username, "role": role})
        logging.info(f"User {username} registered successfully with role {role}")
        return jsonify({"message": "User registered successfully", "token": access_token}), 201

    except sqlite3.IntegrityError:
        logging.error("Signup failed: Username or email already exists")
        return jsonify({"error": "Username or Email already exists"}), 409

    except Exception as e:
        logging.error(f"Signup failed: {e}\n{traceback.format_exc()}")
        return jsonify({"error": "Internal Server Error. Check logs for details."}), 500

# API for user login
@app.route('/login', methods=['POST'])
def login():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        data = request.json
        logging.info(f"Received login request: {data}")

        username = data.get('username', '').strip()
        password = data.get('password', '').strip()

        user = cursor.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            access_token = create_access_token(identity={"username": username, "role": user["role"]})
            logging.info(f"User {username} logged in successfully")
            return jsonify({"message": "Login successful", "token": access_token}), 200
        else:
            logging.warning("Login failed: Invalid credentials")
            return jsonify({"error": "Invalid username or password"}), 401
    except Exception as e:
        logging.error(f"Login failed: {e}\n{traceback.format_exc()}")
        return jsonify({"error": "Internal Server Error. Check logs for details."}), 500
    finally:
        cursor.close()
        conn.close()

# Protected route (Only logged-in users can access this)
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    logging.info(f"Protected route accessed by {current_user['username']}")
    return jsonify({"message": f"Hello {current_user['username']}, this is a protected route!"})

# Admin-only API to show registered users
SECRET_ADMIN_KEY = "a1f47c8de93d61eb6c1d93cf7e5b0f34f9d85e8d5a3a1b88e623a7c1c4b5e7e9"

@app.route('/show-users', methods=['GET'])
def show_users():
    # Read the Admin Key from request headers
    admin_key = request.headers.get("X-Admin-Key")

    # Check if the provided key is correct
    if admin_key != SECRET_ADMIN_KEY:
        return jsonify({"error": "Unauthorized - Invalid Admin Key"}), 403

    # Fetch users from the database
    conn = get_db_connection()
    cursor = conn.cursor()
    users = cursor.execute("SELECT id, username, name, email, role FROM users").fetchall()
    conn.close()

    return jsonify([dict(row) for row in users])

# Admin-only API to show all penetration testing reports
@app.route('/all-reports', methods=['GET'])
@admin_required
def all_reports():
    conn = get_db_connection()
    cursor = conn.cursor()
    reports = cursor.execute("SELECT * FROM scan_reports").fetchall()
    conn.close()
    return jsonify([dict(row) for row in reports])

if __name__ == '__main__':
    app.run(debug=True)
