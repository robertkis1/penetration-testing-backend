from flask import Flask, request, jsonify
import sqlite3
import bcrypt
import os
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from functools import wraps

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Change this to a secure key
jwt = JWTManager(app)
CORS(app)

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

# Check if table exists before altering it
def update_database_schema():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if users table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
    table_exists = cursor.fetchone()

    if table_exists:
        cursor.execute("PRAGMA table_info(users)")
        existing_columns = [col[1] for col in cursor.fetchall()]

        if "name" not in existing_columns:
            cursor.execute("ALTER TABLE users ADD COLUMN name TEXT;")
        
        if "email" not in existing_columns:
            cursor.execute("ALTER TABLE users ADD COLUMN email TEXT UNIQUE;")
        
        if "role" not in existing_columns:
            cursor.execute("ALTER TABLE users ADD COLUMN role TEXT CHECK(role IN ('user', 'admin')) DEFAULT 'user';")
        
        conn.commit()
    
    conn.close()

# Ensure the database and tables are set up correctly
create_user_table()
update_database_schema()

# Middleware to check if user is admin
def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        current_user = get_jwt_identity()
        if current_user["role"] != "admin":
            return jsonify({"error": "Access denied. Admins only."}), 403
        return fn(*args, **kwargs)
    return wrapper

# API for user signup
@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.json
        username = data.get('username', '')
        password = data.get('password', '')
        name = data.get('name', '')
        email = data.get('email', '')
        role = data.get('role', 'user')  # Default role is 'user'

        if not username or not password or not name or not email:
            return jsonify({"error": "All fields are required"}), 400

        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = get_db_connection()
        cursor = conn.cursor()

        # Insert user safely
        cursor.execute("INSERT INTO users (username, password, name, email, role) VALUES (?, ?, ?, ?, ?)",
                     (username, hashed_password, name, email, role))
        conn.commit()

        # Close connection properly
        cursor.close()
        conn.close()

        # Generate JWT Token
        access_token = create_access_token(identity={"username": username, "role": role})
        return jsonify({"message": "User registered successfully", "token": access_token}), 201

    except sqlite3.OperationalError as e:
        return jsonify({"error": "Database is locked, please try again later."}), 500

    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or Email already exists"}), 409

# API for user login
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username', '')
        password = data.get('password', '')

        conn = get_db_connection()
        cursor = conn.cursor()
        user = cursor.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            # Generate JWT token with role information
            access_token = create_access_token(identity={"username": username, "role": user["role"]})
            return jsonify({"message": "Login successful", "token": access_token}), 200
        else:
            return jsonify({"error": "Invalid username or password"}), 401
    finally:
        cursor.close()
        conn.close()

# Protected route (Only logged-in users can access this)
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Hello {current_user['username']}, this is a protected route!"})

# Admin-only API to show registered users
@app.route('/show-users', methods=['GET'])
@admin_required
def show_users():
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
    reports = cursor.execute("SELECT * FROM scan_reports").fetchall()  # Assuming scan_reports table exists
    conn.close()
    return jsonify([dict(row) for row in reports])

if __name__ == '__main__':
    app.run(debug=True)
