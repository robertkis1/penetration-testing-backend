from flask import Flask, request, jsonify
import sqlite3
import bcrypt
import logging
import traceback
import os
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from functools import wraps

# Initialize Flask App
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'fallback-secret-key')
jwt = JWTManager(app)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)  # Updated CORS config

# Enable Logging for Debugging
logging.basicConfig(level=logging.DEBUG)

# Connect to SQLite database
def get_db_connection():
    db_path = os.getenv("DATABASE_URL", "/tmp/scans.db")  # Use the new path
    conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
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
                    role TEXT CHECK(role IN ('user', 'admin')) DEFAULT 'user',
                    tos_accepted BOOLEAN DEFAULT 0,
                    privacy_policy BOOLEAN DEFAULT 0,
                    gdpr BOOLEAN DEFAULT 0
                    )''')
    conn.commit()
    conn.close()

# Ensure the database table exists
create_user_table()

# Middleware to check if user is admin
def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        current_user = get_jwt_identity()
        logging.info(f"Checking admin access for user: {current_user}")

        if isinstance(current_user, dict) and current_user.get("role") != "admin":
            logging.warning(f"Access denied for non-admin user: {current_user}")
            return jsonify({"error": "Access denied. Admins only."}), 403

        return fn(*args, **kwargs)
    return wrapper

# 🟢 User Signup API (Enhanced)
@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.json
        logging.info(f"Received signup request: {data}")

        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        name = data.get('name', '').strip()
        email = data.get('email', '').strip()
        role = data.get('role', 'user').strip()
        tos_accepted = data.get('tos_accepted', False)
        privacy_policy = data.get('privacy_policy', False)
        gdpr = data.get('gdpr', False)

        if not username or not password or not name or not email:
            return jsonify({"error": "All fields are required"}), 400

        if not tos_accepted or not privacy_policy or not gdpr:
            return jsonify({"error": "You must accept the Terms of Service, Privacy Policy, and GDPR compliance"}), 400

        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("INSERT INTO users (username, password, name, email, role, tos_accepted, privacy_policy, gdpr) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                     (username, hashed_password, name, email, role, tos_accepted, privacy_policy, gdpr))
        conn.commit()
        conn.close()

        access_token = create_access_token(identity={"username": username, "role": role, "name": name})
        logging.info(f"User {username} registered successfully with role {role}")
        return jsonify({"message": "User registered successfully", "token": access_token}), 201

    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or Email already exists"}), 409

    except Exception as e:
        logging.error(f"Signup failed: {e}\n{traceback.format_exc()}")
        return jsonify({"error": "Internal Server Error"}), 500

# 🟢 User Login API (Returns Full Name)
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        user = cursor.execute("SELECT id, username, password, name, role FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        if not user:
            return jsonify({"error": "Invalid email or password"}), 401

        stored_password = user["password"]
        if isinstance(stored_password, str):
            stored_password = stored_password.encode("utf-8")

        if bcrypt.checkpw(password.encode('utf-8'), stored_password):
            access_token = create_access_token(identity={"username": user["username"], "role": user["role"], "name": user["name"]})
            return jsonify({"message": "Login successful", "token": access_token, "role": user["role"], "name": user["name"]}), 200
        else:
            return jsonify({"error": "Invalid email or password"}), 401

    except Exception as e:
        return jsonify({"error": "Internal Server Error"}), 500

# 🟢 Get All Users (Admin Only)
@app.route('/show-users', methods=['GET'])
@admin_required
def show_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    users = cursor.execute("SELECT id, username, name, email, role FROM users").fetchall()
    conn.close()
    return jsonify([dict(row) for row in users])

# 🟢 Update User Profile
@app.route('/update-user/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    try:
        data = request.json
        logging.info(f"Received update request for user ID {user_id}: {data}")

        username = data.get('username', '').strip()
        name = data.get('name', '').strip()
        email = data.get('email', '').strip()
        role = data.get('role', '').strip()

        if not username or not name or not email or not role:
            return jsonify({"error": "All fields are required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE users
            SET username = ?, name = ?, email = ?, role = ?
            WHERE id = ?
        """, (username, name, email, role, user_id))

        conn.commit()
        conn.close()
        return jsonify({"message": "User updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": "Internal Server Error"}), 500

# 🟢 Delete User (Admin Only)
@app.route('/delete-user/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "User deleted successfully"}), 200

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))  # Use Render's assigned port
    app.run(host='0.0.0.0', port=port, debug=True)
