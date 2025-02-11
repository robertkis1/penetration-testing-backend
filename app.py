import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import bcrypt
import jwt  # PyJWT library
from jwt import encode, decode  # Ensure correct functions are used
import datetime
from flask import request
from functools import wraps

# ✅ Define Flask App FIRST
app = Flask(__name__)
CORS(app)

# ✅ Load Environment Variables
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')
app.config['JWT_EXPIRATION_TIME'] = int(os.getenv('JWT_EXPIRATION_TIME', 3600))
BCRYPT_LOG_ROUNDS = int(os.getenv('BCRYPT_LOG_ROUNDS', 12))

# ✅ Initialize Database
db = SQLAlchemy(app)

# ✅ Define User Model BEFORE creating tables
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'admin' or 'user'
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# ✅ Ensure Tables Are Created AFTER Defining Models
with app.app_context():
    db.create_all()

# ✅ Default Home Route
@app.route('/')
def home():
    return jsonify({"message": "Penetration Testing Backend API is running!"}), 200

# ✅ User Registration Route
@app.route('/register', methods=['POST'])
def register():
    data = request.json

    if not data.get('full_name') or not data.get('email') or not data.get('username') or not data.get('password') or not data.get('role'):
        return jsonify({"message": "All fields are required"}), 400

    hashed_pw = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt(BCRYPT_LOG_ROUNDS))

    new_user = User(
        full_name=data['full_name'],
        email=data['email'],
        username=data['username'],
        password=hashed_pw.decode('utf-8'),
        role=data['role']
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

# ✅ User Login Route
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    
    if user and bcrypt.checkpw(data['password'].encode('utf-8'), user.password.encode('utf-8')):
        token = encode(
            {
                "user_id": user.id,
                "role": user.role,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=app.config['JWT_EXPIRATION_TIME'])
            },
            app.config['SECRET_KEY'],
            algorithm="HS256"
        )
        return jsonify({"token": token, "role": user.role, "full_name": user.full_name}), 200

    return jsonify({"message": "Invalid credentials"}), 401

# ✅ Get Users (Admin Only)
@app.route('/admin/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([{"id": u.id, "full_name": u.full_name, "email": u.email, "username": u.username, "role": u.role} for u in users])

# ✅ Delete User (Admin)
@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"}), 200
    return jsonify({"message": "User not found"}), 404

# ✅ Update User Profile (User)
@app.route('/update-profile', methods=['PUT'])
def update_profile():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()

    if user:
        user.full_name = data.get('full_name', user.full_name)
        user.username = data.get('username', user.username)
        if 'password' in data:
            user.password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt(BCRYPT_LOG_ROUNDS)).decode('utf-8')

        db.session.commit()
        return jsonify({"message": "Profile updated successfully"}), 200
    
    return jsonify({"message": "User not found"}), 404

from flask import request
from functools import wraps

# ✅ Function to Verify Admin Token
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get("Authorization")

        if not token:
            return jsonify({"message": "Missing token"}), 403

        try:
            token = token.split("Bearer ")[1]  # Extract actual token
            decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])

            if decoded_token.get("role") != "admin":
                return jsonify({"message": "Unauthorized"}), 403

        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 401

        return f(*args, **kwargs)

    return decorated_function


# ✅ Route for Admin to Create Users
@app.route('/admin/add-user', methods=['POST'])
@admin_required
def add_user():
    try:
        data = request.json

        if not all(k in data for k in ['full_name', 'email', 'username', 'password', 'role']):
            return jsonify({"message": "All fields are required"}), 400

        # ✅ Ensure Email is Unique
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user:
            return jsonify({"message": "User already exists"}), 400

        hashed_pw = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt(BCRYPT_LOG_ROUNDS))

        new_user = User(
            full_name=data['full_name'],
            email=data['email'],
            username=data['username'],
            password=hashed_pw.decode('utf-8'),
            role=data['role']
        )

        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "New user created successfully!"}), 201
    except Exception as e:
        print("Error creating user:", str(e))
        return jsonify({"message": "Internal Server Error"}), 500


# ✅ Run Flask App
if __name__ == '__main__':
    app.run(debug=True)
