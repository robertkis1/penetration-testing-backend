import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import bcrypt
import jwt
import datetime

app = Flask(__name__)
CORS(app)

# Load environment variables from Render
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_default_secret_key')  # Fallback for local testing
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')
app.config['JWT_EXPIRATION_TIME'] = int(os.getenv('JWT_EXPIRATION_TIME', 3600))  # 1 hour by default
BCRYPT_LOG_ROUNDS = int(os.getenv('BCRYPT_LOG_ROUNDS', 12))  # Default bcrypt security rounds

db = SQLAlchemy(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'admin' or 'user'
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# Create the database tables if they don't exist
with app.app_context():
    db.create_all()

# User Registration Route
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

# User Login Route
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    
    if user and bcrypt.checkpw(data['password'].encode('utf-8'), user.password.encode('utf-8')):
        token = jwt.encode(
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

# Get Users (Admin Only)
@app.route('/admin/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([{"id": u.id, "full_name": u.full_name, "email": u.email, "username": u.username, "role": u.role} for u in users])

# Delete User (Admin)
@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"}), 200
    return jsonify({"message": "User not found"}), 404

# Update User Profile (User)
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

# Run Application
if __name__ == '__main__':
    app.run(debug=True)
