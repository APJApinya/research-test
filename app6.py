import os
import secrets
from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    encryption_key = db.Column(db.LargeBinary, nullable=False)
    message_count = db.Column(db.Integer, default=0)

db.create_all()

# Utility to derive key using PBKDF2
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Utility to generate random encryption key
def generate_key() -> bytes:
    return os.urandom(32)

# User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    salt = os.urandom(16)
    encryption_key = derive_key(password, salt)
    password_hash = generate_password_hash(password)

    new_user = User(username=username, password_hash=password_hash, encryption_key=encryption_key)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201

# User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        session['user_id'] = user.id
        return jsonify({"message": "Login successful"}), 200

    return jsonify({"error": "Invalid credentials"}), 401

# Encrypt message using AES-GCM
def encrypt_message(key: bytes, message: str):
    iv = os.urandom(12)  # Secure random IV for AES-GCM
    aesgcm = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = aesgcm.update(message.encode()) + aesgcm.finalize()
    return iv + ciphertext + aesgcm.tag

# Decrypt message using AES-GCM
def decrypt_message(key: bytes, ciphertext: bytes):
    iv, tag, actual_ciphertext = ciphertext[:12], ciphertext[-16:], ciphertext[12:-16]
    aesgcm = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    return aesgcm.update(actual_ciphertext) + aesgcm.finalize()

# Send message to another user
@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return jsonify({"error": "Authentication required"}), 401

    data = request.json
    recipient_username = data.get('recipient')
    message = data.get('message')

    recipient = User.query.filter_by(username=recipient_username).first()
    if not recipient:
        return jsonify({"error": "Recipient not found"}), 404

    # Check if key rotation is needed
    if recipient.message_count >= 10:
        recipient.encryption_key = generate_key()
        recipient.message_count = 0

    encrypted_message = encrypt_message(recipient.encryption_key, message)
    # For simplicity, store encrypted message in recipient's object
    recipient.message_count += 1
    db.session.commit()

    return jsonify({"message": "Message sent successfully", "encrypted_message": encrypted_message.hex()}), 200

# Secure connection simulation - using HTTPS in deployment
@app.before_first_request
def secure_connection_setup():
    # This is to ensure the server runs securely, but local testing may use HTTP.
    print("Ensure to use HTTPS in production to secure client-server communication.")

# Example secure message retrieval
@app.route('/get_messages', methods=['GET'])
def get_messages():
    if 'user_id' not in session:
        return jsonify({"error": "Authentication required"}), 401

    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Simulate retrieval of stored messages (not fully implemented)
    return jsonify({"message": "No new messages"}), 200

if __name__ == '__main__':
    # Ensure to use an HTTPS server in production
    app.run(ssl_context='adhoc', debug=True)
