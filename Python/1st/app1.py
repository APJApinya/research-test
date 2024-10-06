from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import bcrypt
import os
import base64

app = Flask(__name__)

# In-memory "database" for users and messages
users_db = {}
messages_db = {}
key_rotation_threshold = 10

def generate_symmetric_key():
    """Generates a symmetric key for AES encryption."""
    return os.urandom(32)  # 256-bit key

def generate_iv():
    """Generates a random IV."""
    return os.urandom(12)  # 96-bit IV for AES-GCM

def encrypt_message(message, key):
    """Encrypt a message using AES-GCM with authenticated encryption."""
    iv = generate_iv()
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encryptor.tag + ciphertext).decode()

def decrypt_message(encrypted_message, key):
    """Decrypt a message using AES-GCM."""
    encrypted_message_bytes = base64.b64decode(encrypted_message)
    iv = encrypted_message_bytes[:12]
    tag = encrypted_message_bytes[12:28]
    ciphertext = encrypted_message_bytes[28:]
    
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def hash_password(password):
    """Hash a password for secure storage."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

def verify_password(password, hashed):
    """Verify a password."""
    return bcrypt.checkpw(password.encode(), hashed)

def derive_key_from_password(password, salt):
    """Derive a symmetric key from the user's password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

@app.route('/register', methods=['POST'])
def register():
    """Register a new user with a password."""
    username = request.json.get('username')
    password = request.json.get('password')
    
    if username in users_db:
        return jsonify({"error": "User already exists"}), 400

    # Hash the password and generate an encryption key
    hashed_password = hash_password(password)
    encryption_key = generate_symmetric_key()
    users_db[username] = {
        'password': hashed_password,
        'key': encryption_key,
        'messages_sent': 0
    }
    
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    """Login a user and verify the password."""
    username = request.json.get('username')
    password = request.json.get('password')
    
    user = users_db.get(username)
    
    if not user or not verify_password(password, user['password']):
        return jsonify({"error": "Invalid username or password"}), 400

    return jsonify({"message": "Login successful"}), 200

@app.route('/send_message', methods=['POST'])
def send_message():
    """Send an encrypted message to another user."""
    sender = request.json.get('sender')
    recipient = request.json.get('recipient')
    message = request.json.get('message')
    
    if recipient not in users_db:
        return jsonify({"error": "Recipient does not exist"}), 400
    
    user = users_db[sender]
    
    # Check for key rotation
    if user['messages_sent'] >= key_rotation_threshold:
        user['key'] = generate_symmetric_key()
        user['messages_sent'] = 0
    
    # Encrypt the message
    encrypted_message = encrypt_message(message, user['key'])
    
    # Store the message
    if recipient not in messages_db:
        messages_db[recipient] = []
    
    messages_db[recipient].append({
        'from': sender,
        'message': encrypted_message
    })
    
    user['messages_sent'] += 1
    
    return jsonify({"message": "Message sent successfully"}), 200

@app.route('/get_messages', methods=['POST'])
def get_messages():
    """Retrieve encrypted messages for a user."""
    username = request.json.get('username')
    
    if username not in messages_db:
        return jsonify({"messages": []}), 200
    
    user = users_db[username]
    encrypted_messages = messages_db[username]
    
    # Decrypt the messages
    decrypted_messages = [
        {
            'from': msg['from'],
            'message': decrypt_message(msg['message'], user['key'])
        }
        for msg in encrypted_messages
    ]
    
    return jsonify({"messages": decrypted_messages}), 200

# Placeholder for certificate validation simulation
@app.route('/validate_certificate', methods=['GET'])
def validate_certificate():
    """Simulate certificate validation between client and server."""
    return jsonify({"message": "Certificate validated successfully"}), 200

if __name__ == '__main__':
    app.run(ssl_context='adhoc')
