from flask import Flask, request, jsonify, session
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from os import urandom
import base64

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = urandom(16)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Create a user table with a hashed password and encryption key
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    encryption_key = db.Column(db.String(150), nullable=False)
    message_count = db.Column(db.Integer, default=0)

db.create_all()

# Function to generate a key using PBKDF2 (Password-based Key Derivation Function)
def generate_key(password, salt, iterations=100000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Generate a random encryption key
def generate_encryption_key():
    return base64.urlsafe_b64encode(urandom(32)).decode('utf-8')

# Generate random IV for AES-GCM encryption
def generate_iv():
    return urandom(12)

# AES-GCM encryption
def encrypt_message(key, message):
    iv = generate_iv()
    encryptor = Cipher(
        algorithms.AES(base64.urlsafe_b64decode(key)),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + encryptor.tag + ciphertext).decode('utf-8')

# AES-GCM decryption
def decrypt_message(key, encrypted_message):
    encrypted_message = base64.urlsafe_b64decode(encrypted_message)
    iv = encrypted_message[:12]
    tag = encrypted_message[12:28]
    ciphertext = encrypted_message[28:]
    decryptor = Cipher(
        algorithms.AES(base64.urlsafe_b64decode(key)),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Key rotation after 10 messages
def rotate_key(user):
    if user.message_count >= 10:
        user.encryption_key = generate_encryption_key()
        user.message_count = 0

### User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    password = data['password']
    
    # Generate password hash and store in the database
    salt = urandom(16)
    password_hash = generate_key(password, salt)
    
    # Generate symmetric key for encryption
    encryption_key = generate_encryption_key()
    
    user = User(username=username, password_hash=password_hash.decode('utf-8'), encryption_key=encryption_key)
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'User registered successfully'}), 201

### User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']
    
    user = User.query.filter_by(username=username).first()
    if user:
        salt = user.password_hash[:16].encode('utf-8')
        password_hash = generate_key(password, salt)
        if password_hash.decode('utf-8') == user.password_hash:
            session['user'] = user.id
            return jsonify({'message': 'Logged in successfully'}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

### Send Message
@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user' not in session:
        return jsonify({'message': 'User not logged in'}), 403
    
    data = request.json
    recipient_username = data['recipient']
    message = data['message']
    
    recipient = User.query.filter_by(username=recipient_username).first()
    if recipient:
        rotate_key(recipient)
        encrypted_message = encrypt_message(recipient.encryption_key, message)
        
        recipient.message_count += 1
        db.session.commit()
        
        return jsonify({'message': 'Message sent', 'encrypted_message': encrypted_message}), 200
    return jsonify({'message': 'Recipient not found'}), 404

### Receive Message (Assuming the messages are stored securely on the server)
@app.route('/receive_message', methods=['POST'])
def receive_message():
    if 'user' not in session:
        return jsonify({'message': 'User not logged in'}), 403
    
    data = request.json
    encrypted_message = data['encrypted_message']
    
    user = User.query.get(session['user'])
    decrypted_message = decrypt_message(user.encryption_key, encrypted_message)
    
    return jsonify({'message': decrypted_message.decode('utf-8')}), 200

### Certificate Validation Simulation
@app.route('/validate_certificate', methods=['POST'])
def validate_certificate():
    # Simulate certificate validation (in reality, this is handled by HTTPS)
    return jsonify({'message': 'Certificate validated'}), 200

if __name__ == '__main__':
    app.run(ssl_context='adhoc')
