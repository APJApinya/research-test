from flask import Flask, request, jsonify
from werkzeug.security import safe_str_cmp
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import bcrypt
import sqlite3
import os
import base64
import json
import ssl

app = Flask(__name__)

# Initialize database for simplicity
DATABASE = 'secure_messaging.db'

def create_database():
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT,
        encryption_key BLOB
    )''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY,
        sender INTEGER,
        receiver INTEGER,
        message BLOB,
        FOREIGN KEY (sender) REFERENCES users(id),
        FOREIGN KEY (receiver) REFERENCES users(id)
    )''')
    connection.commit()
    connection.close()

# Key Derivation Function (PBKDF2) for generating a strong key from user password
def generate_password_hash(password):
    salt = bcrypt.gensalt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return bcrypt.hashpw(password.encode(), salt), key

# Encrypt message using AES-GCM
def encrypt_message(key, plaintext):
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    encryptor.authenticate_additional_data(b"authenticated_data")
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv + ciphertext + encryptor.tag

# Decrypt message using AES-GCM
def decrypt_message(key, ciphertext):
    iv = ciphertext[:12]
    tag = ciphertext[-16:]
    ct = ciphertext[12:-16]
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    decryptor.authenticate_additional_data(b"authenticated_data")
    return decryptor.update(ct) + decryptor.finalize()

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    password = data['password']

    try:
        password_hash, key = generate_password_hash(password)

        connection = sqlite3.connect(DATABASE)
        cursor = connection.cursor()
        cursor.execute("INSERT INTO users (username, password_hash, encryption_key) VALUES (?, ?, ?)",
                       (username, password_hash, key))
        connection.commit()
        connection.close()

        return jsonify({"message": "User registered successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"message": "Username already exists"}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()
    cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    connection.close()

    if user and bcrypt.checkpw(password.encode(), user[1]):
        return jsonify({"message": "Login successful", "user_id": user[0]}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.json
    sender = data['sender']
    receiver = data['receiver']
    message = data['message']

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()
    cursor.execute("SELECT encryption_key FROM users WHERE id = ?", (sender,))
    user = cursor.fetchone()

    if not user:
        connection.close()
        return jsonify({"message": "Sender not found"}), 404

    key = user[0]
    encrypted_message = encrypt_message(key, message)

    cursor.execute("INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)",
                   (sender, receiver, encrypted_message))
    connection.commit()
    connection.close()

    return jsonify({"message": "Message sent successfully"}), 201

@app.route('/get_messages/<int:user_id>', methods=['GET'])
def get_messages(user_id):
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()
    cursor.execute("SELECT encryption_key FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if not user:
        connection.close()
        return jsonify({"message": "User not found"}), 404

    key = user[0]
    cursor.execute("SELECT sender, message FROM messages WHERE receiver = ?", (user_id,))
    messages = cursor.fetchall()
    connection.close()

    decrypted_messages = [{"sender": msg[0], "message": decrypt_message(key, msg[1]).decode()} for msg in messages]

    return jsonify(decrypted_messages), 200

if __name__ == '__main__':
    create_database()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
    app.run(host='0.0.0.0', port=5000, ssl_context=context)
