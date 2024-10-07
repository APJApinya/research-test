import os
import hashlib
import base64
import sqlite3
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from flask import Flask, request, jsonify
from OpenSSL import SSL
from werkzeug.security import safe_str_cmp

app = Flask(__name__)

# Database connection (for simplicity, SQLite is used)
db_file = 'secure_app.db'

# Configurations
KEY_ROTATION_LIMIT = 10
SALT = os.urandom(16)  # Can be securely stored per user


# Helper functions
def hash_password(password, salt):
    return PBKDF2(password, salt, dkLen=32)


def encrypt_message(message, key):
    iv = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, iv)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return {
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8')
    }


def decrypt_message(encrypted_data, key):
    iv = base64.b64decode(encrypted_data['iv'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    tag = base64.b64decode(encrypted_data['tag'])
    cipher = AES.new(key, AES.MODE_GCM, iv)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')


def init_db():
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password_hash BLOB, salt BLOB)''')
    # Create message key table
    c.execute('''CREATE TABLE IF NOT EXISTS message_keys
                 (username TEXT, key BLOB, message_count INTEGER)''')
    conn.commit()
    conn.close()


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']

    password_hash = hash_password(password, SALT)

    try:
        conn = sqlite3.connect(db_file)
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                  (username, password_hash, SALT))
        conn.commit()
        conn.close()
        return jsonify({'message': 'User registered successfully'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'User already exists'}), 409


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()

    if row is None:
        return jsonify({'error': 'Invalid username or password'}), 401

    stored_hash, salt = row
    if safe_str_cmp(hash_password(password, salt), stored_hash):
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401


@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()
    sender = data['sender']
    recipient = data['recipient']
    message = data['message']

    # Load recipient's encryption key and perform key rotation if needed
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute("SELECT key, message_count FROM message_keys WHERE username = ?", (recipient,))
    row = c.fetchone()

    if row is None or row[1] >= KEY_ROTATION_LIMIT:
        # Generate a new key
        new_key = os.urandom(32)
        message_count = 0
        c.execute("REPLACE INTO message_keys (username, key, message_count) VALUES (?, ?, ?)",
                  (recipient, new_key, message_count))
    else:
        new_key, message_count = row

    # Encrypt the message
    encrypted_data = encrypt_message(message, new_key)
    c.execute("UPDATE message_keys SET message_count = ? WHERE username = ?", (message_count + 1, recipient))

    conn.commit()
    conn.close()

    return jsonify({'encrypted_message': encrypted_data}), 200


@app.route('/receive_message', methods=['POST'])
def receive_message():
    data = request.get_json()
    username = data['username']
    encrypted_data = data['encrypted_message']

    # Load user's encryption key
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute("SELECT key FROM message_keys WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()

    if row is None:
        return jsonify({'error': 'No key found for the user'}), 404

    key = row[0]
    try:
        message = decrypt_message(encrypted_data, key)
        return jsonify({'message': message}), 200
    except ValueError:
        return jsonify({'error': 'Decryption failed'}), 400


if __name__ == '__main__':
    init_db()

    # HTTPS context with client certificate validation
    context = SSL.Context(SSL.TLSv1_2_METHOD)
    context.use_privatekey_file('server.key')
    context.use_certificate_file('server.crt')
    context.load_verify_locations('client.crt')
    context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, lambda conn, cert, errno, depth, ok: ok)

    app.run(ssl_context=context, host='0.0.0.0', port=443)
