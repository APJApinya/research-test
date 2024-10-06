import os
import sqlite3
from flask import Flask, request, jsonify, session, redirect, url_for
from cryptography.fernet import Fernet
from bcrypt import hashpw, gensalt, checkpw

app = Flask(__name__)
app.secret_key = os.urandom(24)
DATABASE = 'users.db'

# Utility Functions
def get_db():
    conn = sqlite3.connect(DATABASE)
    return conn

def init_db():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                key TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                encrypted_message TEXT NOT NULL
            )
        ''')
        conn.commit()

# User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400

    password_hash = hashpw(password.encode('utf-8'), gensalt())
    key = Fernet.generate_key()

    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password_hash, key) VALUES (?, ?, ?)',
                           (username, password_hash, key))
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Username already exists'}), 400

    return jsonify({'message': 'User registered successfully'}), 201

# User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()

    if user and checkpw(password.encode('utf-8'), user[0]):
        session['username'] = username
        return jsonify({'message': 'Logged in successfully'}), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 400

# Send Message
@app.route('/send_message', methods=['POST'])
def send_message():
    if 'username' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    data = request.json
    recipient = data.get('recipient')
    message = data.get('message')

    if not recipient or not message:
        return jsonify({'error': 'Missing recipient or message'}), 400

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT key FROM users WHERE username = ?', (recipient,))
        user = cursor.fetchone()

    if not user:
        return jsonify({'error': 'Recipient not found'}), 404

    key = user[0]
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode('utf-8'))

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO messages (sender, recipient, encrypted_message) VALUES (?, ?, ?)',
                       (session['username'], recipient, encrypted_message.decode('utf-8')))
        conn.commit()

    return jsonify({'message': 'Message sent successfully'}), 201

# Retrieve Messages
@app.route('/get_messages', methods=['GET'])
def get_messages():
    if 'username' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    username = session['username']

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT encrypted_message FROM messages WHERE recipient = ?', (username,))
        messages = cursor.fetchall()
        cursor.execute('SELECT key FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    key = user[0]
    fernet = Fernet(key)

    decrypted_messages = [fernet.decrypt(msg[0].encode('utf-8')).decode('utf-8') for msg in messages]

    return jsonify({'messages': decrypted_messages}), 200

# Logout
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return jsonify({'message': 'Logged out successfully'}), 200

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
