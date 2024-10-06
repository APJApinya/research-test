from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from os import urandom
import base64
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.urandom(16)  # Secret key for session
backend = default_backend()

# Create or connect to SQLite database
DATABASE = 'secure_messaging.db'
conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    encryption_key BLOB NOT NULL)''')
cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id INTEGER NOT NULL,
                    recipient_id INTEGER NOT NULL,
                    encrypted_message BLOB NOT NULL,
                    iv BLOB NOT NULL,
                    FOREIGN KEY(sender_id) REFERENCES users(id),
                    FOREIGN KEY(recipient_id) REFERENCES users(id))''')
conn.commit()
conn.close()

# Helper functions
def generate_key(password: bytes, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    return kdf.derive(password)

def encrypt_message(key, plaintext):
    iv = urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return (ciphertext, iv, encryptor.tag)

def decrypt_message(key, iv, tag, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=backend)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Flask Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        salt = os.urandom(16)
        key = generate_key(password.encode(), salt)
        password_hash = generate_password_hash(password)
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password_hash, encryption_key) VALUES (?, ?, ?)',
                           (username, password_hash, key))
            conn.commit()
        except sqlite3.IntegrityError:
            return 'Username already exists.'
        finally:
            conn.close()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            return redirect(url_for('home'))
        
        return 'Invalid credentials'
    
    return render_template('login.html')

@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Display received messages
    cursor.execute('SELECT sender_id, encrypted_message, iv FROM messages WHERE recipient_id = ?', (user_id,))
    messages = []
    for sender_id, ciphertext, iv in cursor.fetchall():
        cursor.execute('SELECT encryption_key FROM users WHERE id = ?', (user_id,))
        key = cursor.fetchone()[0]
        plaintext = decrypt_message(key, iv, ciphertext[:16], ciphertext[16:])
        messages.append({'sender_id': sender_id, 'message': plaintext})
    
    if request.method == 'POST':
        recipient_username = request.form['recipient']
        message = request.form['message']
        
        cursor.execute('SELECT id, encryption_key FROM users WHERE username = ?', (recipient_username,))
        recipient = cursor.fetchone()
        if recipient:
            recipient_id, recipient_key = recipient
            ciphertext, iv, tag
