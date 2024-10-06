# Import necessary libraries
import sqlite3
import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64

# Setting up the database
conn = sqlite3.connect(':memory:')
cursor = conn.cursor()

cursor.execute('''CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash BLOB NOT NULL,
                    encryption_key BLOB NOT NULL)''')

cursor.execute('''CREATE TABLE messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id INTEGER NOT NULL,
                    recipient_id INTEGER NOT NULL,
                    encrypted_message BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    FOREIGN KEY(sender_id) REFERENCES users(id),
                    FOREIGN KEY(recipient_id) REFERENCES users(id))''')

conn.commit()

# Utility functions
def generate_key():
    """Generates a 32-byte key for AES-GCM encryption"""
    return AESGCM.generate_key(bit_length=256)

def encrypt_message(key, message):
    """Encrypts the message with the given key using AES-GCM"""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # AES-GCM requires a 12-byte nonce
    encrypted_message = aesgcm.encrypt(nonce, message.encode(), None)
    return encrypted_message, nonce

def decrypt_message(key, encrypted_message, nonce):
    """Decrypts the encrypted message with the given key using AES-GCM"""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, encrypted_message, None).decode()

# User Registration
def register_user(username, password):
    # Generate password hash using bcrypt
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    encryption_key = generate_key()

    try:
        cursor.execute('INSERT INTO users (username, password_hash, encryption_key) VALUES (?, ?, ?)',
                       (username, password_hash, encryption_key))
        conn.commit()
        print(f"User {username} registered successfully.")
    except sqlite3.IntegrityError:
        print(f"Username '{username}' already exists. Please choose a different username.")

# User Login
def login_user(username, password):
    cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    if user and bcrypt.checkpw(password.encode(), user[1]):
        print(f"User {username} logged in successfully.")
        return user[0]
    else:
        print("Invalid username or password.")
        return None

# Send Encrypted Message
def send_message(sender_id, recipient_username, message):
    cursor.execute('SELECT id, encryption_key FROM users WHERE username = ?', (recipient_username,))
    recipient = cursor.fetchone()

    if not recipient:
        print(f"Recipient '{recipient_username}' does not exist.")
        return

    recipient_id, recipient_key = recipient

    # Encrypt the message with recipient's key
    encrypted_message, nonce = encrypt_message(recipient_key, message)

    # Store the message in the database
    cursor.execute('INSERT INTO messages (sender_id, recipient_id, encrypted_message, nonce) VALUES (?, ?, ?, ?)',
                   (sender_id, recipient_id, encrypted_message, nonce))
    conn.commit()
    print(f"Message sent to {recipient_username} successfully.")

# Read Encrypted Message
def read_messages(user_id):
    cursor.execute('SELECT sender_id, encrypted_message, nonce FROM messages WHERE recipient_id = ?', (user_id,))
    messages = cursor.fetchall()

    if not messages:
        print("No messages found.")
        return

    cursor.execute('SELECT encryption_key FROM users WHERE id = ?', (user_id,))
    user_key = cursor.fetchone()[0]

    for sender_id, encrypted_message, nonce in messages:
        cursor.execute('SELECT username FROM users WHERE id = ?', (sender_id,))
        sender_username = cursor.fetchone()[0]
        decrypted_message = decrypt_message(user_key, encrypted_message, nonce)
        print(f"Message from {sender_username}: {decrypted_message}")

# Example Usage
register_user("alice", "password123")
register_user("bob", "securepassword")

alice_id = login_user("alice", "password123")
bob_id = login_user("bob", "securepassword")

if alice_id:
    send_message(alice_id, "bob", "Hello Bob, how are you?")

if bob_id:
    read_messages(bob_id)

