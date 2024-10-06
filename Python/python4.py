import sqlite3
import bcrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os

# Database setup
conn = sqlite3.connect('secure_messaging.db')
c = conn.cursor()

# Create user and messages tables
c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash BLOB)''')
c.execute('''CREATE TABLE IF NOT EXISTS messages (sender TEXT, recipient TEXT, nonce BLOB, ciphertext BLOB, tag BLOB)''')
conn.commit()

# Register user function
def register_user(username, password):
    # Check if user already exists
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    if c.fetchone():
        print("User already exists.")
        return

    # Hash the password
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password.encode(), salt)

    # Store the user in the database
    c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
    conn.commit()
    print("User registered successfully.")

# Login user function
def login_user(username, password):
    c.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    result = c.fetchone()

    if result and bcrypt.checkpw(password.encode(), result[0]):
        print("Login successful.")
        return True
    else:
        print("Login failed. Incorrect username or password.")
        return False

# Encrypt message function
def encrypt_message(key, plaintext):
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return nonce, ciphertext, encryptor.tag

# Decrypt message function
def decrypt_message(key, nonce, ciphertext, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Send message function
def send_message(sender, recipient, plaintext):
    # Derive a key for encryption using recipient's username as the salt
    salt = recipient.encode()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    key = kdf.derive(sender.encode())  # Derive a key using the sender's username

    # Encrypt the message
    nonce, ciphertext, tag = encrypt_message(key, plaintext)

    # Store the message in the database
    c.execute('INSERT INTO messages (sender, recipient, nonce, ciphertext, tag) VALUES (?, ?, ?, ?, ?)',
              (sender, recipient, nonce, ciphertext, tag))
    conn.commit()
    print("Message sent successfully.")

# Read message function
def read_messages(username):
    # Retrieve all messages for the user
    c.execute('SELECT sender, nonce, ciphertext, tag FROM messages WHERE recipient = ?', (username,))
    messages = c.fetchall()

    # Derive a key for decryption using recipient's username as the salt
    salt = username.encode()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())

    for sender, nonce, ciphertext, tag in messages:
        try:
            key = kdf.derive(sender.encode())  # Derive a key using the sender's username
            plaintext = decrypt_message(key, nonce, ciphertext, tag)
            print(f"Message from {sender}: {plaintext.decode()}")
        except Exception as e:
            print(f"Failed to decrypt message from {sender}: {str(e)}")

# Example usage
if __name__ == "__main__":
    while True:
        print("\n1. Register\n2. Login\n3. Send Message\n4. Read Messages\n5. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            username = input("Enter username: ")
            password = input("Enter password: ")
            register_user(username, password)

        elif choice == '2':
            username = input("Enter username: ")
            password = input("Enter password: ")
            if login_user(username, password):
                print(f"Welcome {username}!")

        elif choice == '3':
            sender = input("Enter your username: ")
            recipient = input("Enter recipient username: ")
            plaintext = input("Enter message: ")
            send_message(sender, recipient, plaintext)

        elif choice == '4':
            username = input("Enter your username: ")
            read_messages(username)

        elif choice == '5':
            break

        else:
            print("Invalid choice. Please try again.")

conn.close()
