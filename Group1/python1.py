from flask import Flask, request, jsonify, session
from flask_bcrypt import Bcrypt
import sqlite3
from flask_cors import CORS

app = Flask(__name__)
bcrypt = Bcrypt(app)
CORS(app)

app.secret_key = 'your_secret_key'  # Update with a secure key

DATABASE = 'database.db'

# Initialize database with tables for users and messages
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            sender_id INTEGER NOT NULL,
                            recipient_id INTEGER NOT NULL,
                            message TEXT NOT NULL,
                            FOREIGN KEY(sender_id) REFERENCES users(id),
                            FOREIGN KEY(recipient_id) REFERENCES users(id))''')

init_db()

# Register endpoint
@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
            conn.commit()
            return jsonify({'message': 'User registered successfully.'}), 201
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Username already exists.'}), 400

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[1], password):
            session['user_id'] = user[0]
            return jsonify({'message': 'Login successful.'}), 200
        else:
            return jsonify({'error': 'Invalid credentials.'}), 401

# Send message endpoint
@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized.'}), 401

    recipient_username = request.json.get('recipient')
    message = request.json.get('message')

    if not recipient_username or not message:
        return jsonify({'error': 'Recipient and message are required.'}), 400

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (recipient_username,))
        recipient = cursor.fetchone()

        if recipient:
            recipient_id = recipient[0]
            sender_id = session['user_id']
            cursor.execute("INSERT INTO messages (sender_id, recipient_id, message) VALUES (?, ?, ?)",
                           (sender_id, recipient_id, message))
            conn.commit()
            return jsonify({'message': 'Message sent successfully.'}), 200
        else:
            return jsonify({'error': 'Recipient not found.'}), 404

# Get messages endpoint
@app.route('/get_messages', methods=['GET'])
def get_messages():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized.'}), 401

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''SELECT users.username, messages.message 
                          FROM messages
                          JOIN users ON messages.sender_id = users.id
                          WHERE messages.recipient_id = ?''', (session['user_id'],))
        messages = cursor.fetchall()

    response = [{'sender': msg[0], 'message': msg[1]} for msg in messages]
    return jsonify(response), 200

# Logout endpoint
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out successfully.'}), 200

if __name__ == '__main__':
    app.run(debug=True)
