from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
import bcrypt
import base64
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = os.urandom(24)
db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    encryption_key = db.Column(db.String(120), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_message = db.Column(db.Text, nullable=False)

# Registration Endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Generate encryption key for the user
    encryption_key = Fernet.generate_key()
    
    # Store user in the database
    new_user = User(username=username, password=hashed_password.decode('utf-8'), encryption_key=encryption_key.decode('utf-8'))
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

# Login Endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return jsonify({'message': 'Invalid credentials'}), 401

    return jsonify({'message': 'Login successful', 'user_id': user.id}), 200

# Send Message Endpoint
@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()
    sender_id = data['sender_id']
    recipient_username = data['recipient_username']
    message = data['message']

    sender = User.query.get(sender_id)
    recipient = User.query.filter_by(username=recipient_username).first()

    if not sender or not recipient:
        return jsonify({'message': 'Sender or recipient not found'}), 404

    # Encrypt the message using the recipient's encryption key
    recipient_key = recipient.encryption_key.encode('utf-8')
    fernet = Fernet(recipient_key)
    encrypted_message = fernet.encrypt(message.encode('utf-8'))

    # Store the encrypted message in the database
    new_message = Message(sender_id=sender.id, recipient_id=recipient.id, encrypted_message=encrypted_message.decode('utf-8'))
    db.session.add(new_message)
    db.session.commit()

    return jsonify({'message': 'Message sent successfully'}), 201

# Read Message Endpoint
@app.route('/read_message', methods=['GET'])
def read_message():
    user_id = request.args.get('user_id')
    recipient = User.query.get(user_id)

    if not recipient:
        return jsonify({'message': 'Recipient not found'}), 404

    # Retrieve all messages for this recipient
    messages = Message.query.filter_by(recipient_id=recipient.id).all()
    decrypted_messages = []

    for msg in messages:
        fernet = Fernet(recipient.encryption_key.encode('utf-8'))
        decrypted_message = fernet.decrypt(msg.encrypted_message.encode('utf-8')).decode('utf-8')
        decrypted_messages.append({
            'sender_id': msg.sender_id,
            'message': decrypted_message
        })

    return jsonify(decrypted_messages), 200

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
