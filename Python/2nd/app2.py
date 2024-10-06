from flask import Flask, request, jsonify, redirect, url_for
from models import db, User, Message
from utils import hash_password, encrypt_message, decrypt_message, rotate_key
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_messaging.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'User already exists'}), 400

    salt = os.urandom(16)
    password_hash = hash_password(password, salt)
    encryption_key = os.urandom(32)  # Symmetric key generation

    new_user = User(username=username, password_hash=password_hash, encryption_key=encryption_key)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()
    sender = User.query.filter_by(username=data['sender']).first()
    recipient = User.query.filter_by(username=data['recipient']).first()
    message = data['message']

    if not sender or not recipient:
        return jsonify({'error': 'User not found'}), 400

    ciphertext = encrypt_message(sender.encryption_key, message)
    
    new_message = Message(sender_id=sender.id, recipient_id=recipient.id, ciphertext=ciphertext)
    db.session.add(new_message)
    db.session.commit()
    
    return jsonify({'message': 'Message sent successfully'})

@app.route('/inbox', methods=['GET'])
def inbox():
    user = User.query.filter_by(username=request.args.get('username')).first()
    if not user:
        return jsonify({'error': 'User not found'}), 400
    
    messages = Message.query.filter_by(recipient_id=user.id).all()
    decrypted_messages = [{'sender': User.query.get(msg.sender_id).username, 
                           'message': decrypt_message(user.encryption_key, msg.ciphertext)} for msg in messages]
    
    return jsonify({'messages': decrypted_messages})

if __name__ == '__main__':
    app.run(ssl_context=('certificates/server.crt', 'certificates/server.key'))
