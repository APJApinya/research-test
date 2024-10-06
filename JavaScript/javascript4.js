const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const port = 3000;

// Middleware to parse JSON bodies
app.use(express.json());

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/secure_messaging_app', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Define User Schema and Model
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});

const User = mongoose.model('User', userSchema);

// Define Message Schema and Model
const messageSchema = new mongoose.Schema({
  sender: String,
  recipient: String,
  content: String,
});

const Message = mongoose.model('Message', messageSchema);

// User Registration
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({ username });
  if (existingUser) {
    return res.status(400).json({ message: 'User already exists' });
  }

  // Hash password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Create new user
  const newUser = new User({ username, password: hashedPassword });
  await newUser.save();

  res.status(201).json({ message: 'User registered successfully' });
});

// User Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Find user
  const user = await User.findOne({ username });
  if (!user) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  // Check password
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  // Generate JWT token
  const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '1h' });

  res.status(200).json({ message: 'Login successful', token });
});

// Middleware to authenticate user using JWT
const authenticateUser = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(403).json({ message: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Failed to authenticate token' });
    }
    req.username = decoded.username;
    next();
  });
};

// Send Encrypted Message
app.post('/message', authenticateUser, async (req, res) => {
  const { recipient, message } = req.body;
  const sender = req.username;

  // Find recipient user
  const recipientUser = await User.findOne({ username: recipient });
  if (!recipientUser) {
    return res.status(404).json({ message: 'Recipient not found' });
  }

  // Generate encryption key
  const encryptionKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);

  // Encrypt the message
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
  let encryptedMessage = cipher.update(message, 'utf8', 'hex');
  encryptedMessage += cipher.final('hex');

  const authTag = cipher.getAuthTag().toString('hex');

  // Save encrypted message to database
  const newMessage = new Message({
    sender,
    recipient,
    content: JSON.stringify({
      iv: iv.toString('hex'),
      encryptedMessage,
      authTag,
    }),
  });

  await newMessage.save();

  res.status(200).json({ message: 'Message sent successfully' });
});

// Read Encrypted Message
app.get('/message/:from', authenticateUser, async (req, res) => {
  const recipient = req.username;
  const sender = req.params.from;

  // Find message
  const message = await Message.findOne({ sender, recipient });
  if (!message) {
    return res.status(404).json({ message: 'Message not found' });
  }

  const { iv, encryptedMessage, authTag } = JSON.parse(message.content);

  // Generate decryption key (in a real application, this should be securely stored)
  const encryptionKey = crypto.randomBytes(32);

  // Decrypt the message
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));

  let decryptedMessage = decipher.update(encryptedMessage, 'hex', 'utf8');
  decryptedMessage += decipher.final('utf8');

  res.status(200).json({ message: decryptedMessage });
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
