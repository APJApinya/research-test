// Import necessary libraries
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Setup Express app
const app = express();
app.use(express.json());

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/secure-messaging', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Define User and Message Schema
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  key: String,
});

const messageSchema = new mongoose.Schema({
  sender: String,
  recipient: String,
  content: String, // Encrypted message
});

// Models
const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

// Helper function to generate a random encryption key
function generateEncryptionKey() {
  return crypto.randomBytes(32).toString('hex');
}

// User Registration Endpoint
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const key = generateEncryptionKey(); // Generate a unique encryption key for each user

    const user = new User({ username, password: hashedPassword, key });
    await user.save();

    res.status(201).send('User registered successfully');
  } catch (error) {
    res.status(500).send('Error registering user');
  }
});

// User Login Endpoint
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign({ username }, 'secretKey', { expiresIn: '1h' });
      res.json({ token });
    } else {
      res.status(401).send('Invalid credentials');
    }
  } catch (error) {
    res.status(500).send('Error logging in');
  }
});

// Middleware for authenticating JWT tokens
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, 'secretKey', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Send Encrypted Message Endpoint
app.post('/send-message', authenticateToken, async (req, res) => {
  try {
    const { recipientUsername, message } = req.body;
    const sender = req.user.username;

    // Find recipient's encryption key
    const recipient = await User.findOne({ username: recipientUsername });
    if (!recipient) return res.status(404).send('Recipient not found');

    // Encrypt the message using recipient's key
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(recipient.key, 'hex'), iv);
    let encrypted = cipher.update(message, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');

    const encryptedMessage = `${iv.toString('hex')}:${authTag}:${encrypted}`;

    // Save the encrypted message
    const newMessage = new Message({ sender, recipient: recipientUsername, content: encryptedMessage });
    await newMessage.save();

    res.status(200).send('Message sent successfully');
  } catch (error) {
    res.status(500).send('Error sending message');
  }
});

// Read Messages Endpoint
app.get('/messages', authenticateToken, async (req, res) => {
  try {
    const recipientUsername = req.user.username;
    const messages = await Message.find({ recipient: recipientUsername });

    const decryptedMessages = await Promise.all(
      messages.map(async (msg) => {
        // Decrypt the message using recipient's key
        const recipient = await User.findOne({ username: recipientUsername });
        if (!recipient) return null;

        const [iv, authTag, encryptedContent] = msg.content.split(':');
        const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(recipient.key, 'hex'), Buffer.from(iv, 'hex'));
        decipher.setAuthTag(Buffer.from(authTag, 'hex'));
        let decrypted = decipher.update(encryptedContent, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return { sender: msg.sender, content: decrypted };
      })
    );

    res.json(decryptedMessages);
  } catch (error) {
    res.status(500).send('Error retrieving messages');
  }
});

// Start the server
app.listen(3000, () => {
  console.log('Server running on port 3000');
});
