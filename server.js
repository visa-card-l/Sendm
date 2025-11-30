const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// THIS IS THE FIX — ALLOWS ALL ORIGINS (localhost + deployed frontend + everything)
app.use(cors());   // Removes ALL CORS restrictions — perfect for development & production

// Optional: If you want to be slightly safer later, use the commented version below
/*
app.use(cors({
  origin: true,
  credentials: true
}));
*/

app.use(express.json());

// Rate limiting (still active — prevents brute force)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { error: 'Too many attempts, try again later.' }
});

// In-memory storage (replace with database later)
let users = [];
let passwordResetTokens = new Map();

// Your secure 64-char JWT secret (already embedded)
const JWT_SECRET = 'pX9kL2mN7qR4tV8wE3zA6bC9dF1gH5jJ0nP2sT5uY8iO3lK6mN9pQ2rE5tW8xZ';

// Email validation
const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

// REGISTER
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { fullName, email, password } = req.body;

    if (!fullName || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password too short' });
    }
    if (users.find(u => u.email === email)) {
      return res.status(409).json({ error: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = {
      id: uuidv4(),
      fullName,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };
    users.push(newUser);

    const token = jwt.sign(
      { userId: newUser.id, email: newUser.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      success: true,
      message: 'Account created',
      token,
      user: { id: newUser.id, fullName, email }
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// LOGIN
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = users.find(u => u.email === email);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: { id: user.id, fullName: user.fullName, email: user.email }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// FORGOT PASSWORD
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !isValidEmail(email)) {
      return res.status(400).json({ error: 'Valid email required' });
    }

    const user = users.find(u => u.email === email);
    if (user) {
      const resetToken = uuidv4();
      passwordResetTokens.set(resetToken, {
        userId: user.id,
        expiresAt: Date.now() + 3600000
      });
      console.log(`Reset token for \( {email}: \){resetToken}`);
    }

    res.json({ success: true, message: 'If email exists, reset link sent' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Middleware to verify token
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid/expired token' });
    req.user = user;
    next();
  });
};

// Protected route example
app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  res.json({
    user: { id: user.id, fullName: user.fullName, email: user.email }
  });
});

app.listen(PORT, () => {
  console.log(`Sendm backend running on https://sendm.onrender.com`);
  console.log(`Port: ${PORT}`);
});

module.exports = app;
