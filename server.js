const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Allow ALL origins (localhost + deployed frontend)
app.use(cors());
app.use(express.json());

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many attempts, try again later.' }
});

// In-memory storage
let users = [];
let passwordResetTokens = new Map();

// Secure 64-char JWT secret
const JWT_SECRET = 'pX9kL2mN7qR4tV8wE3zA6bC9dF1gH5jJ0nP2sT5uY8iO3lK6mN9pQ2rE5tW8xZ';

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

// REGISTER
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { fullName, email, password } = req.body;

    if (!fullName || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email address' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    if (users.find(u => u.email === email)) {
      return res.status(409).json({ error: 'Email already registered' });
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
      message: 'Account created successfully',
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

// FORGOT PASSWORD — UPDATED TO TELL IF USER DOESN'T EXIST
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !isValidEmail(email)) {
      return res.status(400).json({ error: 'Please provide a valid email address' });
    }

    const user = users.find(u => u.email === email);

    if (!user) {
      // CLEAR MESSAGE: User doesn't exist
      return res.status(404).json({
        success: false,
        error: 'No account found with that email'
      });
    }

    // User exists → generate reset token
    const resetToken = uuidv4();
    const resetTokenExpiry = Date.now() + 60 * 60 * 1000; // 1 hour

    passwordResetTokens.set(resetToken, {
      userId: user.id,
      expiresAt: resetTokenExpiry
    });

    // In production: send email here
    console.log(`Password reset link: https://sendm.onrender.com/reset-password?token=${resetToken}`);
    console.log(`Token expires at: ${new Date(resetTokenExpiry).toLocaleString()}`);

    res.json({
      success: true,
      message: 'Password reset link sent to your email'
    });

  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Token verification middleware
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = decoded;
    next();
  });
};

// Protected route: Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  res.json({
    user: { id: user.id, fullName: user.fullName, email: user.email }
  });
});

app.listen(PORT, () => {
  console.log(`Sendm backend running on https://sendm.onrender.com:${PORT}`);
});

module.exports = app;
