const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const { Telegraf } = require('telegraf');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Rate limiter for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { error: 'Too many attempts, try again later.' }
});

// In-memory storage (replace with database in production)
let users = [];
let resetCodes = new Map();
const activeBots = new Map();

// JWT Secret â€” use environment variable in production!
const JWT_SECRET = process.env.JWT_SECRET || 'pX9kL2mN7qR4tV8wE3zA6bC9dF1gH5jJ0nP2sT5uY8iO3lK6mN9pQ2rE5tW8xZ';

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

// ========================
// AUTHENTICATION MIDDLEWARE
// ========================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = decoded;
    next();
  });
};

// ========================
// TELEGRAM BOT LAUNCHER
// ========================
function launchUserBot(user) {
  if (!user.telegramBotToken || activeBots.has(user.id)) return;

  const bot = new Telegraf(user.telegramBotToken);

  bot.start(async (ctx) => {
    const chatId = ctx.chat.id.toString();
    user.telegramChatId = chatId;
    user.isTelegramConnected = true;

    await ctx.replyWithHTML(`
<b>Sendm 2FA Activated!</b>

You will now receive password reset codes here.
<i>Never share your bot token.</i>
    `);

    console.log(`2FA activated for ${user.email}`);
  });

  bot.command('status', (ctx) => {
    ctx.replyWithHTML(`
<b>Sendm Status</b>
Account: <code>${user.email}</code>
2FA: <b>${user.isTelegramConnected ? 'Active' : 'Not connected'}</b>
    `);
  });

  bot.launch();
  activeBots.set(user.id, bot);
  console.log(`Bot launched for ${user.email}`);
}

// ========================
// ROUTES
// ========================

// Register
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password) return res.status(400).json({ error: 'All fields required' });
    if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email' });
    if (password.length < 6) return res.status(400).json({ error: 'Password too short' });

    if (users.find(u => u.email === email.toLowerCase())) {
      return res.status(409).json({ error: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = {
      id: uuidv4(),
      fullName,
      email: email.toLowerCase(),
      password: hashedPassword,
      createdAt: new Date().toISOString(),
      telegramBotToken: null,
      telegramChatId: null,
      isTelegramConnected: false
    };

    users.push(newUser);

    const token = jwt.sign({ userId: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      success: true,
      message: 'Account created!',
      token,
      user: { id: newUser.id, fullName, email: newUser.email, isTelegramConnected: false }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email.toLowerCase());

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        fullName: user.fullName,
        email: user.email,
        isTelegramConnected: user.isTelegramConnected
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  res.json({
    user: {
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      isTelegramConnected: user.isTelegramConnected
    }
  });
});

// CONNECT TELEGRAM BOT â€” SAFE + DIRECT getMe CHECK
app.post('/api/auth/connect-telegram', authenticateToken, async (req, res) => {
  const { botToken } = req.body;

  if (!botToken || typeof botToken !== 'string') {
    return res.status(400).json({ error: 'Bot token is required' });
  }

  const token = botToken.trim();

  try {
    // Direct call to Telegram API â€” no Telegraf dependency here
    const response = await fetch(`https://api.telegram.org/bot${token}/getMe`);

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      console.log('Telegram rejected token:', errData);

      if (response.status === 401) return res.status(400).json({ error: 'Invalid bot token (Unauthorized)' });
      if (response.status === 404) return res.status(400).json({ error: 'Token not found. Did you copy the full token?' });
      return res.status(400).json({ error: 'Invalid bot token' });
    }

    const data = await response.json();
    if (!data.ok || !data.result?.is_bot) {
      return res.status(400).json({ error: 'Not a valid bot token' });
    }

    const botUsername = data.result.username ? `@${data.result.username}` : 'your bot';

    // Save to user
    const user = users.find(u => u.id === req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.telegramBotToken = token;
    user.isTelegramConnected = false; // becomes true after /start

    // Launch bot to listen for /start
    launchUserBot(user);

    console.log(`Telegram bot connected: \( {user.email} â†’ \){botUsername}`);

    res.json({
      success: true,
      message: 'Bot connected! Open it in Telegram and tap /start',
      botUsername
    });

  } catch (err) {
    console.error('Token validation failed:', err.message);
    res.status(500).json({ error: 'Failed to connect bot. Try again.' });
  }
});

// Forgot password â†’ send code via Telegram
app.post('/api/auth/forgot-password', async (req, res) => {
  // ... (your existing code - unchanged)
});

// Reset password with code
app.post('/api/auth/reset-password', async (req, res) => {
  // ... (your existing code - unchanged)
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Sendm Auth Backend running on port ${PORT}`);
  console.log(`https://sendm.onrender.com`);
});

module.exports = app;
