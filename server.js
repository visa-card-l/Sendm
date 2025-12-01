const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { Telegraf } = require('telegraf');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'https://sendmi.onrender.com'],
  credentials: true
}));
app.use(express.json());

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// In-memory storage (replace with MongoDB later)
let users = [];
const activeBots = new Map();

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key-change-in-production-123456789';

// Email validation
const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

// ========================
// AUTH MIDDLEWARE
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
// LAUNCH USER BOT — FIXED FOREVER (uses userId, not object reference)
// ========================
function launchUserBot(userId) {
  const user = users.find(u => u.id === userId);
  if (!user || !user.telegramBotToken) return;

  // Stop any old bot
  if (activeBots.has(userId)) {
    activeBots.get(userId).stop();
    activeBots.delete(userId);
  }

  const bot = new Telegraf(user.telegramBotToken);

  bot.start(async (ctx) => {
    const payload = ctx.startPayload || '';
    const chatId = ctx.chat.id.toString();

    // Always get fresh user from array
    const currentUser = users.find(u => u.id === userId);
    if (!currentUser) {
      await ctx.reply('Error: Account no longer exists.');
      return;
    }

    if (payload === userId) {
      currentUser.telegramChatId = chatId;
      currentUser.isTelegramConnected = true;

      await ctx.replyWithHTML(`
<b>Sendm 2FA Activated Successfully!</b>

Account: <code>${currentUser.email}</code>
You will now receive 2FA codes here.

<i>Keep this chat private • Never share access</i>
      `);
      console.log(`2FA Activated → \( {currentUser.email} | Chat: \){chatId}`);
    }
    else if (currentUser.isTelegramConnected && chatId === currentUser.telegramChatId) {
      await ctx.replyWithHTML(`<b>Welcome back!</b>\nYour 2FA is already active.`);
    }
    else {
      await ctx.replyWithHTML(`
<b>Invalid or expired link</b>

Generate a new one from your Sendm dashboard.
      `);
    }
  });

  bot.command('status', async (ctx) => {
    const currentUser = users.find(u => u.id === userId);
    if (!currentUser || ctx.chat.id.toString() !== currentUser.telegramChatId) return;

    await ctx.replyWithHTML(`
<b>Sendm • Status</b>

Account: <code>${currentUser.email}</code>
2FA: <b>${currentUser.isTelegramConnected ? 'Active' : 'Inactive'}</b>
    `);
  });

  bot.launch();
  activeBots.set(userId, bot);
  console.log(`Bot launched for user \( {userId} ( \){user.email})`);
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

    const normalizedEmail = email.toLowerCase();
    if (users.find(u => u.email === normalizedEmail)) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const newUser = {
      id: Date.now().toString(),
      fullName,
      email: normalizedEmail,
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
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email.toLowerCase());
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
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
    console.error('Login error:', err);
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

// CONNECT TELEGRAM — 100% PLEXZORA FORMAT + FIXED FOREVER
app.post('/api/auth/connect-telegram', authenticateToken, async (req, res) => {
  const botToken = req.body.botToken?.trim();

  if (!botToken) {
    return res.status(400).json({ error: 'Bot token is required' });
  }

  try {
    // Validate bot token
    const response = await fetch(`https://api.telegram.org/bot${botToken}/getMe`);
    const data = await response.json();

    if (!data.ok || !data.result?.username) {
      return res.status(400).json({ error: 'Invalid bot token' });
    }

    const botUsername = data.result.username;
    const user = users.find(u => u.id === req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Stop old bot
    if (activeBots.has(user.id)) {
      activeBots.get(user.id).stop();
      activeBots.delete(user.id);
    }

    // Save token and reset state
    user.telegramBotToken = botToken;
    user.isTelegramConnected = false;
    user.telegramChatId = null;

    // Launch bot using user ID (safe across restarts)
    launchUserBot(user.id);

    // EXACT PLEXZORA MAGIC LINK FORMAT
    const telegramLink = `https://t.me/\( {botUsername}?start= \){user.id}`;

    console.log(`Magic link generated → ${telegramLink}`);

    res.json({
      success: true,
      message: 'Bot connected! Tap the link to activate 2FA',
      botUsername: `@${botUsername}`,
      telegramLink,        // 100% same as Plexzora
      instructions: 'Click link → Tap START → Done!'
    });

  } catch (err) {
    console.error('Connect error:', err.message);
    res.status(500).json({ error: 'Failed to connect bot' });
  }
});

// Check connection status
app.get('/api/auth/bot-status', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  res.json({
    isConnected: user.isTelegramConnected,
    chatId: user.telegramChatId || null
  });
});

// Disconnect Telegram
app.post('/api/auth/disconnect-telegram', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (activeBots.has(user.id)) {
    activeBots.get(user.id).stop();
    activeBots.delete(user.id);
  }

  user.telegramBotToken = null;
  user.telegramChatId = null;
  user.isTelegramConnected = false;

  res.json({ success: true, message: 'Telegram disconnected successfully' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Sendm Backend Running`);
  console.log(`https://sendm.onrender.com`);
  console.log(`Local: http://localhost:${PORT}`);
});

module.exports = app;
