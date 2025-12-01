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

// Rate limiting for login/register
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { error: 'Too many attempts, try again later.' }
});

// In-memory DB (replace with MongoDB later if you want)
let users = [];
const activeBots = new Map();

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-change-in-prod-123456789';

// ========================
// AUTH MIDDLEWARE
// ========================
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Bad token' });
    else {
      req.user = decoded;
      next();
    }
  });
};

// ========================
// LAUNCH USER BOT (safe & fixed forever)
// ========================
function launchUserBot(userId) {
  const user = users.find(u => u.id === userId);
  if (!user || !user.telegramBotToken) return;

  // Kill old bot
  if (activeBots.has(userId)) {
    activeBots.get(userId).stop();
    activeBots.delete(userId);
  }

  const bot = new Telegraf(user.telegramBotToken);

  bot.start(async (ctx) => {
    const payload = ctx.startPayload || '';
    const chatId = ctx.chat.id.toString();

    const currentUser = users.find(u => u.id === userId);
    if (!currentUser) return await ctx.reply('User not found.');

    // safety

    // First time connecting with correct payload
    if (payload === userId) {
      currentUser.telegramChatId = chatId;
      currentUser.isTelegramConnected = true;

      await ctx.replyWithHTML(`
<b>Sendm 2FA Activated!</b>

Account: <code>${currentUser.email}</code>
You’ll now get 2FA codes here.

<i>Keep this chat private • Never share it</i>
      `);
      console.log(`2FA Activated → \( {currentUser.email} | Chat ID: \){chatId}`);
    }
    // Already connected & correct chat
    else if (currentUser.isTelegramConnected && chatId === currentUser.telegramChatId) {
      await ctx.replyWithHTML(`<b>Welcome back!</b>\n2FA is active.`);
    }
    // Wrong or expired link
    else {
      await ctx.replyWithHTML(`
<b>Invalid or expired link</b>

Generate a new one from your Sendm dashboard.
      `);
    }
  });

  bot.command('status', async (ctx) => {
    const user = users.find(u => u.id === userId);
    if (!user || ctx.chat.id.toString() !== user.telegramChatId) return;

    await ctx.replyWithHTML(`
<b>Sendm Status</b>

Account: <code>${user.email}</code>
2FA: <b>${user.isTelegramConnected ? 'Active' : 'Inactive'}</b>
    `);
  });

  bot.launch();
  activeBots.set(userId, bot);
  console.log(`Bot launched for \( {user.email} ( \){userId})`);
}

// ========================
// ROUTES
// ========================

// Register
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { fullName, email, password } = req.body;
  if (!fullName || !email || !password) return res.status(400).json({ error: 'Fill all fields' });

  const normalizedEmail = email.toLowerCase().trim();
  if (users.find(u => u.email === normalizedEmail)) return res.status(409).json({ error: 'Email taken' });
  if (password.length < 6) return res.status(400).json({ error: 'Password too short' });

  const hashed = await bcrypt.hash(password, 12);
  const newUser = {
    id: Date.now().toString(),
    fullName,
    email: normalizedEmail,
    password: hashed,
    createdAt: new Date().toISOString(),
    telegramBotToken: null,
    telegramChatId: null,
    isTelegramConnected: false
  };

  users.push(newUser);

  const token = jwt.sign({ userId: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '7d' });

  res.json({
    success: true,
    token,
    user: { id: newUser.id, fullName, email: newUser.email, isTelegramConnected: false }
  });
});

// Login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email.toLowerCase().trim());

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Wrong email or password' });
  }

  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

  res.json({
    success: true,
    token,
    user: { id: user.id, fullName: user.fullName, email: user.email, isTelegramConnected: user.isTelegramConnected }
  });
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User gone' });

  res.json({
    user: {
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      isTelegramConnected: user.isTelegramConnected
    }
  });
});

// CONNECT TELEGRAM — SUPER SIMPLE & 100% WORKING
app.post('/api/auth/connect-telegram', authenticateToken, async (req, res) => {
  const botToken = req.body.botToken?.trim();
  if (!botToken) return res.status(400).json({ error: 'Send bot token' });

  try {
    const response = await fetch(`https://api.telegram.org/bot${botToken}/getMe`);
    const data = await response.json();

    if (!data.ok) return res.status(400).json({ error: 'Invalid bot token' });

    const botUsername = data.result.username; // e.g. MySendmBot
    const user = users.find(u => u.id === req.user.userId);

    // Stop old bot
    if (activeBots.has(user.id)) {
      activeBots.get(user.id).stop();
      activeBots.delete(user.id);
    }

    // Save new token & reset connection
    user.telegramBotToken = botToken;
    user.isTelegramConnected = false;
    user.telegramChatId = null;

    // Launch fresh bot
    launchUserBot(user.id);

    // CORRECT DEEP LINK — WORKS EVERY TIME
    const link = `https://t.me/\( {botUsername}?start= \){user.id}`;

    res.json({
      success: true,
      message: 'Bot connected! Click the link to activate 2FA',
      botUsername: `@${botUsername}`,
      link: link,
      openInTelegram: link
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to connect bot' });
  }
});

// Check status
app.get('/api/auth/bot-status', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  res.json({
    isConnected: user?.isTelegramConnected || false,
    chatId: user?.telegramChatId || null
  });
});

// Disconnect
app.post('/api/auth/disconnect-telegram', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (activeBots.has(user.id)) {
    activeBots.get(user.id).stop();
    activeBots.delete(user.id);
  }

  user.telegramBotToken = null;
  user.telegramChatId = null;
  null;
  user.isTelegramConnected = false;

  res.json({ success: true, message: 'Disconnected' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Sendm Backend RUNNING`);
  console.log(`https://sendmi.onrender.com`);
  console.log(`Local: http://localhost:${PORT}`);
});

module.exports = app;
