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
  origin: ['http://localhost:3000', 'https://sendm.onrender.com'],
  credentials: true
}));
app.use(express.json());

// Rate limiter for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// In-memory storage (use MongoDB/Redis in production)
let users = [];
const activeBots = new Map();

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'pX9kL2mN7qR4tV8wE3zA6bC9dF1gH5jJ0nP2sT5uY8iO3lK6mN9pQ2rE5tW8xZ';

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
// LAUNCH USER BOT (Plexzora-style)
// ========================
function launchUserBot(user) {
  // Stop existing bot if running
  if (activeBots.has(user.id)) {
    activeBots.get(user.id).stop();
    activeBots.delete(user.id);
  }

  if (!user.telegramBotToken) return;

  const bot = new Telegraf(user.telegramBotToken);

  bot.start(async (ctx) => {
    const payload = ctx.startPayload || '';
    const chatId = ctx.chat.id.toString();

    // Plexzora logic: payload must exactly equal user.id
    if (payload === user.id) {
      user.telegramChatId = chatId;
      user.isTelegramConnected = true;

      await ctx.replyWithHTML(`
<b>Sendm 2FA Activated Successfully!</b>

Account: <code>${user.email}</code>
You will now receive 2FA codes here.

<i>Keep this chat private • Never share your bot token</i>
      `);
      console.log(`2FA activated: \( {user.email} → Chat ID: \){chatId}`);
    } 
    else if (user.isTelegramConnected && chatId === user.telegramChatId) {
      await ctx.replyWithHTML(`
<b>Welcome back!</b>

Your Sendm 2FA is active and ready.
Use /status anytime.
      `);
    } 
    else {
      await ctx.replyWithHTML(`
<b>Invalid or expired link</b>

Please generate a new activation link from your Sendm dashboard.
      `);
    }
  });

  bot.command('status', (ctx) => {
    if (ctx.chat.id.toString() !== user.telegramChatId) {
      return ctx.reply('This bot belongs to another account.');
    }
    ctx.replyWithHTML(`
<b>Sendm • Connection Status</b>

Account: <code>${user.email}</code>
Status: <b>${user.isTelegramConnected ? 'Active' : 'Not Connected'}</b>
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
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

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
      message: 'Account created successfully',
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

// Connect Telegram — EXACTLY LIKE PLEXZORA
app.post('/api/auth/connect-telegram', authenticateToken, async (req, res) => {
  const { botToken = req.body.botToken?.trim();

  if (!botToken) {
    return res.status(400).json({ error: 'Bot token is required' });
  }

  try {
    // Validate bot token with Telegram API
    const response = await fetch(`https://api.telegram.org/bot${botToken}/getMe`);
    const data = await response.json();

    if (!data.ok || !data.result?.username) {
      return res.status(400).json({ error: 'Invalid bot token. Please check and try again.' });
    }

    const botUsername = data.result.username;
    const user = users.find(u => u.id === req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Stop any previous bot
    if (activeBots.has(user.id)) {
      activeBots.get(user.id).stop();
      activeBots.delete(user.id);
    }

    // Save token and reset connection state
    user.telegramBotToken = botToken;
    user.isTelegramConnected = false;
    user.telegramChatId = null;

    // Launch the bot (this populates bot.botInfo)
    const bot = new Telegraf(botToken);

    bot.start(async (ctx) => {
      if (ctx.startPayload === user.id) {
        user.telegramChatId = ctx.chat.id.toString();
        user.isTelegramConnected = true;

        await ctx.replyWithHTML(`
<b>Sendm 2FA Activated!</b>

Account: <code>${user.email}</code>
You will now receive login codes here.

<i>Keep this chat safe • Never share access</i>
        `);
      } else if (user.isTelegramConnected && ctx.chat.id.toString() === user.telegramChatId) {
        await ctx.replyWithHTML(`<b>Already connected!</b>\nWelcome back.`);
      } else {
        await ctx.replyWithHTML(`<b>Invalid link</b>\nGenerate a new one from dashboard.`);
      }
    });

    bot.command('status', (ctx) => {
      if (ctx.chat.id.toString() !== user.telegramChatId) return;
      ctx.replyWithHTML(`
<b>Sendm Status</b>
Account: <code>${user.email}</code>
2FA: <b>${user.isTelegramConnected ? 'Active' : 'Inactive'}</b>
      `);
    });

    bot.launch();
    activeBots.set(user.id, bot);

    // EXACT PLEXZORA FORMAT — 100% IDENTICAL
    const telegramLink = `https://t.me/\( {botUsername}?start= \){user.id}`;

    console.log(`Generated Plexzora-style link → ${telegramLink}`);

    res.json({
      success: true,
      message: 'Bot connected! Tap the link below to activate 2FA',
      botUsername: `@${botUsername}`,
      telegramLink, // This is the magic link — exactly like Plexzora
      instructions: 'Click link → Tap "START" → Done!'
    });

  } catch (err) {
    console.error('Telegram connection failed:', err.message);
    res.status(500).json({ error: 'Failed to connect bot. Try again.' });
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
  console.log(`Sendm Backend Running → https://sendm.onrender.com:${PORT}`);
  console.log(`Local: http://localhost:${PORT}`);
});

module.exports = app;
