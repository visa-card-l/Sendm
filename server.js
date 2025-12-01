const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { Telegraf } = require('telegraf');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: ['http://localhost:3000', 'https://sendmi.onrender.com'],
  credentials: true
}));
app.use(express.json());

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many attempts, try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

let users = [];
const activeBots = new Map();
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-2025';

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token required' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
};

function launchUserBot(userId) {
  const user = users.find(u => u.id === userId);
  if (!user?.telegramBotToken) return;

  if (activeBots.has(userId)) {
    activeBots.get(userId).stop().catch(() => {});
    activeBots.delete(userId);
  }

  const bot = new Telegraf(user.telegramBotToken);

  bot.start(async (ctx) => {
    const payload = ctx.startPayload || '';
    const chatId = ctx.chat.id.toString();
    const currentUser = users.find(u => u.id === userId);
    if (!currentUser) return await ctx.reply('Account error.');

    if (payload === userId) {
      currentUser.telegramChatId = chatId;
      currentUser.isTelegramConnected = true;
      await ctx.replyWithHTML(`
<b>Sendmi 2FA Activated!</b>

Account: <code>${currentUser.email}</code>
You’ll receive codes here.

<i>Keep this chat private • Never share</i>
      `);
      console.log(`2FA Activated → ${currentUser.email}`);
    } else if (currentUser.isTelegramConnected && chatId === currentUser.telegramChatId) {
      await ctx.replyWithHTML(`<b>Welcome back!</b>\n2FA is active.`);
    } else {
      await ctx.replyWithHTML(`<b>Invalid link</b>\nGenerate a new one from dashboard.`);
    }
  });

  bot.command('status', async (ctx) => {
    const user = users.find(u => u.id === userId);
    if (!user || ctx.chat.id.toString() !== user.telegramChatId) return;
    await ctx.replyWithHTML(`
<b>Sendmi Status</b>
Account: <code>${user.email}</code>
2FA: <b>${user.isTelegramConnected ? 'Active' : 'Inactive'}</b>
    `);
  });

  bot.launch();
  activeBots.set(userId, bot);
  console.log(`Bot launched → ${user.email}`);
}

// ======================== ROUTES ========================

app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { fullName, email, password } = req.body;
  if (!fullName || !email || !password) return res.status(400).json({ error: 'All fields required' });
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email' });
  if (password.length < 6) return res.status(400).json({ error: 'Password too short' });

  const normalizedEmail = email.toLowerCase().trim();
  if (users.find(u => u.email === normalizedEmail)) return res.status(409).json({ error: 'Email taken' });

  const hashed = await bcrypt.hash(password, 12);
  const newUser = {
    id: Date.now().toString(),
    fullName: fullName.trim(),
    email: normalizedEmail,
    password: hashed,
    createdAt: new Date().toISOString(),
    telegramBotToken: null,
    telegramChatId: null,
    isTelegramConnected: false
  };
  users.push(newUser);

  const token = jwt.sign({ userId: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '7d' });

  res.status(201).json({
    success: true, token,
    user: { id: newUser.id, fullName: newUser.fullName, email: newUser.email, isTelegramConnected: false }
  });
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email.toLowerCase().trim());
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ success: true, token, user: { id: user.id, fullName: user.fullName, email: user.email, isTelegramConnected: user.isTelegramConnected } });
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user: { id: user.id, fullName: user.fullName, email: user.email, isTelegramConnected: user.isTelegramConnected } });
});

// FINAL FIXED TELEGRAM CONNECT — NO @ IN LINK
app.post('/api/auth/connect-telegram', authenticateToken, async (req, res) => {
  const botToken = req.body.botToken?.trim();
  if (!botToken) return res.status(400).json({ error: 'Bot token required' });

  try {
    const resp = await fetch(`https://api.telegram.org/bot${botToken}/getMe`);
    const data = await resp.json();

    if (!data.ok || !data.result?.username)
      return res.status(400).json({ error: 'Invalid bot token' });

    const botUsername = data.result.username; // ← NO @
    const botName = data.result.first_name;

    const user = users.find(u => u.id === req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (activeBots.has(user.id)) {
      await activeBots.get(user.id).stop().catch(() => {});
      activeBots.delete(user.id);
    }

    user.telegramBotToken = botToken;
    user.isTelegramConnected = false;
    user.telegramChatId = null;
    launchUserBot(user.id);

    const telegramLink = `https://t.me/\( {botUsername}?start= \){user.id}`;

    res.json({
      success: true,
      message: 'Bot connected!',
      botUsername: `@${botUsername}`,
      botName,
      telegramLink,
      instructions: 'Click link → Tap START → Done!'
    });
  } catch (err) {
    res.status(500).json({ error: 'Connection failed' });
  }
});

app.get('/api/auth/bot-status', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json({ isConnected: user.isTelegramConnected, chatId: user.telegramChatId });
});

app.post('/api/auth/disconnect-telegram', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'Not found' });

  if (activeBots.has(user.id)) {
    activeBots.get(user.id).stop().catch(() => {});
    activeBots.delete(user.id);
  }

  user.telegramBotToken = null;
  user.telegramChatId = null;
  user.isTelegramConnected = false;

  res.json({ success: true, message: 'Disconnected' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Sendmi Backend Running`);
  console.log(`https://sendmi.onrender.com`);
  console.log(`Local: http://localhost:${PORT}`);
});

module.exports = app;
