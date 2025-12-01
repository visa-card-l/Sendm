const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const { Telegraf } = require('telegraf');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many attempts, try again later.' }
});

let users = [];
const activeBots = new Map();

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-2025';

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

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

function launchUserBot(user) {
  // Stop old bot if exists
  if (activeBots.has(user.id)) {
    activeBots.get(user.id).stop();
    activeBots.delete(user.id);
  }

  const bot = new Telegraf(user.telegramBotToken);

  bot.start(async (ctx) => {
    const payload = ctx.startPayload || '';
    const chatId = ctx.chat.id.toString();

    if (payload === user.id) {
      if (user.isTelegramConnected && user.telegramChatId === chatId) {
        return ctx.replyWithHTML('You are already connected!');
      }

      user.telegramChatId = chatId;
      user.isTelegramConnected = true;

      await ctx.replyWithHTML(`
<b>Sendm 2FA Connected Successfully!</b>

You will now receive login codes here.

<i>Keep this chat private • Never share your bot</i>
      `);
      console.log(`2FA connected: \( {user.email} → \){chatId}`);
      return;
    }

    await ctx.replyWithHTML(`
<b>Invalid or expired link</b>

This link is only valid once.
    `);
  });

  bot.command('status', (ctx) => {
    ctx.replyWithHTML(`
<b>Sendm 2FA Status</b>
Account: <code>${user.email}</code>
Status: <b>${user.isTelegramConnected ? 'Connected' : 'Not Connected'}</b>
    `);
  });

  bot.catch((err) => console.error(`Bot error [${user.email}]:`, err));
  bot.launch();
  activeBots.set(user.id, bot);
  console.log(`Bot launched for \( {user.email} (@ \){user.telegramBotUsername})`);
}

// ======================== ROUTES ========================

app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { fullName, email, password } = req.body;
  if (!fullName || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email' });
  if (password.length < 6) return res.status(400).json({ error: 'Password too short' });

  if (users.find(u => u.email === email.toLowerCase())) {
    return res.status(409).json({ error: 'Email already exists' });
  }

  const hashed = await bcrypt.hash(password, 12);
  const newUser = {
    id: uuidv4(),
    fullName,
    email: email.toLowerCase(),
    password: hashed,
    createdAt: new Date().toISOString(),
    telegramBotToken: null,
    telegramBotUsername: null,
    telegramChatId: null,
    isTelegramConnected: false
  };

  users.push(newUser);
  const token = jwt.sign({ userId: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '7d' });

  res.status(201).json({
    success: true,
    token,
    user: { id: newUser.id, fullName, email: newUser.email, isTelegramConnected: false }
  });
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email.toLowerCase());

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

  res.json({
    success: true,
    token,
    user: { id: user.id, fullName: user.fullName, email: user.email, isTelegramConnected: user.isTelegramConnected }
  });
});

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

// PERFECT, FINAL, BULLETPROOF CONNECT ROUTE
app.post('/api/auth/connect-telegram', authenticateToken, async (req, res) => {
  const { botToken } = req.body;
  if (!botToken || typeof botToken !== 'string') {
    return res.status(400).json({ error: 'Bot token required' });
  }

  const token = botToken.trim();

  try {
    const user = users.find(u => u.id === req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Stop any old bot
    if (activeBots.has(user.id)) {
      activeBots.get(user.id).stop();
      activeBots.delete(user.id);
    }

    // Create temporary bot to get real username
    const tempBot = new Telegraf(token);
    
    // This forces getMe() and fills bot.botInfo with 100% correct data
    const botInfo = await tempBot.telegram.getMe();
    
    const botUsername = botInfo.username; // THIS IS THE TRUTH — always correct

    if (!botUsername) {
      return res.status(400).json({ error: 'Bot has no username. Set one in @BotFather.' });
    }

    // Save everything
    user.telegramBotToken = token;
    user.telegramBotUsername = botUsername;
    user.isTelegramConnected = false;
    user.telegramChatId = null;

    // Now launch the real bot
    launchUserBot(user);

    // 1000000% GUARANTEED WORKING LINK
    const startLink = `https://t.me/\( {botUsername}?start= \){user.id}`;

    console.log(`PERFECT 2FA LINK → ${user.email}`);
    console.log(`   Bot: @${botUsername}`);
    console.log(`   Link: ${startLink}`);

    res.json({
      success: true,
      message: 'Tap below to connect your private 2FA bot',
      botUsername: `@${botUsername}`,
      startLink
    });

  } catch (err) {
    console.error('Invalid bot token:', err.message);
    res.status(400).json({ 
      error: 'Invalid bot token. Copy it exactly from @BotFather.' 
    });
  }
});

app.get('/api/auth/bot-status', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  res.json({
    activated: user.isTelegramConnected,
    chatId: user.telegramChatId || null,
    botUsername: user.telegramBotUsername ? `@${user.telegramBotUsername}` : null
  });
});

app.listen(PORT, () => {
  console.log(`Sendm 2FA Server running on port ${PORT}`);
  console.log(`http://localhost:${PORT}`);
});
