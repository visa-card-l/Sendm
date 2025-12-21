// server.js — FIXED VERSION: PROPER DEDUPLICATION + STRING CONCATENATION (December 21, 2025)

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const { Telegraf } = require('telegraf');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Security & Storage
const JWT_SECRET = 'sendm2fa_ultra_secure_jwt_2025!@#$%^&*()_+-=9876543210zyxwvutsrqponmlkjihgfedcba';
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Too many attempts' } });

let users = [];
const activeBots = new Map();
const resetTokens = new Map();
const landingPages = new Map();
const formPages = new Map();
const allSubmissions = new Map(); // userId → array of contact objects
const pendingSubscribers = new Map();

// Broadcast queuing config
const BATCH_SIZE = 25;
const BATCH_INTERVAL_MS = 15000;

// Persistence
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const BROADCASTS_FILE = path.join(DATA_DIR, 'scheduled_broadcasts.json');
let scheduledBroadcasts = new Map();
const scheduledTimeouts = new Map();

function loadScheduledBroadcasts() {
  if (fs.existsSync(BROADCASTS_FILE)) {
    try {
      const data = JSON.parse(fs.readFileSync(BROADCASTS_FILE, 'utf8'));
      for (const entry of data) {
        scheduledBroadcasts.set(entry.broadcastId, entry);
        if (entry.status === 'pending') {
          const delay = entry.scheduledTime - Date.now();
          if (delay > 0) {
            const timeoutId = setTimeout(() => {
              executeScheduledBroadcast(entry.broadcastId);
            }, delay);
            scheduledTimeouts.set(entry.broadcastId, timeoutId);
            console.log('Re-scheduled broadcast ' + entry.broadcastId + ' in ' + Math.round(delay / 1000) + ' seconds');
          } else {
            executeScheduledBroadcast(entry.broadcastId);
          }
        }
      }
      console.log('Loaded ' + scheduledBroadcasts.size + ' scheduled broadcasts from disk');
    } catch (err) {
      console.error('Failed to load scheduled broadcasts:', err.message);
    }
  }
}

function saveScheduledBroadcasts() {
  try {
    const data = Array.from(scheduledBroadcasts.values());
    fs.writeFileSync(BROADCASTS_FILE, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error('Failed to save scheduled broadcasts:', err.message);
  }
}

function executeScheduledBroadcast(broadcastId) {
  const task = scheduledBroadcasts.get(broadcastId);
  if (!task || task.status !== 'pending') {
    console.warn('[SCHEDULED] Task ' + broadcastId + ' not pending or not found');
    return;
  }

  console.log('[SCHEDULED START] Executing broadcast ' + broadcastId + ' for user ' + task.userId);
  const result = executeBroadcast(task.userId, task.message);

  task.status = result.error ? 'failed' : (result.failed === 0 ? 'sent' : 'partial');
  if (result.error) task.error = result.error;
  if (!result.error) task.result = { sent: result.sent, failed: result.failed, total: result.total };
  if (result.failures && result.failures.length) task.failures = result.failures;
  task.executedAt = new Date().toISOString();

  scheduledBroadcasts.set(broadcastId, task);
  scheduledTimeouts.delete(broadcastId);
  saveScheduledBroadcasts();

  console.log('[SCHEDULED END] Broadcast ' + broadcastId + ' completed with status: ' + task.status);
}

function scheduleBroadcast(userId, message, recipients = 'all', scheduledTime) {
  const broadcastId = uuidv4();
  const scheduledMs = new Date(scheduledTime).getTime();
  const entry = {
    broadcastId,
    userId,
    message,
    recipients,
    scheduledTime: scheduledMs,
    createdAt: Date.now(),
    status: 'pending'
  };

  scheduledBroadcasts.set(broadcastId, entry);

  const delay = scheduledMs - Date.now();
  if (delay > 0) {
    const timeoutId = setTimeout(() => {
      executeScheduledBroadcast(broadcastId);
    }, delay);
    scheduledTimeouts.set(broadcastId, timeoutId);
    console.log('Scheduled broadcast ' + broadcastId + ' in ' + Math.round(delay / 1000) + ' seconds');
  } else {
    executeScheduledBroadcast(broadcastId);
  }

  saveScheduledBroadcasts();
  return broadcastId;
}

async function executeBroadcast(userId, message) {
  const bot = activeBots.get(userId);
  if (!bot || !bot.telegram) {
    return { sent: 0, failed: 0, error: 'Bot not connected at execution time' };
  }

  const mySubs = allSubmissions.get(userId) || [];
  const targets = mySubs.filter(s => s.status === 'subscribed' && s.telegramChatId);

  if (targets.length === 0) {
    return { sent: 0, failed: 0, total: 0 };
  }

  const batches = [];
  for (let i = 0; i < targets.length; i += BATCH_SIZE) {
    batches.push(targets.slice(i, i + BATCH_SIZE));
  }

  let sent = 0;
  let failed = 0;
  const failures = [];

  for (let batchIndex = 0; batchIndex < batches.length; batchIndex++) {
    const batch = batches[batchIndex];
    for (const sub of batch) {
      const chatId = sub.telegramChatId;
      try {
        await bot.telegram.sendMessage(chatId, message, { parse_mode: 'HTML' });
        sent++;
      } catch (err) {
        failed++;
        const errorMsg = err.message || err.description || 'Unknown error';
        failures.push({ chatId, error: errorMsg });
      }
    }
    if (batchIndex < batches.length - 1) {
      await new Promise(resolve => setTimeout(resolve, BATCH_INTERVAL_MS));
    }
  }

  return {
    sent,
    failed,
    total: targets.length,
    failures: failures.length > 0 ? failures : undefined
  };
}

// Load on startup
loadScheduledBroadcasts();

// Auto-relaunch bots
users.forEach(user => {
  if (user.telegramBotToken) {
    launchUserBot(user);
  }
});

// Cleanup on shutdown
process.on('SIGTERM', () => {
  for (const timeout of scheduledTimeouts.values()) {
    clearTimeout(timeout);
  }
  scheduledTimeouts.clear();
});

// Helpers
function generate2FACode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function send2FACodeViaBot(user, code) {
  if (!user.isTelegramConnected || !user.telegramChatId || !activeBots.has(user.id)) return false;
  const bot = activeBots.get(user.id);
  try {
    await bot.telegram.sendMessage(user.telegramChatId, 'Security Alert – Password Reset\n\nYour 6-digit code:\n\n<b>' + code + '</b>\n\nValid for 10 minutes.', { parse_mode: 'HTML' });
    return true;
  } catch (err) {
    return false;
  }
}

function escapeHtml(unsafe) {
  return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

function launchUserBot(user) {
  if (activeBots.has(user.id)) {
    activeBots.get(user.id).stop();
    activeBots.delete(user.id);
  }

  const bot = new Telegraf(user.telegramBotToken);

  bot.start(async (ctx) => {
    const payload = ctx.startPayload || '';
    const chatId = ctx.chat.id.toString();

    if (payload.startsWith('sub_') && pendingSubscribers.has(payload)) {
      const sub = pendingSubscribers.get(payload);
      if (sub.userId === user.id) {
        let list = allSubmissions.get(user.id) || [];

        const existingByChatIdIndex = list.findIndex(e => e.telegramChatId === chatId);
        const existingByContactIndex = list.findIndex(e => e.contact === sub.contact);

        if (existingByChatIdIndex !== -1) {
          list[existingByChatIdIndex] = {
            ...list[existingByChatIdIndex],
            name: sub.name,
            contact: sub.contact,
            shortId: sub.shortId,
            subscribedAt: new Date().toISOString(),
            status: 'subscribed',
          };
        } else if (existingByContactIndex !== -1) {
          list[existingByContactIndex] = {
            ...list[existingByContactIndex],
            name: sub.name,
            telegramChatId: chatId,
            shortId: sub.shortId,
            subscribedAt: new Date().toISOString(),
            status: 'subscribed',
          };
        } else {
          list.push({
            name: sub.name,
            contact: sub.contact,
            telegramChatId: chatId,
            shortId: sub.shortId,
            submittedAt: new Date().toISOString(),
            subscribedAt: new Date().toISOString(),
            status: 'subscribed'
          });
        }

        allSubmissions.set(user.id, list);
        pendingSubscribers.delete(payload);

        await ctx.replyWithHTML('<b>✅ Subscription Confirmed!</b>\n\nHi <b>' + escapeHtml(sub.name) + '</b>!\n\nYou\'re now fully subscribed.\n\nThank you ❤️');
        return;
      }
    }

    if (payload === user.id) {
      user.telegramChatId = chatId;
      user.isTelegramConnected = true;
      await ctx.replyWithHTML('<b>Sendm 2FA Connected Successfully! 🔐</b>\n\nYou will now receive login & recovery codes here.\n\n<i>Keep this chat private</i>');
      return;
    }

    await ctx.replyWithHTML('<b>Welcome!</b>\n\nSubscribe from the page to get updates.');
  });

  bot.command('status', (ctx) => {
    ctx.replyWithHTML('<b>Sendm 2FA Status</b>\nAccount: <code>' + user.email + '</code>\nStatus: <b>' + (user.isTelegramConnected ? 'Connected' : 'Not Connected') + '</b>');
  });

  bot.catch((err) => console.error('Bot error [' + user.email + ']:', err));
  bot.launch();
  activeBots.set(user.id, bot);
}

setInterval(() => {
  const now = Date.now();
  for (const [p, d] of pendingSubscribers.entries()) {
    if (now - d.createdAt > 30 * 60 * 1000) pendingSubscribers.delete(p);
  }
}, 60 * 60 * 1000);

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization ? req.headers.authorization.split(' ')[1] : req.query.token;
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = decoded;
    next();
  });
};

// Auth Routes
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { fullName, email, password } = req.body;
  if (!fullName || !email || !password) return res.status(400).json({ error: 'All fields required' });
  if (users.find(u => u.email === email.toLowerCase())) return res.status(409).json({ error: 'Email already exists' });

  const hashed = await bcrypt.hash(password, 12);
  const newUser = {
    id: uuidv4(),
    fullName: fullName,
    email: email.toLowerCase(),
    password: hashed,
    createdAt: new Date().toISOString(),
    telegramBotToken: null,
    telegramChatId: null,
    isTelegramConnected: false,
    botUsername: null
  };

  users.push(newUser);
  const token = jwt.sign({ userId: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '7d' });

  res.status(201).json({
    success: true,
    token: token,
    user: { id: newUser.id, fullName: newUser.fullName, email: newUser.email, isTelegramConnected: false }
  });
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email.toLowerCase());
  if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

  res.json({
    success: true,
    token: token,
    user: { id: user.id, fullName: user.fullName, email: user.email, isTelegramConnected: user.isTelegramConnected }
  });
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user: { id: user.id, fullName: user.fullName, email: user.email, isTelegramConnected: user.isTelegramConnected } });
});

app.post('/api/auth/connect-telegram', authenticateToken, async (req, res) => {
  const { botToken } = req.body;
  if (!botToken || !botToken.trim()) return res.status(400).json({ error: 'Bot token required' });

  const token = botToken.trim();
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  try {
    if (activeBots.has(user.id)) {
      activeBots.get(user.id).stop();
      activeBots.delete(user.id);
    }

    const response = await fetch('https://api.telegram.org/bot' + token + '/getMe');
    const data = await response.json();

    if (!data.ok || !data.result || !data.result.username) return res.status(400).json({ error: 'Invalid bot token' });

    const botUsername = data.result.username.replace(/^@/, '');
    user.telegramBotToken = token;
    user.botUsername = botUsername;
    user.isTelegramConnected = false;
    user.telegramChatId = null;
    launchUserBot(user);

    const startLink = 'https://t.me/' + botUsername + '?start=' + user.id;

    res.json({ success: true, message: 'Bot connected!', botUsername: '@' + botUsername, startLink: startLink });
  } catch (err) {
    res.status(500).json({ error: 'Failed to connect to Telegram' });
  }
});

app.post('/api/auth/change-bot-token', authenticateToken, async (req, res) => {
  const { newBotToken } = req.body;
  if (!newBotToken || !newBotToken.trim()) return res.status(400).json({ error: 'New bot token required' });

  const token = newBotToken.trim();
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  try {
    if (activeBots.has(user.id)) {
      activeBots.get(user.id).stop();
      activeBots.delete(user.id);
    }

    const response = await fetch('https://api.telegram.org/bot' + token + '/getMe');
    const data = await response.json();

    if (!data.ok || !data.result || !data.result.username) return res.status(400).json({ error: 'Invalid bot token' });

    const botUsername = data.result.username.replace(/^@/, '');
    user.telegramBotToken = token;
    user.botUsername = botUsername;
    user.isTelegramConnected = false;
    user.telegramChatId = null;
    launchUserBot(user);

    const startLink = 'https://t.me/' + botUsername + '?start=' + user.id;

    res.json({ success: true, message: 'Bot token updated!', botUsername: '@' + botUsername, startLink: startLink });
  } catch (err) {
    res.status(500).json({ error: 'Failed to validate token' });
  }
});

app.post('/api/auth/disconnect-telegram', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (activeBots.has(user.id)) {
    activeBots.get(user.id).stop();
    activeBots.delete(user.id);
  }

  user.telegramBotToken = null;
  user.botUsername = null;
  user.telegramChatId = null;
  user.isTelegramConnected = false;

  res.json({ success: true, message: 'Telegram disconnected' });
});

app.get('/api/auth/bot-status', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ activated: user.isTelegramConnected, chatId: user.telegramChatId || null });
});

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

  const user = users.find(u => u.email === email.toLowerCase());
  if (!user) return res.json({ success: true, message: 'If account exists, code was sent.' });

  if (!user.isTelegramConnected) return res.status(400).json({ error: 'Telegram 2FA not connected' });

  const code = generate2FACode();
  const resetToken = uuidv4();
  const expiresAt = Date.now() + 10 * 60 * 1000;

  resetTokens.set(resetToken, { userId: user.id, code: code, expiresAt: expiresAt });
  const sent = await send2FACodeViaBot(user, code);
  if (!sent) return res.status(500).json({ error: 'Failed to send code' });

  res.json({ success: true, message: 'Code sent!', resetToken: resetToken });
});

app.post('/api/auth/verify-reset-code', (req, res) => {
  const { resetToken, code } = req.body;
  if (!resetToken || !code) return res.status(400).json({ error: 'Token and code required' });

  const entry = resetTokens.get(resetToken);
  if (!entry || Date.now() > entry.expiresAt) {
    resetTokens.delete(resetToken);
    return res.status(400).json({ error: 'Invalid or expired code' });
  }

  if (entry.code !== code.trim()) return res.status(400).json({ error: 'Wrong code' });

  res.json({ success: true, message: 'Verified', userId: entry.userId });
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { resetToken, newPassword } = req.body;
  if (!resetToken || !newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Valid token and password required' });

  const entry = resetTokens.get(resetToken);
  if (!entry || Date.now() > entry.expiresAt) {
    resetTokens.delete(resetToken);
    return res.status(400).json({ error: 'Invalid session' });
  }

  const user = users.find(u => u.id === entry.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  user.password = await bcrypt.hash(newPassword, 12);
  resetTokens.delete(resetToken);

  res.json({ success: true, message: 'Password reset successful' });
});

// Pages & Forms Routes
app.get('/api/pages', authenticateToken, (req, res) => {
  const userPages = Array.from(landingPages.entries())
    .filter(([_, page]) => page.userId === req.user.userId)
    .map(([shortId, page]) => ({
      shortId: shortId,
      title: page.title,
      createdAt: page.createdAt,
      updatedAt: page.updatedAt,
      url: req.protocol + '://' + req.get('host') + '/p/' + shortId
    }));
  res.json({ pages: userPages });
});

app.post('/api/pages/save', authenticateToken, (req, res) => {
  const { shortId, title, config } = req.body;
  if (!title || !config || !Array.isArray(config.blocks)) return res.status(400).json({ error: 'Title and config.blocks required' });

  const finalShortId = shortId || uuidv4().slice(0, 8);
  const now = new Date().toISOString();

  const cleanBlocks = config.blocks
    .map(block => {
      if (block.isEditor || (block.id && (block.id.includes('editor-') || block.id.includes('control-')))) return null;
      if (block.type === 'text') {
        const content = (block.content || '').trim();
        if (!content) return null;
        return { type: 'text', tag: block.tag || 'p', content: content };
      }
      if (block.type === 'image') {
        const src = block.src ? block.src.trim() : '';
        if (!src) return null;
        return { type: 'image', src: src };
      }
      if (block.type === 'button') {
        const text = (block.text || '').trim();
        if (!text) return null;
        return { type: 'button', text: text, href: block.href || '' };
      }
      if (block.type === 'form') {
        const html = block.html ? block.html.trim() : '';
        if (!html) return null;
        return { type: 'form', html: html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') };
      }
      return null;
    })
    .filter(Boolean);

  if (cleanBlocks.length === 0) return res.status(400).json({ error: 'No valid content blocks found.' });

  landingPages.set(finalShortId, {
    userId: req.user.userId,
    title: title.trim(),
    config: { blocks: cleanBlocks },
    createdAt: landingPages.get(finalShortId) ? landingPages.get(finalShortId).createdAt : now,
    updatedAt: now
  });

  res.json({
    success: true,
    shortId: finalShortId,
    url: req.protocol + '://' + req.get('host') + '/p/' + finalShortId
  });
});

app.post('/api/pages/delete', authenticateToken, (req, res) => {
  const { shortId } = req.body;
  const page = landingPages.get(shortId);
  if (!page || page.userId !== req.user.userId) return res.status(404).json({ error: 'Page not found' });
  landingPages.delete(shortId);
  res.json({ success: true });
});

app.get('/p/:shortId', (req, res) => {
  const page = landingPages.get(req.params.shortId);
  if (!page) return res.status(404).render('404');
  res.render('landing', { title: page.title, blocks: page.config.blocks });
});

app.get('/api/forms', authenticateToken, (req, res) => {
  const userForms = Array.from(formPages.entries())
    .filter(([_, form]) => form.userId === req.user.userId)
    .map(([shortId, formData]) => ({
      shortId: shortId,
      title: formData.title,
      createdAt: formData.createdAt,
      updatedAt: formData.updatedAt,
      url: req.protocol + '://' + req.get('host') + '/f/' + shortId
    }));
  res.json({ forms: userForms });
});

app.post('/api/forms/save', authenticateToken, (req, res) => {
  const { shortId, title, state } = req.body;
  if (!title || !state) return res.status(400).json({ error: 'Title and state required' });

  const sanitizedState = JSON.parse(JSON.stringify(state));
  if (sanitizedState.headerText) sanitizedState.headerText = sanitizedState.headerText.replace(/<script.*?<\/script>/gi, '');
  if (sanitizedState.subheaderText) sanitizedState.subheaderText = sanitizedState.subheaderText.replace(/<script.*?<\/script>/gi, '');
  if (sanitizedState.buttonText) sanitizedState.buttonText = sanitizedState.buttonText.replace(/<script.*?<\/script>/gi, '');

  const finalShortId = shortId || uuidv4().slice(0, 8);
  const now = new Date().toISOString();

  formPages.set(finalShortId, {
    userId: req.user.userId,
    title: title.trim(),
    state: sanitizedState,
    createdAt: formPages.get(finalShortId) ? formPages.get(finalShortId).createdAt : now,
    updatedAt: now
  });

  res.json({
    success: true,
    shortId: finalShortId,
    url: req.protocol + '://' + req.get('host') + '/f/' + finalShortId
  });
});

app.post('/api/forms/delete', authenticateToken, (req, res) => {
  const { shortId } = req.body;
  const formData = formPages.get(shortId);
  if (!formData || formData.userId !== req.user.userId) return res.status(404).json({ error: 'Form not found' });
  formPages.delete(shortId);
  res.json({ success: true });
});

app.get('/f/:shortId', (req, res) => {
  const formData = formPages.get(req.params.shortId);
  if (!formData) return res.status(404).render('404');
  res.render('form', { title: formData.title, state: formData.state });
});

// Subscription & Contacts
app.post('/api/subscribe/:shortId', async (req, res) => {
  const { shortId } = req.params;
  const { name, email } = req.body;

  if (!name || !name.trim() || !email || !email.trim()) {
    return res.status(400).json({ error: 'Valid name and contact required' });
  }

  const page = formPages.get(shortId);
  if (!page) return res.status(404).json({ error: 'Page not found' });

  const owner = users.find(u => u.id === page.userId);
  if (!owner || !owner.telegramBotToken || !owner.botUsername) {
    return res.status(400).json({ error: 'Broadcast bot not connected' });
  }

  const contactValue = email.trim();
  const payload = 'sub_' + shortId + '_' + uuidv4().slice(0, 12);

  let list = allSubmissions.get(owner.id) || [];

  const existingByContactIndex = list.findIndex(c => c.contact === contactValue);

  const baseEntry = {
    name: name.trim(),
    contact: contactValue,
    shortId: shortId,
    submittedAt: new Date().toISOString(),
  };

  if (existingByContactIndex !== -1) {
    // Update existing — preserve status, chatId, subscribedAt
    const existing = list[existingByContactIndex];
    list[existingByContactIndex] = {
      ...existing,
      name: baseEntry.name,
      shortId: baseEntry.shortId,
      submittedAt: baseEntry.submittedAt,
    };
  } else {
    // New contact — start as pending
    list.push({
      ...baseEntry,
      telegramChatId: null,
      subscribedAt: null,
      status: 'pending'
    });
  }

  allSubmissions.set(owner.id, list);

  pendingSubscribers.set(payload, {
    userId: owner.id,
    shortId: shortId,
    name: name.trim(),
    contact: contactValue,
    createdAt: Date.now()
  });

  const deepLink = 'https://t.me/' + owner.botUsername + '?start=' + payload;
  res.json({ success: true, deepLink: deepLink });
});

app.get('/api/contacts', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const allContacts = allSubmissions.get(userId) || [];

  allContacts.sort((a, b) => new Date(b.submittedAt) - new Date(a.submittedAt));

  const contacts = allContacts.map(c => ({
    name: c.name,
    contact: c.contact,
    status: c.status,
    statusLabel: c.status === 'subscribed' ? 'Subscribed ✅' : 'Pending ⏳',
    telegramChatId: c.telegramChatId || null,
    pageId: c.shortId,
    pageUrl: req.protocol + '://' + req.get('host') + '/f/' + c.shortId,
    submittedAt: new Date(c.submittedAt).toLocaleString(),
    subscribedAt: c.subscribedAt ? new Date(c.subscribedAt).toLocaleString() : null
  }));

  const stats = {
    total: allContacts.length,
    subscribed: allContacts.filter(c => c.status === 'subscribed').length,
    pending: allContacts.filter(c => c.status === 'pending').length,
    subscribedPercentage: allContacts.length > 0 ? Math.round((allContacts.filter(c => c.status === 'subscribed').length / allContacts.length) * 100) : 0
  };

  res.json({ success: true, contacts: contacts, stats: stats });
});

app.post('/api/contacts/delete', authenticateToken, (req, res) => {
  const { contacts } = req.body;
  if (!Array.isArray(contacts) || contacts.length === 0) {
    return res.status(400).json({ error: 'Provide an array of contact values to delete' });
  }

  const userId = req.user.userId;
  let list = allSubmissions.get(userId) || [];

  const initialLength = list.length;
  list = list.filter(c => !contacts.includes(c.contact));

  allSubmissions.set(userId, list);

  const deletedCount = initialLength - list.length;

  res.json({
    success: true,
    deletedCount: deletedCount,
    remaining: list.length
  });
});

// Broadcast Routes
app.post('/api/broadcast/now', authenticateToken, async (req, res) => {
  const { message, recipients = 'all' } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message required' });

  const userId = req.user.userId;
  const result = await executeBroadcast(userId, message);

  res.json({ success: true, sent: result.sent, failed: result.failed, total: result.total });
});

app.post('/api/broadcast/schedule', authenticateToken, async (req, res) => {
  const { message, scheduledTime, recipients = 'all' } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message required' });

  const userId = req.user.userId;

  if (scheduledTime === 'now') {
    const result = await executeBroadcast(userId, message);
    return res.json({ success: true, sent: result.sent, failed: result.failed, total: result.total, immediate: true });
  }

  if (!scheduledTime || isNaN(new Date(scheduledTime).getTime())) {
    return res.status(400).json({ error: 'Valid future datetime or "now" required' });
  }

  const scheduled = new Date(scheduledTime);
  if (scheduled <= new Date()) {
    return res.status(400).json({ error: 'Schedule time must be in the future' });
  }

  const broadcastId = scheduleBroadcast(userId, message, recipients, scheduledTime);

  res.json({
    success: true,
    message: 'Broadcast scheduled!',
    broadcastId: broadcastId,
    scheduledTime: scheduled.toISOString(),
    recipients: recipients
  });
});

app.get('/api/broadcast/scheduled', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const scheduled = Array.from(scheduledBroadcasts.values())
    .filter(t => t.userId === userId)
    .map(t => ({
      broadcastId: t.broadcastId,
      message: t.message.substring(0, 100) + (t.message.length > 100 ? '...' : ''),
      scheduledTime: new Date(t.scheduledTime).toISOString(),
      status: t.status,
      executedAt: t.executedAt || null,
      result: t.result || null,
      recipients: t.recipients
    }))
    .sort((a, b) => new Date(b.scheduledTime) - new Date(a.scheduledTime));

  res.json({ success: true, scheduled: scheduled });
});

// Views (EJS files written at startup)
const viewsDir = path.join(__dirname, 'views');
if (!fs.existsSync(viewsDir)) fs.mkdirSync(viewsDir, { recursive: true });
if (!fs.existsSync(path.join(__dirname, 'public'))) fs.mkdirSync(path.join(__dirname, 'public'), { recursive: true });

// landing.ejs
fs.writeFileSync(path.join(viewsDir, 'landing.ejs'), `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><%= title %></title>
  <style>
    :root{--primary:#1564C0;--primary-light:#3485e5;}
    *{margin:0;padding:0;box-sizing:border-box;}
    body{font-family:'Segoe UI',Arial,sans-serif;background:#f5f8fc;color:#343a40;line-height:1.7;}
    .container{max-width:700px;margin:40px auto;background:white;border-radius:24px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,0.12);}
    .content{padding:80px 50px;text-align:center;}
    h1{font-size:42px;font-weight:700;margin-bottom:20px;background:linear-gradient(135deg,var(--primary),var(--primary-light));-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
    .hero-img{max-width:100%;border-radius:18px;box-shadow:0 15px 40px rgba(0,0,0,0.15);margin:50px 0;}
    .cta{display:inline-block;padding:22px 70px;font-size:21px;font-weight:600;background:var(--primary);color:white;border-radius:16px;box-shadow:0 12px 35px rgba(21,100,192,0.4);text-decoration:none;margin-bottom:30px;}
    .form-block{padding:40px;background:#f9fbff;border-radius:20px;margin:50px 0;border:1px solid #e0e7ff;}
    .form-block input,.form-block button{width:100%;padding:16px;margin:10px 0;border-radius:12px;border:1px solid #ddd;font-size:16px;}
    .form-block button{background:var(--primary);color:white;border:none;font-weight:600;cursor:pointer;}
    .footer{padding:40px;background:#f9f9f9;text-align:center;color:#888;font-size:14px;border-top:1px solid #eee;}
  </style>
</head>
<body>
  <div class="container">
    <div class="content">
<% blocks.forEach(block => { %>
      <% if (block.type === 'text') { %>
        <% if (block.tag === 'h1') { %><h1><%= block.content %></h1><% } %>
        <% if (block.tag === 'h2') { %><h2><%= block.content %></h2><% } %>
        <% if (block.tag === 'p') { %><p><%= block.content %></p><% } %>
      <% } else if (block.type === 'image') { %>
        <img src="<%= block.src %>" alt="Image" class="hero-img" loading="lazy">
      <% } else if (block.type === 'button') { %>
        <a href="<%= block.href || '#' %>" class="cta" <%= block.href && block.href.startsWith('http') ? 'target="_blank" rel="noopener"' : '' %>><%= block.text %></a>
      <% } else if (block.type === 'form') { %>
        <div class="form-block"><%- block.html %></div>
      <% } %>
<% }) %>
    </div>
    <div class="footer">
      © <%= new Date().getFullYear() %> Sendm<br>
      <a href="#" style="color:var(--primary);text-decoration:none;">Unsubscribe</a> • <a href="#" style="color:var(--primary);text-decoration:none;">Privacy</a>
    </div>
  </div>
</body>
</html>
`);

// form.ejs
fs.writeFileSync(path.join(viewsDir, 'form.ejs'), `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><%= title %></title>
  <style>
    :root{--primary:#1564C0;--primary-light:#3485e5;}
    *{margin:0;padding:0;box-sizing:border-box;}
    body{font-family:'Segoe UI',Arial,sans-serif;background:#f5f8fc;color:#343a40;line-height:1.7;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}
    .form-container{max-width:500px;width:100%;background:white;border-radius:24px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,0.12);padding:50px 40px;}
    h2{text-align:center;font-size:32px;margin-bottom:12px;}
    .subheader{text-align:center;color:#666;margin-bottom:40px;font-size:17px;}
    .input-group{margin-bottom:20px;}
    .input-group input{width:100%;padding:16px;border-radius:12px;border:1px solid #ddd;font-size:16px;background:#fafbff;}
    button{width:100%;padding:18px;margin-top:20px;background:var(--primary);color:white;border:none;font-weight:600;cursor:pointer;border-radius:12px;font-size:18px;}
    button:hover{background:var(--primary-light);}
    .footer{padding:30px 0;background:#f9f9f9;text-align:center;color:#888;font-size:14px;margin-top:40px;}
  </style>
</head>
<body>
  <div class="form-container">
    <div id="form-content"></div>
    <div class="footer">© <%= new Date().getFullYear() %> Sendm</div>
  </div>

  <script>
    const state = JSON.parse('<%- JSON.stringify(state || {}) %>');
    const container = document.getElementById('form-content');

    if (state.headerText) {
      const h2 = document.createElement('h2');
      h2.textContent = state.headerText;
      container.appendChild(h2);
    }

    if (state.subheaderText) {
      const p = document.createElement('p');
      p.className = 'subheader';
      p.textContent = state.subheaderText;
      container.appendChild(p);
    }

    if (Array.isArray(state.placeholders)) {
      state.placeholders.forEach(field => {
        const div = document.createElement('div');
        div.className = 'input-group';
        const input = document.createElement('input');
        input.type = field.type || 'text';
        input.placeholder = field.placeholder || '';
        input.required = field.required || false;
        div.appendChild(input);
        container.appendChild(div);
      });
    }

    const button = document.createElement('button');
    button.textContent = state.buttonText || 'Subscribe';
    button.style.background = state.buttonColor || 'var(--primary)';
    button.style.color = state.buttonTextColor || '#ffffff';
    container.appendChild(button);

    button.addEventListener('click', async (e) => {
      e.preventDefault();
      const inputs = container.querySelectorAll('input');
      let name = '';
      let email = '';
      inputs.forEach(i => {
        const ph = (i.placeholder || '').toLowerCase();
        if (ph.includes('name')) name = i.value.trim();
        if (ph.includes('email') || ph.includes('phone')) email = i.value.trim();
      });

      if (!name || !email) {
        alert('Please fill name and contact');
        return;
      }

      button.disabled = true;
      button.textContent = 'Processing...';

      const pathParts = window.location.pathname.split('/');
      const shortId = pathParts[pathParts.length - 1];

      try {
        const res = await fetch('/api/subscribe/' + shortId, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: name, email: email })
        });
        const data = await res.json();

        if (data.success) {
          const tgLink = 'https://t.me/' + data.deepLink.split('?start=')[0].replace('https://t.me/', '') + '?start=' + data.deepLink.split('?start=')[1];
          window.location.href = tgLink;
        } else {
          alert(data.error || 'Subscription failed');
          button.disabled = false;
          button.textContent = state.buttonText || 'Subscribe';
        }
      } catch (err) {
        alert('Network error');
        button.disabled = false;
        button.textContent = state.buttonText || 'Subscribe';
      }
    });
  </script>
</body>
</html>
`);

// 404.ejs
fs.writeFileSync(path.join(viewsDir, '404.ejs'), `
<!DOCTYPE html><html><head><title>404</title><style>body{font-family:sans-serif;background:#f8f9fa;text-align:center;padding:100px;color:#333;}h1{font-size:80px;}p{font-size:20px;}</style></head><body><h1>404</h1><p>Page not found</p></body></html>
`);

app.use((req, res) => res.status(404).render('404'));

app.listen(PORT, () => {
  console.log('\nSENDEM SERVER — FIXED DEDUPLICATION + STRING CONCATENATION');
  console.log('http://localhost:' + PORT);
  console.log('✓ No duplicate pending/subscribed entries for same contact');
  console.log('✓ All links use string concatenation');
  console.log('✓ All routes intact\n');
});
