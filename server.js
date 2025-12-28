require('dotenv').config();

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const { Telegraf } = require('telegraf');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== SENSITIVE DATA FROM .env ====================
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_weak_secret_change_me_immediately';
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || 'sk_test_fallback_change_me';
const PAYSTACK_PUBLIC_KEY = process.env.PAYSTACK_PUBLIC_KEY || 'pk_test_fallback_change_me';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'midas';

// Warnings if secrets are not properly set
if (JWT_SECRET === 'fallback_weak_secret_change_me_immediately') {
  console.warn('⚠️  WARNING: JWT_SECRET not set in .env! Using insecure fallback.');
}
if (PAYSTACK_SECRET_KEY.startsWith('sk_test_fallback')) {
  console.warn('⚠️  WARNING: PAYSTACK_SECRET_KEY not set in .env!');
}

// ==================== PAYSTACK CONFIG ====================
const MONTHLY_PRICE = 500000; // ₦5,000 in kobo (Paystack uses smallest currency unit)

// ==================== DYNAMIC SERVER LIMITS (CONTROLLED VIA /admin-limits) ====================
let DAILY_BROADCAST_LIMIT = 3;
let MAX_LANDING_PAGES = 5;
let MAX_FORMS = 5;

// ==============================================================================================

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Security & Storage
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Too many attempts' } });

let users = [];
const activeBots = new Map();
const resetTokens = new Map();
const landingPages = new Map();
const formPages = new Map();
const allSubmissions = new Map();
const pendingSubscribers = new Map();

// Daily broadcast tracking
const userBroadcastDaily = new Map();

// Broadcast config
const BATCH_SIZE = 25;
const BATCH_INTERVAL_MS = 15000;
const MAX_MSG_LENGTH = 4000;

// Persistence
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const BROADCASTS_FILE = path.join(DATA_DIR, 'scheduled_broadcasts.json');
let scheduledBroadcasts = new Map();

// ======================== SUBSCRIPTION HELPERS ========================

function hasActiveSubscription(user) {
  return user.isSubscribed && user.subscriptionEndDate && new Date(user.subscriptionEndDate) > new Date();
}

function getUserLimits(user) {
  if (hasActiveSubscription(user)) {
    return {
      dailyBroadcasts: Infinity,
      maxLandingPages: Infinity,
      maxForms: Infinity
    };
  }
  return {
    dailyBroadcasts: DAILY_BROADCAST_LIMIT,
    maxLandingPages: MAX_LANDING_PAGES,
    maxForms: MAX_FORMS
  };
}

// ======================== UTILITIES ========================

function sanitizeTelegramHtml(unsafe) {
  if (!unsafe || typeof unsafe !== 'string') return '';

  const allowedTags = new Set([
    'b', 'strong', 'i', 'em', 'u', 'ins', 's', 'strike', 'del', 'span',
    'tg-spoiler', 'a', 'code', 'pre', 'tg-emoji'
  ]);

  const allowedAttrs = {
    a: ['href'],
    'tg-emoji': ['emoji-id']
  };

  let clean = unsafe
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '')
    .replace(/on\w+="[^"]*"/gi, '')
    .replace(/javascript:/gi, '');

  clean = clean.replace(/<\/?([a-z][a-z0-9]*)\b[^>]*>/gi, (match, tagName) => {
    const tag = tagName.toLowerCase();
    if (!allowedTags.has(tag)) return '';

    if (match.startsWith('</')) return '</' + tag + '>';

    let attrs = '';
    const attrRegex = /([a-z0-9-]+)="([^"]*)"/gi;
    let attrMatch;
    while ((attrMatch = attrRegex.exec(match)) !== null) {
      const attrName = attrMatch[1].toLowerCase();
      let attrValue = attrMatch[2];

      if (allowedAttrs[tag] && allowedAttrs[tag].includes(attrName)) {
        if (attrName === 'href') {
          if (!/^https?:\/\//i.test(attrValue) && !attrValue.startsWith('/')) {
            attrValue = '#';
          }
        }
        attrs += ' ' + attrName + '="' + attrValue.replace(/"/g, '&quot;') + '"';
      }
    }

    return '<' + tag + attrs + '>';
  });

  return clean.trim();
}

function splitTelegramMessage(text) {
  if (!text) return [];

  const chunks = [];
  let current = '';
  const lines = text.split(/\r?\n/);

  for (let line of lines) {
    while (line.length > MAX_MSG_LENGTH) {
      if (current) {
        chunks.push(current.trim());
        current = '';
      }
      chunks.push(line.substring(0, MAX_MSG_LENGTH).trim());
      line = line.substring(MAX_MSG_LENGTH);
    }

    if (current.length + line.length + (current ? 1 : 0) <= MAX_MSG_LENGTH) {
      current += (current ? '\n' : '') + line;
    } else {
      if (current) chunks.push(current.trim());
      current = line;
    }
  }

  if (current) chunks.push(current.trim());

  if (chunks.length <= 1) return chunks;

  const total = chunks.length;
  return chunks.map((chunk, i) => {
    const header = `(\( {i + 1}/ \){total})\n\n`;
    if (header.length + chunk.length > MAX_MSG_LENGTH) {
      return chunk;
    }
    return header + chunk;
  });
}

function escapeHtml(unsafe) {
  return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

function getTodayDateString() {
  return new Date().toISOString().slice(0, 10);
}

// ======================== PERSISTENCE ========================

function loadScheduledBroadcasts() {
  if (fs.existsSync(BROADCASTS_FILE)) {
    try {
      const data = JSON.parse(fs.readFileSync(BROADCASTS_FILE, 'utf8'));
      for (const entry of data) {
        scheduledBroadcasts.set(entry.broadcastId, entry);
      }
    } catch (err) {
      console.error('Failed to load broadcasts:', err.message);
    }
  }
}

function saveScheduledBroadcasts() {
  try {
    const pendingOnly = Array.from(scheduledBroadcasts.values()).filter(t => t.status === 'pending');
    fs.writeFileSync(BROADCASTS_FILE, JSON.stringify(pendingOnly, null, 2));
  } catch (err) {
    console.error('Failed to save broadcasts:', err.message);
  }
}

// ======================== SCHEDULED BROADCAST EXECUTION ========================

async function executeScheduledBroadcast(broadcastId) {
  const task = scheduledBroadcasts.get(broadcastId);
  if (!task || task.status !== 'pending') return;

  const result = await executeBroadcast(task.userId, task.message);

  let reportText = `<b>Scheduled Broadcast Report</b>\n\n`;

  if (result.error) {
    reportText += `<b>Failed to send</b>\n${escapeHtml(result.error)}`;
  } else {
    const statusEmoji = result.failed === 0 ? '✔' : '⚠️';
    reportText += statusEmoji + ' <b>' + result.sent + ' of ' + result.total + '</b> contacts received the message.\n';
    if (result.failed > 0) {
      reportText += '' + result.failed + ' failed to deliver.';
    }
  }

  reportText += `\n\nSent on: ${new Date().toLocaleString()}`;

  const user = users.find(u => u.id === task.userId);
  if (user && user.isTelegramConnected && user.telegramChatId && activeBots.has(user.id)) {
    try {
      await activeBots.get(user.id).telegram.sendMessage(user.telegramChatId, reportText, { parse_mode: 'HTML' });
    } catch (err) {
      console.error(`Failed to send report to user ${user.email}:`, err.message);
    }
  }

  scheduledBroadcasts.delete(broadcastId);
  saveScheduledBroadcasts();
}

// Periodic checker (every minute)
setInterval(() => {
  const now = Date.now();
  for (const [broadcastId, task] of scheduledBroadcasts.entries()) {
    if (task.status === 'pending' && task.scheduledTime <= now) {
      executeScheduledBroadcast(broadcastId);
    }
  }
}, 60000);

function scheduleBroadcast(userId, message, recipients = 'all', scheduledTime) {
  const broadcastId = uuidv4();
  const scheduledMs = new Date(scheduledTime).getTime();

  if (isNaN(scheduledMs) || scheduledMs <= Date.now()) {
    executeBroadcast(userId, message); // immediate if time is invalid or past
    return broadcastId;
  }

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
  saveScheduledBroadcasts();

  return broadcastId;
}

// ======================== BROADCAST SENDING (WITH BLOCK DETECTION & UNSUBSCRIBE) ========================

async function executeBroadcast(userId, message) {
  const bot = activeBots.get(userId);
  if (!bot || !bot.telegram) return { sent: 0, failed: 0, total: 0, error: 'Bot not connected' };

  const sanitizedMessage = sanitizeTelegramHtml(message);
  const numberedChunks = splitTelegramMessage(sanitizedMessage);

  const targets = (allSubmissions.get(userId) || []).filter(s => s.status === 'subscribed' && s.telegramChatId);
  if (targets.length === 0) return { sent: 0, failed: 0, total: 0 };

  const batches = [];
  for (let i = 0; i < targets.length; i += BATCH_SIZE) {
    batches.push(targets.slice(i, i + BATCH_SIZE));
  }

  let sent = 0, failed = 0;
  let contactsList = allSubmissions.get(userId) || [];

  for (let i = 0; i < batches.length; i++) {
    const batch = batches[i];
    for (const sub of batch) {
      try {
        for (const chunk of numberedChunks) {
          await bot.telegram.sendMessage(sub.telegramChatId, chunk, { parse_mode: 'HTML' });
        }
        sent++;
      } catch (err) {
        failed++;

        const errMsg = err.message?.toLowerCase() || '';
        const isBlocked =
          err.response?.error_code === 403 ||
          errMsg.includes('blocked') ||
          errMsg.includes('kicked') ||
          errMsg.includes('forbidden') ||
          errMsg.includes('chat not found') ||
          errMsg.includes('user is deactivated');

        if (isBlocked && sub.telegramChatId) {
          contactsList = contactsList.map(entry => {
            const matchesChatId = entry.telegramChatId === sub.telegramChatId;
            const matchesContact = entry.contact === sub.contact;

            if ((matchesChatId || matchesContact) &&
                (entry.status === 'subscribed' || entry.status === 'pending')) {
              return {
                ...entry,
                status: 'unsubscribed',
                unsubscribedAt: new Date().toISOString(),
                telegramChatId: matchesChatId ? null : entry.telegramChatId
              };
            }
            return entry;
          });
        }
      }
    }

    allSubmissions.set(userId, contactsList);

    if (i < batches.length - 1) await new Promise(r => setTimeout(r, BATCH_INTERVAL_MS));
  }

  return { sent, failed, total: targets.length };
}

// ======================== BOT LAUNCH ========================

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
        const byChat = list.findIndex(e => e.telegramChatId === chatId);
        const byContact = list.findIndex(e => e.contact === sub.contact);

        let updatedEntry = false;

        if (byChat !== -1) {
          list[byChat] = { ...list[byChat], name: sub.name, contact: sub.contact, shortId: sub.shortId, subscribedAt: new Date().toISOString(), status: 'subscribed' };
          updatedEntry = true;
        } else if (byContact !== -1) {
          list[byContact] = { ...list[byContact], name: sub.name, telegramChatId: chatId, shortId: sub.shortId, subscribedAt: new Date().toISOString(), status: 'subscribed' };
          updatedEntry = true;
        } else {
          list.push({ name: sub.name, contact: sub.contact, telegramChatId: chatId, shortId: sub.shortId, submittedAt: new Date().toISOString(), subscribedAt: new Date().toISOString(), status: 'subscribed' });
          updatedEntry = true;
        }

        if (updatedEntry) {
          list = list.filter(entry => !(entry.contact === sub.contact && entry.status === 'pending'));
          allSubmissions.set(user.id, list);
        }

        pendingSubscribers.delete(payload);

        // === CUSTOM WELCOME MESSAGE ===
        const form = formPages.get(sub.shortId);
        let welcomeText = '<b>Subscription Confirmed!</b>\n\nHi <b>' + escapeHtml(sub.name) + '</b>!\n\nYou\'re now subscribed.\n\nThank you';

        if (form && form.state && form.state.welcomeMessage && form.state.welcomeMessage.trim()) {
          welcomeText = form.state.welcomeMessage
            .replace(/\{name\}/gi, '<b>' + escapeHtml(sub.name) + '</b>')
            .replace(/\{contact\}/gi, escapeHtml(sub.contact));
        }

        await ctx.replyWithHTML(welcomeText);
        return;
      }
    }

    if (payload === user.id) {
      user.telegramChatId = chatId;
      user.isTelegramConnected = true;
      await ctx.replyWithHTML('<b>Sendm 2FA Connected Successfully!</b>\n\nYou will receive login codes here.');
      return;
    }

    await ctx.replyWithHTML('<b>Welcome!</b>\n\nSubscribe from the page to get updates.');
  });

  bot.command('status', ctx => ctx.replyWithHTML('<b>Sendm 2FA Status</b>\nAccount: <code>' + user.email + '</code>\nStatus: <b>' + (user.isTelegramConnected ? 'Connected' : 'Not Connected') + '</b>'));

  bot.catch(err => console.error('Bot error [' + user.email + ']:', err));
  bot.launch();
  activeBots.set(user.id, bot);
}

// ======================== JWT MIDDLEWARE ========================

const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization ? req.headers.authorization.split(' ')[1] : req.query.token;
  if (!token) return res.status(401).json({ error: 'Access token required' });
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
};

// ======================== AUTH ROUTES ========================

app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { fullName, email, password } = req.body;
  if (!fullName || !email || !password) return res.status(400).json({ error: 'All fields required' });
  if (users.find(u => u.email === email.toLowerCase())) return res.status(409).json({ error: 'Email already exists' });

  const hashed = await bcrypt.hash(password, 12);
  const newUser = {
    id: uuidv4(),
    fullName,
    email: email.toLowerCase(),
    password: hashed,
    createdAt: new Date().toISOString(),
    telegramBotToken: null,
    telegramChatId: null,
    isTelegramConnected: false,
    botUsername: null,
    isSubscribed: false,
    subscriptionEndDate: null,
    subscriptionPlan: null
  };
  users.push(newUser);
  const token = jwt.sign({ userId: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '7d' });

  res.status(201).json({ success: true, token, user: { id: newUser.id, fullName, email: newUser.email, isTelegramConnected: false } });
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email.toLowerCase());
  if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ success: true, token, user: { id: user.id, fullName: user.fullName, email: user.email, isTelegramConnected: user.isTelegramConnected } });
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
    if (activeBots.has(user.id)) { activeBots.get(user.id).stop(); activeBots.delete(user.id); }

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
    res.json({ success: true, message: 'Bot connected!', botUsername: '@' + botUsername, startLink });
  } catch {
    res.status(500).json({ error: 'Failed to connect' });
  }
});

app.post('/api/auth/change-bot-token', authenticateToken, async (req, res) => {
  const { newBotToken } = req.body;
  if (!newBotToken || !newBotToken.trim()) return res.status(400).json({ error: 'New bot token required' });

  const token = newBotToken.trim();
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  try {
    if (activeBots.has(user.id)) { activeBots.get(user.id).stop(); activeBots.delete(user.id); }

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
    res.json({ success: true, message: 'Bot token updated!', botUsername: '@' + botUsername, startLink });
  } catch {
    res.status(500).json({ error: 'Failed to validate token' });
  }
});

app.post('/api/auth/disconnect-telegram', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (activeBots.has(user.id)) { activeBots.get(user.id).stop(); activeBots.delete(user.id); }

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

function generate2FACode() { return Math.floor(100000 + Math.random() * 900000).toString(); }

async function send2FACodeViaBot(user, code) {
  if (!user.isTelegramConnected || !user.telegramChatId || !activeBots.has(user.id)) return false;
  try {
    await activeBots.get(user.id).telegram.sendMessage(user.telegramChatId,
      'Security Alert – Password Reset\n\nYour 6-digit code:\n\n<b>' + code + '</b>\n\nValid for 10 minutes.', { parse_mode: 'HTML' });
    return true;
  } catch {
    return false;
  }
}

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

  const user = users.find(u => u.email === email.toLowerCase());
  if (!user) return res.json({ success: true, message: 'If account exists, code was sent.' });
  if (!user.isTelegramConnected) return res.status(400).json({ error: 'Telegram 2FA not connected' });

  const code = generate2FACode();
  const resetToken = uuidv4();
  resetTokens.set(resetToken, { userId: user.id, code, expiresAt: Date.now() + 10 * 60 * 1000 });
  const sent = await send2FACodeViaBot(user, code);
  if (!sent) return res.status(500).json({ error: 'Failed to send code' });

  res.json({ success: true, message: 'Code sent!', resetToken });
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

// ======================== SUBSCRIPTION ROUTES ========================

app.get('/api/subscription/status', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const subscribed = hasActiveSubscription(user);
  res.json({
    subscribed,
    plan: subscribed ? 'premium-monthly' : 'free',
    endDate: user.subscriptionEndDate || null,
    daysLeft: subscribed ? Math.ceil((new Date(user.subscriptionEndDate) - new Date()) / (1000 * 60 * 60 * 24)) : 0
  });
});

app.post('/api/subscription/initiate', authenticateToken, async (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (hasActiveSubscription(user)) {
    return res.status(400).json({ error: 'You already have an active subscription' });
  }

  try {
    const response = await axios.post(
      'https://api.paystack.co/transaction/initialize',
      {
        email: user.email,
        amount: MONTHLY_PRICE,
        currency: 'NGN',
        callback_url: req.protocol + '://' + req.get('host') + '/subscription-success',
        metadata: {
          userId: user.id,
          plan: 'premium-monthly'
        }
      },
      {
        headers: {
          Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );

    const { authorization_url, reference } = response.data.data;

    user.pendingPaymentReference = reference;

    res.json({
      success: true,
      authorizationUrl: authorization_url,
      reference
    });
  } catch (error) {
    console.error('Paystack init error:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to initialize payment' });
  }
});

app.post('/api/subscription/webhook', (req, res) => {
  const hash = crypto
    .createHmac('sha512', PAYSTACK_SECRET_KEY)
    .update(JSON.stringify(req.body))
    .digest('hex');

  if (hash !== req.headers['x-paystack-signature']) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  const event = req.body;

  if (event.event === 'charge.success') {
    const { reference, metadata } = event.data;
    const { userId } = metadata;

    const user = users.find(u => u.id === userId);
    if (!user) {
      console.error('Webhook: User not found for ID:', userId);
      return res.status(200).send('OK');
    }

    if (user.pendingPaymentReference !== reference) {
      console.warn('Webhook: Reference mismatch');
      return res.status(200).send('OK');
    }

    const endDate = new Date();
    endDate.setDate(endDate.getDate() + 30);

    user.isSubscribed = true;
    user.subscriptionEndDate = endDate.toISOString();
    user.subscriptionPlan = 'premium-monthly';
    delete user.pendingPaymentReference;

    console.log(`Subscription activated for user: \( {user.email} until \){endDate}`);
  }

  res.status(200).send('OK');
});

app.get('/subscription-success', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html><head><title>Subscription Successful</title>
    <style>body{font-family:sans-serif;background:#121212;color:#0f0;text-align:center;padding:100px;}</style>
    </head>
    <body>
      <h1>✔ Subscription Successful!</h1>
      <p>You now have unlimited broadcasts, pages, and forms.</p>
      <p><a href="/" style="color:#ffd700;">← Back to Dashboard</a></p>
    </body></html>
  `);
});

// ======================== PAGES ROUTES ========================

app.get('/api/pages', authenticateToken, (req, res) => {
  const pages = Array.from(landingPages.entries())
    .filter(([_, p]) => p.userId === req.user.userId)
    .map(([shortId, p]) => ({ shortId, title: p.title, createdAt: p.createdAt, updatedAt: p.updatedAt, url: req.protocol + '://' + req.get('host') + '/p/' + shortId }));
  res.json({ pages });
});

app.post('/api/pages/save', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const user = users.find(u => u.id === userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const limits = getUserLimits(user);
  const currentCount = Array.from(landingPages.values()).filter(p => p.userId === userId).length;

  if (currentCount >= limits.maxLandingPages) {
    return res.status(403).json({ 
      error: `Limit reached: Maximum ${limits.maxLandingPages === Infinity ? 'unlimited (subscribed)' : limits.maxLandingPages} landing pages allowed.` 
    });
  }

  const { shortId, title, config } = req.body;
  if (!title || !config || !Array.isArray(config.blocks)) return res.status(400).json({ error: 'Title and config.blocks required' });

  const finalShortId = shortId || uuidv4().slice(0, 8);
  const now = new Date().toISOString();

  const cleanBlocks = config.blocks.map(b => {
    if (b.isEditor || (b.id && (b.id.includes('editor-') || b.id.includes('control-')))) return null;
    if (b.type === 'text') {
      const content = (b.content || '').trim();
      if (!content) return null;
      return { type: 'text', tag: b.tag || 'p', content };
    }
    if (b.type === 'image') {
      const src = b.src ? b.src.trim() : '';
      if (!src) return null;
      return { type: 'image', src };
    }
    if (b.type === 'button') {
      const text = (b.text || '').trim();
      if (!text) return null;
      return { type: 'button', text, href: b.href || '' };
    }
    if (b.type === 'form') {
      const html = b.html ? b.html.trim() : '';
      if (!html) return null;
      return { type: 'form', html: html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') };
    }
    return null;
  }).filter(Boolean);

  if (cleanBlocks.length === 0) return res.status(400).json({ error: 'No valid blocks' });

  landingPages.set(finalShortId, {
    userId: req.user.userId,
    title: title.trim(),
    config: { blocks: cleanBlocks },
    createdAt: landingPages.get(finalShortId)?.createdAt || now,
    updatedAt: now
  });

  res.json({ success: true, shortId: finalShortId, url: req.protocol + '://' + req.get('host') + '/p/' + finalShortId });
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

app.get('/api/page/:shortId', (req, res) => {
  const page = landingPages.get(req.params.shortId);
  if (!page) return res.status(404).json({ error: 'Page not found' });
  res.json({ shortId: req.params.shortId, title: page.title, config: page.config });
});

// ======================== FORMS ROUTES ========================

app.get('/api/forms', authenticateToken, (req, res) => {
  const forms = Array.from(formPages.entries())
    .filter(([_, f]) => f.userId === req.user.userId)
    .map(([shortId, f]) => ({ shortId, title: f.title, createdAt: f.createdAt, updatedAt: f.updatedAt, url: req.protocol + '://' + req.get('host') + '/f/' + shortId }));
  res.json({ forms });
});

app.post('/api/forms/save', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  const user = users.find(u => u.id === userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const limits = getUserLimits(user);
  const currentCount = Array.from(formPages.values()).filter(f => f.userId === userId).length;

  if (currentCount >= limits.maxForms) {
    return res.status(403).json({ 
      error: `Limit reached: Maximum ${limits.maxForms === Infinity ? 'unlimited (subscribed)' : limits.maxForms} forms allowed.` 
    });
  }

  const { shortId, title, state } = req.body;
  if (!title || !state) return res.status(400).json({ error: 'Title and state required' });

  const sanitizedState = JSON.parse(JSON.stringify(state));

  // Sanitize existing fields
  if (sanitizedState.headerText) sanitizedState.headerText = sanitizedState.headerText.replace(/<script.*?<\/script>/gi, '');
  if (sanitizedState.subheaderText) sanitizedState.subheaderText = sanitizedState.subheaderText.replace(/<script.*?<\/script>/gi, '');
  if (sanitizedState.buttonText) sanitizedState.buttonText = sanitizedState.buttonText.replace(/<script.*?<\/script>/gi, '');

  // NEW: Sanitize and store custom welcome message (supports HTML)
  if (sanitizedState.welcomeMessage) {
    sanitizedState.welcomeMessage = sanitizeTelegramHtml(sanitizedState.welcomeMessage.trim());
  }

  const finalShortId = shortId || uuidv4().slice(0, 8);
  const now = new Date().toISOString();

  formPages.set(finalShortId, {
    userId: req.user.userId,
    title: title.trim(),
    state: sanitizedState,
    createdAt: formPages.get(finalShortId)?.createdAt || now,
    updatedAt: now
  });

  res.json({ success: true, shortId: finalShortId, url: req.protocol + '://' + req.get('host') + '/f/' + finalShortId });
});

app.post('/api/forms/delete', authenticateToken, (req, res) => {
  const { shortId } = req.body;
  const form = formPages.get(shortId);
  if (!form || form.userId !== req.user.userId) return res.status(404).json({ error: 'Form not found' });
  formPages.delete(shortId);
  res.json({ success: true });
});

app.get('/f/:shortId', (req, res) => {
  const form = formPages.get(req.params.shortId);
  if (!form) return res.status(404).render('404');
  res.render('form', { title: form.title, state: form.state });
});

app.get('/api/form/:shortId', (req, res) => {
  const form = formPages.get(req.params.shortId);
  if (!form) return res.status(404).json({ error: 'Form not found' });
  res.json({ shortId: req.params.shortId, title: form.title, state: form.state });
});

// ======================== SUBSCRIPTION & CONTACTS ========================

app.post('/api/subscribe/:shortId', async (req, res) => {
  const { shortId } = req.params;
  const { name, email } = req.body;
  if (!name || !name.trim() || !email || !email.trim()) return res.status(400).json({ error: 'Valid name and contact required' });

  const page = formPages.get(shortId);
  if (!page) return res.status(404).json({ error: 'Page not found' });

  const owner = users.find(u => u.id === page.userId);
  if (!owner || !owner.telegramBotToken || !owner.botUsername) return res.status(400).json({ error: 'Bot not connected' });

  const contactValue = email.trim();
  const payload = 'sub_' + shortId + '_' + uuidv4().slice(0, 12);

  let list = allSubmissions.get(owner.id) || [];
  const existingIndex = list.findIndex(c => c.contact === contactValue);

  const base = { name: name.trim(), contact: contactValue, shortId, submittedAt: new Date().toISOString() };

  if (existingIndex !== -1) {
    list[existingIndex] = { ...list[existingIndex], ...base };
  } else {
    list.push({ ...base, telegramChatId: null, subscribedAt: null, status: 'pending' });
  }

  allSubmissions.set(owner.id, list);

  pendingSubscribers.set(payload, {
    userId: owner.id,
    shortId,
    name: name.trim(),
    contact: contactValue,
    createdAt: Date.now()
  });

  const deepLink = 'https://t.me/' + owner.botUsername + '?start=' + payload;
  res.json({ success: true, deepLink });
});

app.get('/api/contacts', authenticateToken, (req, res) => {
  const contacts = (allSubmissions.get(req.user.userId) || []).map(c => ({
    name: c.name,
    contact: c.contact,
    status: c.status,
    telegramChatId: c.telegramChatId || null,
    pageId: c.shortId,
    submittedAt: new Date(c.submittedAt).toLocaleString(),
    subscribedAt: c.subscribedAt ? new Date(c.subscribedAt).toLocaleString() : null
  }));
  res.json({ success: true, contacts });
});

app.post('/api/contacts/delete', authenticateToken, (req, res) => {
  const { contacts } = req.body;
  if (!Array.isArray(contacts) || !contacts.length) return res.status(400).json({ error: 'Provide contact array' });

  const userId = req.user.userId;
  let list = allSubmissions.get(userId) || [];
  const initial = list.length;
  list = list.filter(c => !contacts.includes(c.contact));
  allSubmissions.set(userId, list);

  res.json({ success: true, deletedCount: initial - list.length, remaining: list.length });
});

// ======================== BROADCAST ROUTES ========================

function incrementDailyBroadcast(userId) {
  const today = getTodayDateString();
  const key = `\( {userId}_ \){today}`;
  const current = userBroadcastDaily.get(key) || 0;
  userBroadcastDaily.set(key, current + 1);
  return current + 1;
}

setInterval(() => {
  const today = getTodayDateString();
  for (const key of userBroadcastDaily.keys()) {
    if (!key.endsWith(today)) {
      userBroadcastDaily.delete(key);
    }
  }
}, 60 * 60 * 1000);

app.post('/api/broadcast/now', authenticateToken, async (req, res) => {
  const { message, recipients = 'all' } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message required' });

  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const limits = getUserLimits(user);
  const todayCount = incrementDailyBroadcast(req.user.userId);

  if (todayCount > limits.dailyBroadcasts) {
    return res.status(403).json({ 
      error: `Daily limit reached: ${limits.dailyBroadcasts === Infinity ? 'Unlimited (subscribed)' : limits.dailyBroadcasts} broadcasts per day.` 
    });
  }

  const sanitizedMessage = sanitizeTelegramHtml(message.trim());
  const result = await executeBroadcast(req.user.userId, sanitizedMessage);

  res.json({ success: true, ...result });
});

app.post('/api/broadcast/schedule', authenticateToken, async (req, res) => {
  const { message, scheduledTime, recipients = 'all' } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message required' });

  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const limits = getUserLimits(user);
  const todayCount = incrementDailyBroadcast(req.user.userId);

  if (todayCount > limits.dailyBroadcasts) {
    return res.status(403).json({ 
      error: `Daily limit reached: ${limits.dailyBroadcasts === Infinity ? 'Unlimited (subscribed)' : limits.dailyBroadcasts} broadcasts per day.` 
    });
  }

  const sanitizedMessage = sanitizeTelegramHtml(message.trim());

  if (scheduledTime === 'now') {
    const result = await executeBroadcast(user.id, sanitizedMessage);
    return res.json({ success: true, ...result, immediate: true });
  }

  const time = new Date(scheduledTime);
  if (isNaN(time.getTime()) || time <= new Date()) {
    return res.status(400).json({ error: 'Invalid future time' });
  }

  const broadcastId = scheduleBroadcast(user.id, sanitizedMessage, recipients, scheduledTime);

  res.json({
    success: true,
    broadcastId,
    scheduledTime: time.toISOString()
  });
});

app.get('/api/broadcast/scheduled', authenticateToken, (req, res) => {
  const scheduled = Array.from(scheduledBroadcasts.values())
    .filter(t => t.userId === req.user.userId && t.status === 'pending')
    .map(t => ({
      broadcastId: t.broadcastId,
      message: t.message.substring(0, 100) + (t.message.length > 100 ? '...' : ''),
      scheduledTime: new Date(t.scheduledTime).toISOString(),
      status: t.status,
      recipients: t.recipients,
      isEditable: true
    }))
    .sort((a, b) => new Date(b.scheduledTime) - new Date(a.scheduledTime));

  res.json({ success: true, scheduled });
});

app.delete('/api/broadcast/scheduled/:broadcastId', authenticateToken, (req, res) => {
  const { broadcastId } = req.params;
  const task = scheduledBroadcasts.get(broadcastId);
  if (!task || task.userId !== req.user.userId) return res.status(404).json({ error: 'Not found' });

  scheduledBroadcasts.delete(broadcastId);
  saveScheduledBroadcasts();
  res.json({ success: true });
});

app.patch('/api/broadcast/scheduled/:broadcastId', authenticateToken, (req, res) => {
  const { broadcastId } = req.params;
  const { message, scheduledTime, recipients } = req.body;
  const task = scheduledBroadcasts.get(broadcastId);
  if (!task || task.userId !== req.user.userId || task.status !== 'pending') return res.status(400).json({ error: 'Cannot edit' });

  if (message && message.trim()) {
    task.message = sanitizeTelegramHtml(message.trim());
  }
  if (recipients) task.recipients = recipients;

  if (scheduledTime) {
    const newTime = new Date(scheduledTime);
    if (isNaN(newTime.getTime()) || newTime <= new Date()) return res.status(400).json({ error: 'Invalid future time' });
    task.scheduledTime = newTime.getTime();
  }

  scheduledBroadcasts.set(broadcastId, task);
  saveScheduledBroadcasts();
  res.json({ success: true, broadcastId, scheduledTime: new Date(task.scheduledTime).toISOString() });
});

app.get('/api/broadcast/scheduled/:broadcastId/details', authenticateToken, (req, res) => {
  const { broadcastId } = req.params;
  const task = scheduledBroadcasts.get(broadcastId);

  if (!task || task.userId !== req.user.userId) {
    return res.status(404).json({ error: 'Broadcast not found or access denied' });
  }

  if (task.status !== 'pending') {
    return res.status(400).json({ error: 'Can only edit pending broadcasts' });
  }

  const scheduledDate = new Date(task.scheduledTime);
  const offsetMs = scheduledDate.getTimezoneOffset() * 60 * 1000;
  const localDate = new Date(scheduledDate.getTime() - offsetMs);
  const localIsoString = localDate.toISOString().slice(0, 16);

  res.json({
    success: true,
    message: task.message,
    scheduledTime: localIsoString,
    recipients: task.recipients || 'all'
  });
});

// ======================== ADMIN LIMITS PAGE ========================

app.get('/admin-limits', (req, res) => {
  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Server Limits Control</title>
  <style>
    body { font-family: 'Segoe UI', sans-serif; background: #121212; color: #e0e0e0; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
    .container { background: #1e1e1e; padding: 40px; border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.6); width: 90%; max-width: 500px; }
    h1 { text-align: center; color: #ffd700; margin-bottom: 30px; }
    label { display: block; margin: 20px 0 8px; font-size: 1.1em; }
    input[type="number"], input[type="password"] { width: 100%; padding: 12px; background: #2d2d2d; border: none; border-radius: 6px; color: white; font-size: 1em; margin-bottom: 15px; }
    button { width: 100%; padding: 14px; background: #ffd700; color: black; font-weight: bold; border: none; border-radius: 6px; cursor: pointer; font-size: 1.1em; }
    button:hover { background: #e6c200; }
    .current { text-align: center; margin: 25px 0; padding: 15px; background: #2d2d2d; border-radius: 8px; font-size: 1.1em; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Server Limits Control</h1>
    <form method="POST">
      <label>Owner Password</label>
      <input type="password" name="password" required placeholder="Enter password">

      <label>Daily Broadcasts per User</label>
      <input type="number" name="daily_broadcast" min="1" value="${DAILY_BROADCAST_LIMIT}" required>

      <label>Max Landing Pages per User</label>
      <input type="number" name="max_pages" min="1" value="${MAX_LANDING_PAGES}" required>

      <label>Max Forms per User</label>
      <input type="number" name="max_forms" min="1" value="${MAX_FORMS}" required>

      <div class="current">
        <strong>Current Limits:</strong><br>
        Broadcasts/day: \( {DAILY_BROADCAST_LIMIT} | Pages: \){MAX_LANDING_PAGES} | Forms: ${MAX_FORMS}
      </div>

      <button type="submit">Update Limits</button>
    </form>
  </div>
</body>
</html>
  `;
  res.send(html);
});

app.post('/admin-limits', (req, res) => {
  const { password, daily_broadcast, max_pages, max_forms } = req.body;

  if (password !== ADMIN_PASSWORD) {
    return res.send(`
      <!DOCTYPE html>
      <html>
        <head><style>body{background:#121212;color:#f44336;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:sans-serif;text-align:center;}</style></head>
        <body><h1>Access Denied<br>Wrong Password</h1></body>
      </html>
    `);
  }

  const newDaily = parseInt(daily_broadcast);
  const newPages = parseInt(max_pages);
  const newForms = parseInt(max_forms);

  if (isNaN(newDaily) || isNaN(newPages) || isNaN(newForms) || newDaily < 1 || newPages < 1 || newForms < 1) {
    return res.send(`
      <!DOCTYPE html>
      <html>
        <head><style>body{background:#121212;color:#f44336;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:sans-serif;text-align:center;}</style></head>
        <body><h1>Invalid Values<br>All limits must be ≥ 1</h1></body>
      </html>
    `);
  }

  DAILY_BROADCAST_LIMIT = newDaily;
  MAX_LANDING_PAGES = newPages;
  MAX_FORMS = newForms;

  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Limits Updated</title>
  <style>
    body { font-family: 'Segoe UI', sans-serif; background: #121212; color: #e0e0e0; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
    .container { background: #1e1e1e; padding: 40px; border-radius: 12px; text-align: center; }
    h1 { color: #4caf50; }
    .success { font-size: 1.2em; margin: 20px 0; }
    a { color: #ffd700; text-decoration: none; font-weight: bold; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Success!</h1>
    <p class="success">Server limits updated successfully:</p>
    <p><strong>Daily Broadcasts:</strong> ${DAILY_BROADCAST_LIMIT}<br>
       <strong>Max Pages:</strong> ${MAX_LANDING_PAGES}<br>
       <strong>Max Forms:</strong> ${MAX_FORMS}</p>
    <p><a href="/admin-limits">← Back to Control Panel</a></p>
  </div>
</body>
</html>
  `);
});

// ======================== CLEANUP & SERVER START ========================

setInterval(() => {
  const now = Date.now();
  for (const [p, d] of pendingSubscribers.entries()) {
    if (now - d.createdAt > 30 * 60 * 1000) pendingSubscribers.delete(p);
  }
}, 60 * 60 * 1000);

loadScheduledBroadcasts();
users.forEach(user => { if (user.telegramBotToken) launchUserBot(user); });

process.on('SIGTERM', () => {
  console.log('SIGTERM received - shutting down gracefully');
  process.exit(0);
});

app.use((req, res) => res.status(404).render('404'));

app.listen(PORT, () => {
  console.log('\nSENDEM SERVER — SECURE WITH ENV VARIABLES');
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Admin panel: http://localhost:${PORT}/admin-limits`);
  console.log('All secrets are now loaded from .env file\n');
});
