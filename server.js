require('dotenv').config();

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const { Telegraf } = require('telegraf');
const path = require('path');
const mongoose = require('mongoose');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== CONFIG & SECRETS ====================
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_weak_secret_change_me_immediately';
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || 'sk_test_fallback_change_me';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'midas';
const DOMAIN = process.env.DOMAIN;
let WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

if (!DOMAIN) {
  console.error('ERROR: DOMAIN environment variable is required for webhooks!');
  process.exit(1);
}

if (!WEBHOOK_SECRET || WEBHOOK_SECRET.trim() === '') {
  WEBHOOK_SECRET = crypto.randomBytes(32).toString('hex');
  console.warn('⚠️  WARNING: WEBHOOK_SECRET not set in .env! Generated temporary one:');
  console.warn('     ' + WEBHOOK_SECRET);
  console.warn('     Add it to your .env file to keep it permanent across restarts:');
  console.warn('     WEBHOOK_SECRET=' + WEBHOOK_SECRET + '\n');
} else {
  console.log('Webhook secret loaded from .env');
}

if (JWT_SECRET.includes('fallback')) {
  console.warn('⚠️  WARNING: JWT_SECRET not set in .env! Using insecure fallback.');
}
if (PAYSTACK_SECRET_KEY.startsWith('sk_test_fallback')) {
  console.warn('⚠️  WARNING: PAYSTACK_SECRET_KEY not set in .env!');
}

const MONTHLY_PRICE_KOBO = 500000; // ₦5,000 in kobo

// Dynamic server-wide limits
let DAILY_BROADCAST_LIMIT = 3;
let MAX_LANDING_PAGES = 5;
let MAX_FORMS = 5;

// Batching config
const BATCH_SIZE = 25;
const BATCH_INTERVAL_MS = 15000;
const MAX_MSG_LENGTH = 4000;

// ==================== MONGODB CONNECTION ====================
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/sendm';
console.log('Connecting to MongoDB:', MONGODB_URI.replace(/:([^:@]+)@/, ':****@'));

mongoose.connect(MONGODB_URI, {
  serverSelectionTimeoutMS: 30000,
  socketTimeoutMS: 45000,
  connectTimeoutMS: 30000,
}).then(() => {
  console.log('✅ MongoDB connected');
}).catch(err => {
  console.error('MongoDB connection failed:', err.message);
  process.exit(1);
});

// ==================== SCHEMAS & MODELS ====================
const userSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  fullName: String,
  email: { type: String, required: true, unique: true, lowercase: true },
  password: String,
  telegramBotToken: String,
  telegramChatId: String,
  isTelegramConnected: { type: Boolean, default: false },
  botUsername: String,
  isSubscribed: { type: Boolean, default: false },
  subscriptionEndDate: Date,
  subscriptionPlan: String,
  pendingPaymentReference: String,
  createdAt: { type: Date, default: Date.now },
}, { timestamps: true });

const landingPageSchema = new mongoose.Schema({
  shortId: { type: String, required: true, unique: true },
  userId: { type: String, required: true },
  title: String,
  config: Object,
  createdAt: Date,
  updatedAt: Date,
}, { timestamps: true });

const formPageSchema = new mongoose.Schema({
  shortId: { type: String, required: true, unique: true },
  userId: { type: String, required: true },
  title: String,
  state: Object,
  welcomeMessage: String,
  createdAt: Date,
  updatedAt: Date,
}, { timestamps: true });

const contactSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  shortId: String,
  name: String,
  contact: { type: String, required: true, lowercase: true },
  telegramChatId: String,
  status: { type: String, default: 'pending' }, // pending, subscribed, unsubscribed
  submittedAt: Date,
  subscribedAt: Date,
  unsubscribedAt: Date,
}, { timestamps: true });

const scheduledBroadcastSchema = new mongoose.Schema({
  broadcastId: { type: String, required: true, unique: true },
  userId: { type: String, required: true },
  message: String,
  recipients: { type: String, default: 'all' },
  scheduledTime: Date,
  status: { type: String, default: 'pending' },
  createdAt: Date,
}, { timestamps: true });

const broadcastDailySchema = new mongoose.Schema({
  userId: { type: String, required: true },
  date: { type: String, required: true },
  count: { type: Number, default: 1 },
}, { timestamps: true });

// Models
const User = mongoose.model('User', userSchema);
const LandingPage = mongoose.model('LandingPage', landingPageSchema);
const FormPage = mongoose.model('FormPage', formPageSchema);
const Contact = mongoose.model('Contact', contactSchema);
const ScheduledBroadcast = mongoose.model('ScheduledBroadcast', scheduledBroadcastSchema);
const BroadcastDaily = mongoose.model('BroadcastDaily', broadcastDailySchema);

// Indexes
landingPageSchema.index({ userId: 1 });
formPageSchema.index({ userId: 1 });
contactSchema.index({ userId: 1 });
contactSchema.index({ userId: 1, contact: 1 }, { unique: true }); // No duplicates per user
contactSchema.index({ userId: 1, status: 1 });
scheduledBroadcastSchema.index({ userId: 1 });
scheduledBroadcastSchema.index({ status: 1 });
scheduledBroadcastSchema.index({ scheduledTime: 1 });
broadcastDailySchema.index({ userId: 1, date: 1 }, { unique: true });

// In-memory helpers
const activeBots = new Map();
const resetTokens = new Map();
const pendingSubscribers = new Map();

// ==================== MIDDLEWARE ====================
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many attempts' }
});

const formSubmitLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many submissions to this form. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip + '::' + req.params.shortId,
  skip: (req) => !req.params.shortId
});

// ==================== WEBHOOK ENDPOINT ====================
app.post('/webhook/' + WEBHOOK_SECRET + '/:userId', async (req, res) => {
  const userId = req.params.userId;
  const bot = activeBots.get(userId);

  let update;
  try {
    if (Buffer.isBuffer(req.body)) {
      update = JSON.parse(req.body.toString('utf8'));
    } else if (req.body && typeof req.body === 'object') {
      update = req.body;
    } else {
      throw new Error('Invalid body format');
    }
  } catch (err) {
    console.error('Failed to parse webhook body for user ' + userId + ':', err);
    return res.sendStatus(400);
  }

  if (bot) {
    try {
      await bot.handleUpdate(update);
    } catch (err) {
      console.error('Webhook handle error for user ' + userId + ':', err);
    }
  }

  res.sendStatus(200);
});

// ==================== UTILITIES ====================
function sanitizeTelegramHtml(unsafe) {
  if (!unsafe || typeof unsafe !== 'string') return '';
  const allowedTags = new Set(['b','strong','i','em','u','ins','s','strike','del','span','tg-spoiler','a','code','pre','tg-emoji']);
  const allowedAttrs = { a: ['href'], 'tg-emoji': ['emoji-id'] };

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
        if (attrName === 'href' && !/^https?:\/\//i.test(attrValue) && !attrValue.startsWith('/')) {
          attrValue = '#';
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

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
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
    const header = '(' + (i + 1) + '/' + total + ')\n\n';
    return header.length + chunk.length > MAX_MSG_LENGTH ? chunk : header + chunk;
  });
}

function escapeHtml(unsafe) {
  if (!unsafe) unsafe = '';
  return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

function getTodayDateString() {
  return new Date().toISOString().slice(0, 10);
}

function hasActiveSubscription(user) {
  return user.isSubscribed && user.subscriptionEndDate && new Date(user.subscriptionEndDate) > new Date();
}

function getUserLimits(user) {
  if (hasActiveSubscription(user)) {
    return { dailyBroadcasts: Infinity, maxLandingPages: Infinity, maxForms: Infinity };
  }
  return { dailyBroadcasts: DAILY_BROADCAST_LIMIT, maxLandingPages: MAX_LANDING_PAGES, maxForms: MAX_FORMS };
}

async function incrementDailyBroadcast(userId) {
  const today = getTodayDateString();
  const record = await BroadcastDaily.findOneAndUpdate(
    { userId, date: today },
    { $inc: { count: 1 } },
    { upsert: true, new: true }
  );
  return record.count;
}

// ==================== JWT AUTH ====================
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : req.query.token;

  if (!token) return res.status(401).json({ error: 'Access token required' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ id: decoded.userId });
    if (!user) return res.status(404).json({ error: 'User not found' });
    req.user = user;
    next();
  } catch (err) {
    res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// ==================== TELEGRAM BOT - PURE WEBHOOK MODE ====================
function launchUserBot(user) {
  if (activeBots.has(user.id)) {
    activeBots.get(user.id).stop('Replaced');
    activeBots.delete(user.id);
  }

  if (!user.telegramBotToken) return;

  const bot = new Telegraf(user.telegramBotToken);

  bot.start(async (ctx) => {
    const payload = ctx.startPayload || '';
    const chatId = ctx.chat.id.toString();

    if (payload.startsWith('sub_') && pendingSubscribers.has(payload)) {
      const sub = pendingSubscribers.get(payload);
      if (sub.userId === user.id) {
        const contacts = await Contact.find({ userId: user.id });

        let targetContact = contacts.find(c => c.telegramChatId === chatId);
        if (!targetContact) {
          targetContact = contacts.find(c => c.contact === sub.contact.toLowerCase());
        }

        let updated = false;

        if (targetContact) {
          targetContact.name = sub.name.trim();
          targetContact.contact = sub.contact.toLowerCase();
          targetContact.shortId = sub.shortId;
          targetContact.telegramChatId = chatId;
          targetContact.status = 'subscribed';
          targetContact.subscribedAt = targetContact.subscribedAt || new Date();
          targetContact.unsubscribedAt = null;
          await targetContact.save();
          updated = true;
        } else {
          const newContact = new Contact({
            userId: user.id,
            shortId: sub.shortId,
            name: sub.name.trim(),
            contact: sub.contact.toLowerCase(),
            telegramChatId: chatId,
            status: 'subscribed',
            submittedAt: new Date(),
            subscribedAt: new Date()
          });
          await newContact.save();
          updated = true;
        }

        if (updated) {
          await Contact.deleteMany({
            userId: user.id,
            contact: sub.contact.toLowerCase(),
            status: 'pending'
          });
        }

        pendingSubscribers.delete(payload);

        const form = await FormPage.findOne({ shortId: sub.shortId });
        let welcomeText = '<b>Subscription Confirmed!</b>\n\nHi <b>' + escapeHtml(sub.name) + '</b>!\n\nYou\'re now subscribed.\n\nThank you';

        if (form && form.welcomeMessage && form.welcomeMessage.trim()) {
          welcomeText = form.welcomeMessage
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
      await user.save();
      await ctx.replyWithHTML('<b>Sendm 2FA Connected Successfully!</b>\n\nYou will receive login codes here.');
      return;
    }

    await ctx.replyWithHTML('<b>Welcome!</b>\n\nSubscribe from the page to get updates.');
  });

  bot.command('status', async (ctx) => {
    await ctx.replyWithHTML('<b>Sendm 2FA Status</b>\nAccount: <code>' + user.email + '</code>\nStatus: <b>' + (user.isTelegramConnected ? 'Connected' : 'Not Connected') + '</b>');
  });

  bot.catch((err) => {
    console.error('Bot error for ' + user.email + ':', err);
  });

  const webhookUrl = 'https://' + DOMAIN + '/webhook/' + WEBHOOK_SECRET + '/' + user.id;

  (async () => {
    try {
      await bot.telegram.deleteWebhook({ drop_pending_updates: true });
      const success = await bot.telegram.setWebhook(webhookUrl);
      if (success) {
        console.log(`Webhook set successfully for @\( {user.botUsername} → \){webhookUrl}`);
      } else {
        console.error(`Failed to set webhook for @${user.botUsername}`);
      }
    } catch (err) {
      console.error(`Webhook setup error for ${user.email}:`, err.message);
    }
  })();

  activeBots.set(user.id, bot);
}

// ==================== AUTH ROUTES ====================
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { fullName, email, password } = req.body;
  if (!fullName || !email || !password) return res.status(400).json({ error: 'All fields required' });

  const existing = await User.findOne({ email: email.toLowerCase() });
  if (existing) return res.status(409).json({ error: 'Email already exists' });

  const hashed = await bcrypt.hash(password, 12);
  const newUser = await User.create({
    id: uuidv4(),
    fullName: fullName.trim(),
    email: email.toLowerCase(),
    password: hashed,
  });

  const token = jwt.sign({ userId: newUser.id }, JWT_SECRET, { expiresIn: '7d' });
  res.status(201).json({
    success: true,
    token,
    user: { id: newUser.id, fullName: newUser.fullName, email: newUser.email, isTelegramConnected: false }
  });
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({
    success: true,
    token,
    user: { id: user.id, fullName: user.fullName, email: user.email, isTelegramConnected: user.isTelegramConnected }
  });
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.json({
    user: {
      id: req.user.id,
      fullName: req.user.fullName,
      email: req.user.email,
      isTelegramConnected: req.user.isTelegramConnected
    }
  });
});

app.post('/api/auth/connect-telegram', authenticateToken, async (req, res) => {
  const { botToken } = req.body;
  if (!botToken || !botToken.trim()) return res.status(400).json({ error: 'Bot token required' });

  const token = botToken.trim();

  try {
    const response = await axios.get('https://api.telegram.org/bot' + token + '/getMe');
    if (!response.data.ok) return res.status(400).json({ error: 'Invalid bot token' });

    const botUsername = response.data.result.username.replace(/^@/, '');

    req.user.telegramBotToken = token;
    req.user.botUsername = botUsername;
    req.user.isTelegramConnected = false;
    req.user.telegramChatId = null;
    await req.user.save();

    launchUserBot(req.user);

    const startLink = 'https://t.me/' + botUsername + '?start=' + req.user.id;
    res.json({
      success: true,
      message: 'Bot connected!',
      botUsername: '@' + botUsername,
      startLink
    });
  } catch (err) {
    console.error('Telegram connect error:', err.message);
    res.status(500).json({ error: 'Failed to validate bot token' });
  }
});

app.post('/api/auth/change-bot-token', authenticateToken, async (req, res) => {
  const { newBotToken } = req.body;
  if (!newBotToken || !newBotToken.trim()) return res.status(400).json({ error: 'New bot token required' });

  const token = newBotToken.trim();

  try {
    const response = await axios.get('https://api.telegram.org/bot' + token + '/getMe');
    if (!response.data.ok) return res.status(400).json({ error: 'Invalid bot token' });

    const botUsername = response.data.result.username.replace(/^@/, '');

    req.user.telegramBotToken = token;
    req.user.botUsername = botUsername;
    req.user.isTelegramConnected = false;
    req.user.telegramChatId = null;
    await req.user.save();

    launchUserBot(req.user);

    const startLink = 'https://t.me/' + botUsername + '?start=' + req.user.id;
    res.json({
      success: true,
      message: 'Bot token updated!',
      botUsername: '@' + botUsername,
      startLink
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to validate new token' });
  }
});

app.post('/api/auth/disconnect-telegram', authenticateToken, async (req, res) => {
  if (activeBots.has(req.user.id)) {
    activeBots.get(req.user.id).stop('Disconnected');
    activeBots.delete(req.user.id);
  }

  req.user.telegramBotToken = null;
  req.user.botUsername = null;
  req.user.telegramChatId = null;
  req.user.isTelegramConnected = false;
  await req.user.save();

  res.json({ success: true, message: 'Telegram disconnected' });
});

app.get('/api/auth/bot-status', authenticateToken, (req, res) => {
  res.json({
    activated: req.user.isTelegramConnected,
    chatId: req.user.telegramChatId || null
  });
});

function generate2FACode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function send2FACodeViaBot(user, code) {
  if (!user.isTelegramConnected || !user.telegramChatId || !activeBots.has(user.id)) return false;
  try {
    await activeBots.get(user.id).telegram.sendMessage(
      user.telegramChatId,
      'Security Alert – Password Reset\n\nYour 6-digit code:\n\n<b>' + code + '</b>\n\nValid for 10 minutes.',
      { parse_mode: 'HTML' }
    );
    return true;
  } catch (err) {
    console.error('Failed to send 2FA code:', err.message);
    return false;
  }
}

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

  const user = await User.findOne({ email: email.toLowerCase() });
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

  const user = await User.findOne({ id: entry.userId });
  if (!user) return res.status(404).json({ error: 'User not found' });

  user.password = await bcrypt.hash(newPassword, 12);
  await user.save();
  resetTokens.delete(resetToken);

  res.json({ success: true, message: 'Password reset successful' });
});

// ==================== SUBSCRIPTION ROUTES ====================
app.get('/api/subscription/status', authenticateToken, async (req, res) => {
  const subscribed = hasActiveSubscription(req.user);
  res.json({
    subscribed,
    plan: subscribed ? 'premium-monthly' : 'free',
    endDate: req.user.subscriptionEndDate || null,
    daysLeft: subscribed
      ? Math.ceil((new Date(req.user.subscriptionEndDate) - new Date()) / (1000 * 60 * 60 * 24))
      : 0
  });
});

app.post('/api/subscription/initiate', authenticateToken, async (req, res) => {
  if (hasActiveSubscription(req.user)) {
    return res.status(400).json({ error: 'You already have an active subscription' });
  }

  try {
    const response = await axios.post(
      'https://api.paystack.co/transaction/initialize',
      {
        email: req.user.email,
        amount: MONTHLY_PRICE_KOBO,
        currency: 'NGN',
        callback_url: req.protocol + '://' + req.get('host') + '/subscription-success',
        metadata: { userId: req.user.id, plan: 'premium-monthly' }
      },
      {
        headers: {
          Authorization: 'Bearer ' + PAYSTACK_SECRET_KEY,
          'Content-Type': 'application/json'
        }
      }
    );

    const authorization_url = response.data.data.authorization_url;
    const reference = response.data.data.reference;

    req.user.pendingPaymentReference = reference;
    await req.user.save();

    res.json({ success: true, authorizationUrl: authorization_url, reference });
  } catch (error) {
    console.error('Paystack init error:', error.response ? error.response.data : error.message);
    res.status(500).json({ error: 'Failed to initialize payment' });
  }
});

app.post('/api/subscription/webhook', async (req, res) => {
  try {
    const hash = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY)
      .update(JSON.stringify(req.body))
      .digest('hex');

    if (hash !== req.headers['x-paystack-signature']) {
      return res.status(401).send('Invalid signature');
    }

    const event = req.body;

    if (event.event === 'charge.success') {
      const reference = event.data.reference;
      const userId = event.data.metadata?.userId;

      if (!userId) return res.status(200).send('OK');

      const user = await User.findOne({ id: userId });
      if (!user || user.pendingPaymentReference !== reference) {
        return res.status(200).send('OK');
      }

      const endDate = new Date();
      endDate.setDate(endDate.getDate() + 30);

      user.isSubscribed = true;
      user.subscriptionEndDate = endDate;
      user.subscriptionPlan = 'premium-monthly';
      user.pendingPaymentReference = undefined;
      await user.save();

      console.log('Subscription activated for ' + user.email + ' (ref: ' + reference + ')');
    }

    res.status(200).send('OK');
  } catch (err) {
    console.error('Webhook error:', err);
    res.status(200).send('OK');
  }
});

app.get('/subscription-success', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Payment Successful</title><style>
  body{font-family:system-ui,sans-serif;background:#0a0a0a;color:#00ff41;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;}
  .box{background:#111;padding:60px;border-radius:20px;text-align:center;box-shadow:0 0 30px rgba(0,255,65,0.2);}
  h1{margin:0 0 20px;font-size:3em;color:#00ff41;}
  p{font-size:1.3em;margin:20px 0;line-height:1.6;}
  a{display:inline-block;margin-top:30px;padding:14px 32px;background:#00ff41;color:#000;font-weight:bold;text-decoration:none;border-radius:8px;font-size:1.1em;}
  a:hover{background:#00cc33;}
</style></head>
<body>
  <div class="box">
    <h1>✓ Payment Successful!</h1>
    <p>Your subscription is now <strong>active</strong>.</p>
    <p>You have unlimited broadcasts, landing pages, and forms.</p>
    <p><a href="/">← Return to Dashboard</a></p>
  </div>
</body>
</html>`);
});

// ==================== LANDING PAGES, FORMS, etc. (unchanged) ====================
// ... (all other routes remain exactly as in previous versions)

// ==================== FINAL SUBSCRIBE LOGIC - MULTI-FORM SUPPORT ====================
app.post('/api/subscribe/:shortId', formSubmitLimiter, async (req, res) => {
  const shortId = req.params.shortId;
  const { name, email } = req.body;

  if (!name?.trim() || !email?.trim()) {
    return res.status(400).json({ error: 'Name and contact required' });
  }

  const form = await FormPage.findOne({ shortId });
  if (!form) return res.status(404).json({ error: 'Form not found' });

  const owner = await User.findOne({ id: form.userId });
  if (!owner?.telegramBotToken) return res.status(400).json({ error: 'Bot not connected' });

  const contactValue = email.trim().toLowerCase();

  let contact = await Contact.findOne({ userId: owner.id, contact: contactValue });

  if (contact) {
    // Existing contact (new, pending, or already subscribed)
    // Just update name and link to this new form — preserve everything else
    contact.name = name.trim();
    contact.shortId = shortId;
    contact.submittedAt = new Date();
    await contact.save();

    return res.json({
      success: true,
      message: 'Thank you! Your details have been updated for this form.'
    });
  }

  // Completely new contact → create pending + generate deep link for confirmation
  contact = new Contact({
    userId: owner.id,
    shortId,
    name: name.trim(),
    contact: contactValue,
    status: 'pending',
    submittedAt: new Date()
  });
  await contact.save();

  const payload = 'sub_' + shortId + '_' + uuidv4().slice(0, 12);
  pendingSubscribers.set(payload, {
    userId: owner.id,
    shortId,
    name: name.trim(),
    contact: contactValue,
    createdAt: Date.now()
  });

  const deepLink = `https://t.me/\( {owner.botUsername}?start= \){payload}`;
  res.json({ success: true, deepLink });
});

// ==================== CONTACTS LIST & DELETE ====================
app.get('/api/contacts', authenticateToken, async (req, res) => {
  const contacts = await Contact.find({ userId: req.user.id }).sort({ submittedAt: -1 });
  const formatted = contacts.map(c => ({
    name: c.name,
    contact: c.contact,
    status: c.status,
    telegramChatId: c.telegramChatId || null,
    pageId: c.shortId,
    submittedAt: new Date(c.submittedAt).toLocaleString(),
    subscribedAt: c.subscribedAt ? new Date(c.subscribedAt).toLocaleString() : null
  }));
  res.json({ success: true, contacts: formatted });
});

app.post('/api/contacts/delete', authenticateToken, async (req, res) => {
  const { contacts } = req.body;
  if (!Array.isArray(contacts) || contacts.length === 0) return res.status(400).json({ error: 'Provide contact array' });

  const result = await Contact.deleteMany({
    userId: req.user.id,
    contact: { $in: contacts.map(c => c.toLowerCase()) }
  });

  res.json({ success: true, deletedCount: result.deletedCount });
});

// ==================== BROADCASTING (with auto-unsubscribe on block) ====================
async function executeBroadcast(userId, message) {
  const bot = activeBots.get(userId);
  if (!bot) return { sent: 0, failed: 0, total: 0, error: 'Bot not connected' };

  const sanitizedMessage = sanitizeTelegramHtml(message);
  const numberedChunks = splitTelegramMessage(sanitizedMessage);

  const targets = await Contact.find({ userId, status: 'subscribed', telegramChatId: { $exists: true, $ne: null } });
  if (targets.length === 0) return { sent: 0, failed: 0, total: 0 };

  let sent = 0;
  let failed = 0;

  for (const target of targets) {
    try {
      for (const chunk of numberedChunks) {
        await bot.telegram.sendMessage(target.telegramChatId, chunk, { parse_mode: 'HTML' });
      }
      sent++;
    } catch (err) {
      failed++;
      const isBlocked = err.response?.error_code === 403 ||
        (err.message && /blocked|kicked|forbidden|chat not found|user is deactivated/i.test(err.message));

      if (isBlocked) {
        target.status = 'unsubscribed';
        target.unsubscribedAt = new Date();
        target.telegramChatId = null;
        await target.save();
      }
    }
  }

  return { sent, failed, total: targets.length };
}

// ... (scheduled broadcasts, admin panel, cleanup, startup — all unchanged)

app.listen(PORT, () => {
  console.log('\n🚀 SENDEM SERVER — FINAL VERSION (January 03, 2026)');
  console.log(`Server running on port ${PORT}`);
  console.log('Key Features:');
  console.log('• Same contact on any form → updates shortId, keeps chat ID and subscription');
  console.log('• No duplicates, no reset to pending');
  console.log('• Users blocked bot → auto-unsubscribed during broadcast');
  console.log('• Full MongoDB persistence + webhook mode\n');
});
