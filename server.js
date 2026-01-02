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
  contact: { type: String, required: true },
  telegramChatId: String,
  status: { type: String, default: 'pending' },
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
contactSchema.index({ userId: 1, contact: 1 });
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
app.use(express.raw({ type: 'application/json' }));

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
app.post('/webhook/' + WEBHOOK_SECRET + '/:userId', express.raw({ type: 'application/json' }), async (req, res) => {
  const userId = req.params.userId;
  const bot = activeBots.get(userId);

  if (bot) {
    try {
      await bot.handleUpdate(JSON.parse(req.body));
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
        let contact = await Contact.findOne({ userId: user.id, contact: sub.contact });

        if (!contact) {
          contact = new Contact({
            userId: user.id,
            shortId: sub.shortId,
            name: sub.name,
            contact: sub.contact,
            submittedAt: new Date(),
            status: 'pending'
          });
        }

        contact.telegramChatId = chatId;
        contact.status = 'subscribed';
        contact.subscribedAt = new Date();
        await contact.save();

        await Contact.deleteMany({ userId: user.id, contact: sub.contact, status: 'pending' });

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
      // Clean any old webhook
      await bot.telegram.deleteWebhook({ drop_pending_updates: true });
      const success = await bot.telegram.setWebhook(webhookUrl);
      if (success) {
        console.log(`Webhook successfully set for @\( {user.botUsername} → \){webhookUrl}`);
      } else {
        console.error(`Failed to set webhook for @${user.botUsername}`);
      }
    } catch (err) {
      console.error(`Webhook setup error for ${user.email}:`, err.message);
    }
  })();

  // Store bot — updates handled manually via /webhook endpoint
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
<head>
  <meta charset="UTF-8">
  <title>Payment Successful</title>
  <style>
    body{font-family:system-ui,sans-serif;background:#0a0a0a;color:#00ff41;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;}
    .box{background:#111;padding:60px;border-radius:20px;text-align:center;box-shadow:0 0 30px rgba(0,255,65,0.2);}
    h1{margin:0 0 20px;font-size:3em;color:#00ff41;}
    p{font-size:1.3em;margin:20px 0;line-height:1.6;}
    a{display:inline-block;margin-top:30px;padding:14px 32px;background:#00ff41;color:#000;font-weight:bold;text-decoration:none;border-radius:8px;font-size:1.1em;}
    a:hover{background:#00cc33;}
  </style>
</head>
<body>
  <div class="box">
    <h1>✔ Payment Successful!</h1>
    <p>Your subscription is now <strong>active</strong>.</p>
    <p>You have unlimited broadcasts, landing pages, and forms.</p>
    <p><a href="/">← Return to Dashboard</a></p>
  </div>
</body>
</html>`);
});

// ==================== LANDING PAGES ====================
app.get('/api/pages', authenticateToken, async (req, res) => {
  const pages = await LandingPage.find({ userId: req.user.id }).sort({ updatedAt: -1 });
  const host = req.get('host');
  const protocol = req.protocol;
  const formatted = pages.map(p => ({
    shortId: p.shortId,
    title: p.title,
    createdAt: p.createdAt,
    updatedAt: p.updatedAt,
    url: protocol + '://' + host + '/p/' + p.shortId
  }));
  res.json({ pages: formatted });
});

app.post('/api/pages/save', authenticateToken, async (req, res) => {
  const { shortId, title, config } = req.body;
  if (!title || !config || !Array.isArray(config.blocks)) return res.status(400).json({ error: 'Title and config.blocks required' });

  const limits = getUserLimits(req.user);
  const currentCount = await LandingPage.countDocuments({ userId: req.user.id });
  if (currentCount >= limits.maxLandingPages && limits.maxLandingPages !== Infinity) {
    return res.status(403).json({ error: 'Maximum landing pages limit reached.' });
  }

  const finalShortId = shortId || uuidv4().slice(0, 8);
  const now = new Date();

  const cleanBlocks = config.blocks.map(b => {
    if (!b || b.isEditor || (b.id && (b.id.includes('editor-') || b.id.includes('control-')))) return null;
    if (b.type === 'text') return { type: 'text', tag: b.tag || 'p', content: (b.content || '').trim() };
    if (b.type === 'image') return b.src ? { type: 'image', src: b.src.trim() } : null;
    if (b.type === 'button') return b.text ? { type: 'button', text: b.text.trim(), href: b.href || '' } : null;
    if (b.type === 'form') return b.html ? { type: 'form', html: b.html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') } : null;
    return null;
  }).filter(Boolean);

  if (cleanBlocks.length === 0) return res.status(400).json({ error: 'No valid blocks' });

  await LandingPage.findOneAndUpdate(
    { shortId: finalShortId },
    {
      userId: req.user.id,
      title: title.trim(),
      config: { blocks: cleanBlocks },
      updatedAt: now,
      createdAt: shortId ? undefined : now
    },
    { upsert: true }
  );

  const url = req.protocol + '://' + req.get('host') + '/p/' + finalShortId;
  res.json({ success: true, shortId: finalShortId, url });
});

app.post('/api/pages/delete', authenticateToken, async (req, res) => {
  const { shortId } = req.body;
  const page = await LandingPage.findOne({ shortId, userId: req.user.id });
  if (!page) return res.status(404).json({ error: 'Page not found' });
  await LandingPage.deleteOne({ shortId });
  res.json({ success: true });
});

app.get('/p/:shortId', async (req, res) => {
  const page = await LandingPage.findOne({ shortId: req.params.shortId });
  if (!page) return res.status(404).render('404');
  res.render('landing', { title: page.title, blocks: page.config.blocks });
});

app.get('/api/page/:shortId', async (req, res) => {
  const page = await LandingPage.findOne({ shortId: req.params.shortId });
  if (!page) return res.status(404).json({ error: 'Page not found' });
  res.json({ shortId: page.shortId, title: page.title, config: page.config });
});

// ==================== FORMS ====================
app.get('/api/forms', authenticateToken, async (req, res) => {
  const forms = await FormPage.find({ userId: req.user.id }).sort({ updatedAt: -1 });
  const host = req.get('host');
  const protocol = req.protocol;
  const formatted = forms.map(f => ({
    shortId: f.shortId,
    title: f.title,
    createdAt: f.createdAt,
    updatedAt: f.updatedAt,
    url: protocol + '://' + host + '/f/' + f.shortId
  }));
  res.json({ forms: formatted });
});

app.post('/api/forms/save', authenticateToken, async (req, res) => {
  const { shortId, title, state, welcomeMessage } = req.body;
  if (!title || !state) return res.status(400).json({ error: 'Title and state required' });

  const limits = getUserLimits(req.user);
  const currentCount = await FormPage.countDocuments({ userId: req.user.id });
  if (currentCount >= limits.maxForms && limits.maxForms !== Infinity) {
    return res.status(403).json({ error: 'Maximum forms limit reached.' });
  }

  const sanitizedState = JSON.parse(JSON.stringify(state));
  if (sanitizedState.headerText) sanitizedState.headerText = sanitizedState.headerText.replace(/<script.*?<\/script>/gi, '');
  if (sanitizedState.subheaderText) sanitizedState.subheaderText = sanitizedState.subheaderText.replace(/<script.*?<\/script>/gi, '');
  if (sanitizedState.buttonText) sanitizedState.buttonText = sanitizedState.buttonText.replace(/<script.*?<\/script>/gi, '');

  const sanitizedWelcome = welcomeMessage && typeof welcomeMessage === 'string'
    ? sanitizeTelegramHtml(welcomeMessage.trim())
    : '';

  const finalShortId = shortId || uuidv4().slice(0, 8);
  const now = new Date();

  await FormPage.findOneAndUpdate(
    { shortId: finalShortId },
    {
      userId: req.user.id,
      title: title.trim(),
      state: sanitizedState,
      welcomeMessage: sanitizedWelcome,
      updatedAt: now,
      createdAt: shortId ? undefined : now
    },
    { upsert: true }
  );

  const url = req.protocol + '://' + req.get('host') + '/f/' + finalShortId;
  res.json({ success: true, shortId: finalShortId, url });
});

app.post('/api/forms/delete', authenticateToken, async (req, res) => {
  const { shortId } = req.body;
  const form = await FormPage.findOne({ shortId, userId: req.user.id });
  if (!form) return res.status(404).json({ error: 'Form not found' });
  await FormPage.deleteOne({ shortId });
  await Contact.deleteMany({ shortId, userId: req.user.id });
  res.json({ success: true });
});

app.get('/f/:shortId', async (req, res) => {
  const form = await FormPage.findOne({ shortId: req.params.shortId });
  if (!form) return res.status(404).render('404');
  res.render('form', { title: form.title, state: form.state });
});

app.get('/api/form/:shortId', async (req, res) => {
  const form = await FormPage.findOne({ shortId: req.params.shortId });
  if (!form) return res.status(404).json({ error: 'Form not found' });
  res.json({
    shortId: form.shortId,
    title: form.title,
    state: form.state,
    welcomeMessage: form.welcomeMessage
  });
});

// ==================== SUBSCRIBE & CONTACTS ====================
app.post('/api/subscribe/:shortId', formSubmitLimiter, async (req, res) => {
  const shortId = req.params.shortId;
  const { name, email } = req.body;
  if (!name || !name.trim() || !email || !email.trim()) return res.status(400).json({ error: 'Valid name and contact required' });

  const form = await FormPage.findOne({ shortId });
  if (!form) return res.status(404).json({ error: 'Form not found' });

  const owner = await User.findOne({ id: form.userId });
  if (!owner || !owner.telegramBotToken || !owner.botUsername) return res.status(400).json({ error: 'Bot not connected' });

  const contactValue = email.trim().toLowerCase();
  const payload = 'sub_' + shortId + '_' + uuidv4().slice(0, 12);

  let contact = await Contact.findOne({ userId: owner.id, contact: contactValue });
  if (contact) {
    contact.name = name.trim();
    contact.shortId = shortId;
    contact.submittedAt = new Date();
    contact.status = 'pending';
  } else {
    contact = new Contact({
      userId: owner.id,
      shortId,
      name: name.trim(),
      contact: contactValue,
      status: 'pending',
      submittedAt: new Date()
    });
  }
  await contact.save();

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
    contact: { $in: contacts }
  });

  res.json({ success: true, deletedCount: result.deletedCount });
});

// ==================== BROADCASTING ====================
async function executeBroadcast(userId, message) {
  const bot = activeBots.get(userId);
  if (!bot) return { sent: 0, failed: 0, total: 0, error: 'Bot not connected' };

  const sanitizedMessage = sanitizeTelegramHtml(message);
  const numberedChunks = splitTelegramMessage(sanitizedMessage);

  const targets = await Contact.find({ userId, status: 'subscribed', telegramChatId: { $exists: true } });
  if (targets.length === 0) return { sent: 0, failed: 0, total: 0 };

  const batches = [];
  for (let i = 0; i < targets.length; i += BATCH_SIZE) {
    batches.push(targets.slice(i, i + BATCH_SIZE));
  }

  let sent = 0;
  let failed = 0;

  for (let i = 0; i < batches.length; i++) {
    const batch = batches[i];
    for (let j = 0; j < batch.length; j++) {
      const target = batch[j];
      try {
        for (let k = 0; k < numberedChunks.length; k++) {
          await bot.telegram.sendMessage(target.telegramChatId, numberedChunks[k], { parse_mode: 'HTML' });
        }
        sent++;
      } catch (err) {
        failed++;
        const isBlocked = err.response && err.response.error_code === 403 ||
          (err.message && /blocked|kicked|forbidden|chat not found|user is deactivated/i.test(err.message));
        if (isBlocked) {
          target.status = 'unsubscribed';
          target.unsubscribedAt = new Date();
          target.telegramChatId = null;
          await target.save();
        }
      }
    }
    if (i < batches.length - 1) {
      await new Promise(resolve => setTimeout(resolve, BATCH_INTERVAL_MS));
    }
  }

  return { sent, failed, total: targets.length };
}

setInterval(async () => {
  const now = new Date();
  const due = await ScheduledBroadcast.find({ status: 'pending', scheduledTime: { $lte: now } });

  for (const task of due) {
    task.status = 'sent';
    await task.save();

    const result = await executeBroadcast(task.userId, task.message);

    const user = await User.findOne({ id: task.userId });
    if (user && user.isTelegramConnected && activeBots.has(user.id)) {
      let reportText = '<b>Scheduled Broadcast Report</b>\n\n';
      if (result.error) {
        reportText += '<b>Failed to send</b>\n' + escapeHtml(result.error);
      } else {
        const emoji = result.failed === 0 ? '✅' : '⚠️';
        reportText += emoji + ' <b>' + result.sent + ' of ' + result.total + '</b> contacts received the message.\n';
        if (result.failed > 0) reportText += result.failed + ' failed to deliver.';
      }
      reportText += '\n\nSent on: ' + new Date().toLocaleString();

      try {
        await activeBots.get(user.id).telegram.sendMessage(user.telegramChatId, reportText, { parse_mode: 'HTML' });
      } catch (err) {
        console.error('Failed to send report to ' + user.email + ': ' + err.message);
      }
    }

    await ScheduledBroadcast.deleteOne({ broadcastId: task.broadcastId });
  }
}, 60000);

app.post('/api/broadcast/now', authenticateToken, async (req, res) => {
  const { message } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message required' });

  const todayCount = await incrementDailyBroadcast(req.user.id);
  const limits = getUserLimits(req.user);
  if (todayCount > limits.dailyBroadcasts && limits.dailyBroadcasts !== Infinity) {
    return res.status(403).json({ error: 'Daily broadcast limit reached.' });
  }

  const result = await executeBroadcast(req.user.id, message.trim());
  res.json({ success: true, sent: result.sent, failed: result.failed, total: result.total });
});

app.post('/api/broadcast/schedule', authenticateToken, async (req, res) => {
  const { message, scheduledTime, recipients = 'all' } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message required' });

  const todayCount = await incrementDailyBroadcast(req.user.id);
  const limits = getUserLimits(req.user);
  if (todayCount > limits.dailyBroadcasts && limits.dailyBroadcasts !== Infinity) {
    return res.status(403).json({ error: 'Daily broadcast limit reached.' });
  }

  const time = new Date(scheduledTime);
  if (isNaN(time.getTime()) || time <= new Date()) {
    return res.status(400).json({ error: 'Invalid future time' });
  }

  const broadcast = await ScheduledBroadcast.create({
    broadcastId: uuidv4(),
    userId: req.user.id,
    message: sanitizeTelegramHtml(message.trim()),
    recipients,
    scheduledTime: time
  });

  res.json({ success: true, broadcastId: broadcast.broadcastId, scheduledTime: time.toISOString() });
});

app.get('/api/broadcast/scheduled', authenticateToken, async (req, res) => {
  const scheduled = await ScheduledBroadcast.find({ userId: req.user.id, status: 'pending' }).sort({ scheduledTime: 1 });
  const formatted = scheduled.map(s => ({
    broadcastId: s.broadcastId,
    message: s.message.substring(0, 100) + (s.message.length > 100 ? '...' : ''),
    scheduledTime: s.scheduledTime.toISOString(),
    status: s.status,
    recipients: s.recipients
  }));
  res.json({ success: true, scheduled: formatted });
});

app.delete('/api/broadcast/scheduled/:broadcastId', authenticateToken, async (req, res) => {
  const result = await ScheduledBroadcast.deleteOne({ broadcastId: req.params.broadcastId, userId: req.user.id });
  if (result.deletedCount === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ success: true });
});

app.patch('/api/broadcast/scheduled/:broadcastId', authenticateToken, async (req, res) => {
  const { message, scheduledTime, recipients } = req.body;
  const task = await ScheduledBroadcast.findOne({ broadcastId: req.params.broadcastId, userId: req.user.id, status: 'pending' });

  if (!task) return res.status(400).json({ error: 'Cannot edit this broadcast' });

  if (message && message.trim()) task.message = sanitizeTelegramHtml(message.trim());
  if (recipients) task.recipients = recipients;
  if (scheduledTime) {
    const newTime = new Date(scheduledTime);
    if (isNaN(newTime.getTime()) || newTime <= new Date()) return res.status(400).json({ error: 'Invalid future time' });
    task.scheduledTime = newTime;
  }

  await task.save();
  res.json({ success: true, broadcastId: task.broadcastId, scheduledTime: task.scheduledTime.toISOString() });
});

app.get('/api/broadcast/scheduled/:broadcastId/details', authenticateToken, async (req, res) => {
  const task = await ScheduledBroadcast.findOne({ broadcastId: req.params.broadcastId, userId: req.user.id });

  if (!task || task.status !== 'pending') {
    return res.status(404).json({ error: 'Broadcast not found or not editable' });
  }

  const scheduledDate = new Date(task.scheduledTime);
  const offsetMs = scheduledDate.getTimezoneOffset() * 60000;
  const localDate = new Date(scheduledDate.getTime() + offsetMs);
  const localIsoString = localDate.toISOString().slice(0, 16);

  res.json({
    success: true,
    message: task.message,
    scheduledTime: localIsoString,
    recipients: task.recipients || 'all'
  });
});

// ==================== ADMIN LIMITS ====================
app.get('/admin-limits', async (req, res) => {
  const totalUsers = await User.countDocuments({});
  const payingUsers = await User.countDocuments({ isSubscribed: true, subscriptionEndDate: { $gt: new Date() } });

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Server Admin Panel</title>
  <style>
    body { font-family: 'Segoe UI', sans-serif; background: #121212; color: #e0e0e0; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
    .container { background: #1e1e1e; padding: 40px; border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.6); width: 90%; max-width: 600px; }
    h1 { text-align: center; color: #ffd700; margin-bottom: 30px; }
    .stats { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 30px; }
    .stat-box { background: #2d2d2d; padding: 20px; border-radius: 10px; text-align: center; }
    .stat-number { font-size: 2.5em; font-weight: bold; color: #00ff41; margin: 10px 0; }
    .stat-label { font-size: 1.1em; color: #aaa; }
    label { display: block; margin: 20px 0 8px; font-size: 1.1em; }
    input[type="number"], input[type="password"] { width: 100%; padding: 12px; background: #2d2d2d; border: none; border-radius: 6px; color: white; font-size: 1em; margin-bottom: 15px; }
    button { width: 100%; padding: 14px; background: #ffd700; color: black; font-weight: bold; border: none; border-radius: 6px; cursor: pointer; font-size: 1.1em; margin-top: 20px; }
    button:hover { background: #e6c200; }
    .current { text-align: center; margin: 25px 0; padding: 15px; background: #2d2d2d; border-radius: 8px; font-size: 1.1em; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Server Admin Panel</h1>
    <div class="stats">
      <div class="stat-box">
        <div class="stat-number">${totalUsers}</div>
        <div class="stat-label">Total Users</div>
      </div>
      <div class="stat-box">
        <div class="stat-number">${payingUsers}</div>
        <div class="stat-label">Paying Users</div>
      </div>
    </div>
    <form method="POST">
      <label>Owner Password</label>
      <input type="password" name="password" required placeholder="Enter admin password">
      <label>Daily Broadcasts per User (Free)</label>
      <input type="number" name="daily_broadcast" min="1" value="${DAILY_BROADCAST_LIMIT}" required>
      <label>Max Landing Pages per User (Free)</label>
      <input type="number" name="max_pages" min="1" value="${MAX_LANDING_PAGES}" required>
      <label>Max Forms per User (Free)</label>
      <input type="number" name="max_forms" min="1" value="${MAX_FORMS}" required>
      <div class="current">
        <strong>Current Free Tier Limits:</strong><br>
        Broadcasts/day: \( {DAILY_BROADCAST_LIMIT} | Pages: \){MAX_LANDING_PAGES} | Forms: ${MAX_FORMS}
      </div>
      <button type="submit">Update Limits</button>
    </form>
  </div>
</body>
</html>`;
  res.send(html);
});

app.post('/admin-limits', (req, res) => {
  const { password, daily_broadcast, max_pages, max_forms } = req.body;

  if (password !== ADMIN_PASSWORD) {
    return res.send('<html><body style="background:#121212;color:#f44336;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:sans-serif;text-align:center;"><h1>Access Denied<br>Wrong Password</h1></body></html>');
  }

  const newDaily = parseInt(daily_broadcast);
  const newPages = parseInt(max_pages);
  const newForms = parseInt(max_forms);

  if (isNaN(newDaily) || isNaN(newPages) || isNaN(newForms) || newDaily < 1 || newPages < 1 || newForms < 1) {
    return res.send('<html><body style="background:#121212;color:#f44336;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:sans-serif;text-align:center;"><h1>Invalid Values<br>All limits must be ≥ 1</h1></body></html>');
  }

  DAILY_BROADCAST_LIMIT = newDaily;
  MAX_LANDING_PAGES = newPages;
  MAX_FORMS = newForms;

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
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
</html>`);
});

// ==================== CLEANUP & STARTUP ====================
setInterval(() => {
  const now = Date.now();
  const keys = Array.from(pendingSubscribers.keys());
  for (const key of keys) {
    const data = pendingSubscribers.get(key);
    if (now - data.createdAt > 30 * 60 * 1000) {
      pendingSubscribers.delete(key);
    }
  }
}, 60 * 60 * 1000);

mongoose.connection.once('open', async () => {
  const usersWithBots = await User.find({ telegramBotToken: { $exists: true, $ne: null } });
  for (const user of usersWithBots) {
    launchUserBot(user);
  }
  console.log(`Launched ${usersWithBots.length} existing bots in pure webhook mode`);
});

process.on('SIGTERM', () => {
  console.log('Shutting down gracefully...');
  process.exit(0);
});

app.use((req, res) => {
  res.status(404).render('404');
});

app.listen(PORT, () => {
  console.log('\nSENDEM SERVER — FINAL PURE WEBHOOK VERSION');
  console.log('Server running on port ' + PORT);
  console.log('Domain: https://' + DOMAIN);
  console.log('Webhook endpoint: /webhook/' + WEBHOOK_SECRET + '/<userId>');
  console.log('No 409 errors | Subscription links work perfectly');
  console.log('Ready for production! 🚀\n');
});
