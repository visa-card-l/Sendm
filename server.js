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
const NodeCache = require('node-cache');

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== CONFIG & SECRETS ====================
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_weak_secret_change_me_immediately';
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || 'sk_test_fallback_change_me';
const PAYSTACK_PUBLIC_KEY = process.env.PAYSTACK_PUBLIC_KEY || 'pk_test_fallback_change_me';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'midas';

if (JWT_SECRET.includes('fallback')) {
  console.warn('⚠️  WARNING: JWT_SECRET not set in .env! Using insecure fallback.');
}
if (PAYSTACK_SECRET_KEY.startsWith('sk_test_fallback')) {
  console.warn('⚠️  WARNING: PAYSTACK_SECRET_KEY not set in .env!');
}

const MONTHLY_PRICE_KOBO = 500000; // ₦5,000 in kobo

// Dynamic server-wide limits (configurable via admin panel)
let DAILY_BROADCAST_LIMIT = 3;
let MAX_LANDING_PAGES = 5;
let MAX_FORMS = 5;

// ==================== CACHING ====================
const cache = new NodeCache({ stdTTL: 300, checkperiod: 320 }); // 5-minute default TTL

// ==================== MONGODB CONNECTION ====================
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/sendm';
console.log('Attempting to connect to MongoDB with URI:', MONGODB_URI.replace(/:([^:@]+)@/, ':****@'));

mongoose.connect(MONGODB_URI, {
  serverSelectionTimeoutMS: 30000,
  socketTimeoutMS: 45000,
  connectTimeoutMS: 30000,
  retryWrites: true,
}).then(() => {
  console.log('✅ Successfully connected to MongoDB');
}).catch(err => {
  console.error('MongoDB connection error:', err.message, err.stack);
  process.exit(1);
});

mongoose.connection.on('error', err => {
  console.error('MongoDB runtime error:', err.message);
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
  pendingPayload: String,
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

// Indexes (only the ones NOT already created by unique: true)
landingPageSchema.index({ userId: 1 });
formPageSchema.index({ userId: 1 });
contactSchema.index({ userId: 1 });
contactSchema.index({ userId: 1, contact: 1 });
contactSchema.index({ userId: 1, status: 1 });
contactSchema.index({ pendingPayload: 1 });
scheduledBroadcastSchema.index({ userId: 1 });
scheduledBroadcastSchema.index({ status: 1 });
scheduledBroadcastSchema.index({ scheduledTime: 1 });
broadcastDailySchema.index({ userId: 1, date: 1 }, { unique: true });

// Active bots
const activeBots = new Map();

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
  skip: (req) => !req.params.shortId,
});

// ==================== UTILITIES ====================
function sanitizeTelegramHtml(str = '') {
  if (typeof str !== 'string') return '';
  return str
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/on\w+\s*=\s*"[^"]*"/gi, '')
    .replace(/javascript:/gi, '')
    .trim();
}

function escapeHtml(unsafe = '') {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function getTodayString() {
  return new Date().toISOString().slice(0, 10);
}

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

async function incrementDailyBroadcastCount(userId) {
  const today = getTodayString();
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

// ==================== TELEGRAM BOT ====================
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

    if (payload.startsWith('sub_')) {
      const contact = await Contact.findOne({ pendingPayload: payload });
      if (contact && contact.userId === user.id) {
        contact.telegramChatId = chatId;
        contact.status = 'subscribed';
        contact.subscribedAt = new Date();
        contact.pendingPayload = undefined;
        await contact.save();

        const form = await FormPage.findOne({ shortId: contact.shortId });
        let welcomeText = '<b>Subscription Confirmed!</b>\n\nHi <b>' + escapeHtml(contact.name) + '</b>!\n\nYou\'re now subscribed. Thank you!';

        if (form && form.welcomeMessage && form.welcomeMessage.trim()) {
          welcomeText = form.welcomeMessage
            .replace(/\{name\}/gi, '<b>' + escapeHtml(contact.name) + '</b>')
            .replace(/\{contact\}/gi, escapeHtml(contact.contact));
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

  bot.catch((err) => console.error('Bot error for ' + user.email + ':', err));
  bot.launch();
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

  try {
    const response = await axios.get('https://api.telegram.org/bot' + botToken.trim() + '/getMe');
    if (!response.data.ok) return res.status(400).json({ error: 'Invalid bot token' });

    const botUsername = response.data.result.username.replace(/^@/, '');

    req.user.telegramBotToken = botToken.trim();
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
      startLink: startLink
    });
  } catch (err) {
    console.error('Telegram connect error:', err.message);
    res.status(500).json({ error: 'Failed to validate bot token' });
  }
});

app.post('/api/auth/change-bot-token', authenticateToken, async (req, res) => {
  const { newBotToken } = req.body;
  if (!newBotToken || !newBotToken.trim()) return res.status(400).json({ error: 'New bot token required' });

  try {
    const response = await axios.get('https://api.telegram.org/bot' + newBotToken.trim() + '/getMe');
    if (!response.data.ok) return res.status(400).json({ error: 'Invalid bot token' });

    const botUsername = response.data.result.username.replace(/^@/, '');

    req.user.telegramBotToken = newBotToken.trim();
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
      startLink: startLink
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

const resetTokens = new Map();

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
  if (!resetToken || !newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'Valid token and password required' });
  }

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

// ==================== SUBSCRIPTION ====================
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
        metadata: {
          userId: req.user.id,
          plan: 'premium-monthly'
        }
      },
      {
        headers: {
          Authorization: 'Bearer ' + PAYSTACK_SECRET_KEY,
          'Content-Type': 'application/json'
        }
      }
    );

    const { authorization_url, reference } = response.data.data;
    req.user.pendingPaymentReference = reference;
    await req.user.save();

    res.json({
      success: true,
      authorizationUrl: authorization_url,
      reference: reference
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

    User.findOne({ id: userId }).then(async (user) => {
      if (!user) return res.status(200).send('OK');
      if (user.pendingPaymentReference !== reference) return res.status(200).send('OK');

      const endDate = new Date();
      endDate.setDate(endDate.getDate() + 30);

      user.isSubscribed = true;
      user.subscriptionEndDate = endDate;
      user.subscriptionPlan = 'premium-monthly';
      delete user.pendingPaymentReference;
      await user.save();

      console.log('Subscription activated for ' + user.email + ' until ' + endDate);
    });
  }

  res.status(200).send('OK');
});

app.get('/subscription-success', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Payment Successful</title>
      <style>
        body {font-family: system-ui, sans-serif; background:#0a0a0a; color:#00ff41; 
              display:flex; justify-content:center; align-items:center; min-height:100vh; margin:0;}
        .box {background:#111; padding:60px; border-radius:20px; text-align:center; box-shadow:0 0 30px rgba(0,255,65,0.2);}
        h1 {margin:0 0 20px; font-size:3em; color:#00ff41;}
        p {font-size:1.3em; margin:20px 0; line-height:1.6;}
        a {display:inline-block; margin-top:30px; padding:14px 32px; background:#00ff41; color:#000; 
           font-weight:bold; text-decoration:none; border-radius:8px; font-size:1.1em;}
        a:hover {background:#00cc33;}
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
    </html>
  `);
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
  if (currentCount >= limits.maxLandingPages) {
    return res.status(403).json({ error: 'Maximum ' + (limits.maxLandingPages === Infinity ? 'unlimited' : limits.maxLandingPages) + ' landing pages allowed.' });
  }

  const finalShortId = shortId || uuidv4().slice(0, 8);
  const now = new Date();

  const cleanBlocks = config.blocks.map(b => {
    if (!b || b.isEditor) return null;
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

  cache.del('page:' + finalShortId);

  const url = req.protocol + '://' + req.get('host') + '/p/' + finalShortId;
  res.json({ success: true, shortId: finalShortId, url: url });
});

app.post('/api/pages/delete', authenticateToken, async (req, res) => {
  const { shortId } = req.body;
  const page = await LandingPage.findOne({ shortId, userId: req.user.id });
  if (!page) return res.status(404).json({ error: 'Page not found' });
  await LandingPage.deleteOne({ shortId });
  cache.del('page:' + shortId);
  res.json({ success: true });
});

app.get('/p/:shortId', async (req, res) => {
  const cacheKey = 'page:' + req.params.shortId;
  let page = cache.get(cacheKey);
  if (!page) {
    page = await LandingPage.findOne({ shortId: req.params.shortId });
    if (!page) return res.status(404).render('404');
    cache.set(cacheKey, page, 3600);
  }
  res.render('landing', { title: page.title, blocks: page.config.blocks });
});

app.get('/api/page/:shortId', authenticateToken, async (req, res) => {
  const page = await LandingPage.findOne({ shortId: req.params.shortId, userId: req.user.id });
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
  if (currentCount >= limits.maxForms) {
    return res.status(403).json({ error: 'Maximum ' + (limits.maxForms === Infinity ? 'unlimited' : limits.maxForms) + ' forms allowed.' });
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

  cache.del('form:' + finalShortId);

  const url = req.protocol + '://' + req.get('host') + '/f/' + finalShortId;
  res.json({ success: true, shortId: finalShortId, url: url });
});

app.post('/api/forms/delete', authenticateToken, async (req, res) => {
  const { shortId } = req.body;
  const form = await FormPage.findOne({ shortId, userId: req.user.id });
  if (!form) return res.status(404).json({ error: 'Form not found' });
  await FormPage.deleteOne({ shortId });
  await Contact.deleteMany({ shortId, userId: req.user.id });
  cache.del('form:' + shortId);
  res.json({ success: true });
});

app.get('/f/:shortId', async (req, res) => {
  const cacheKey = 'form:' + req.params.shortId;
  let form = cache.get(cacheKey);
  if (!form) {
    form = await FormPage.findOne({ shortId: req.params.shortId });
    if (!form) return res.status(404).render('404');
    cache.set(cacheKey, form, 3600);
  }
  res.render('form', { title: form.title, state: form.state });
});

app.get('/api/form/:shortId', authenticateToken, async (req, res) => {
  const form = await FormPage.findOne({ shortId: req.params.shortId, userId: req.user.id });
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
  const { shortId } = req.params;
  const { name, email } = req.body;
  if (!name || !email || !name.trim() || !email.trim()) return res.status(400).json({ error: 'Name and email required' });

  const form = await FormPage.findOne({ shortId });
  if (!form) return res.status(404).json({ error: 'Form not found' });

  const owner = await User.findOne({ id: form.userId });
  if (!owner || !owner.telegramBotToken) return res.status(400).json({ error: 'Bot not connected' });

  const contactValue = email.trim().toLowerCase();
  const payload = 'sub_' + shortId + '_' + uuidv4().slice(0, 12);

  let contact = await Contact.findOne({ userId: owner.id, contact: contactValue });
  if (contact) {
    contact.name = name.trim();
    contact.shortId = shortId;
    contact.submittedAt = new Date();
  } else {
    contact = new Contact({
      userId: owner.id,
      shortId,
      name: name.trim(),
      contact: contactValue,
      status: 'pending',
      submittedAt: new Date(),
      pendingPayload: payload
    });
  }
  await contact.save();

  const deepLink = 'https://t.me/' + owner.botUsername + '?start=' + payload;
  res.json({ success: true, deepLink: deepLink });
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
  const chunks = sanitizedMessage.match(/[\s\S]{1,4000}/g) || [];

  const targets = await Contact.find({ userId, status: 'subscribed', telegramChatId: { $exists: true } });
  if (targets.length === 0) return { sent: 0, failed: 0, total: 0 };

  let sent = 0, failed = 0;

  for (const target of targets) {
    try {
      for (const chunk of chunks) {
        await bot.telegram.sendMessage(target.telegramChatId, chunk, { parse_mode: 'HTML' });
      }
      sent++;
    } catch (err) {
      failed++;
      if (err.response?.error_code === 403) {
        target.status = 'unsubscribed';
        target.unsubscribedAt = new Date();
        target.telegramChatId = null;
        await target.save();
      }
    }
  }

  return { sent, failed, total: targets.length };
}

app.post('/api/broadcast/now', authenticateToken, async (req, res) => {
  const { message } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message required' });

  const todayCount = await incrementDailyBroadcastCount(req.user.id);
  const limits = getUserLimits(req.user);
  if (todayCount > limits.dailyBroadcasts) {
    return res.status(403).json({ error: 'Daily limit reached: ' + (limits.dailyBroadcasts === Infinity ? 'Unlimited' : limits.dailyBroadcasts) + ' broadcasts per day.' });
  }

  const result = await executeBroadcast(req.user.id, message.trim());
  res.json({ success: true, ...result });
});

app.post('/api/broadcast/schedule', authenticateToken, async (req, res) => {
  const { message, scheduledTime } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Message required' });

  const todayCount = await incrementDailyBroadcastCount(req.user.id);
  const limits = getUserLimits(req.user);
  if (todayCount > limits.dailyBroadcasts) {
    return res.status(403).json({ error: 'Daily limit reached' });
  }

  const time = new Date(scheduledTime);
  if (isNaN(time.getTime()) || time <= new Date()) {
    return res.status(400).json({ error: 'Invalid future time' });
  }

  const broadcast = await ScheduledBroadcast.create({
    broadcastId: uuidv4(),
    userId: req.user.id,
    message: sanitizeTelegramHtml(message.trim()),
    scheduledTime: time
  });

  res.json({
    success: true,
    broadcastId: broadcast.broadcastId,
    scheduledTime: time.toISOString()
  });
});

app.get('/api/broadcast/scheduled', authenticateToken, async (req, res) => {
  const scheduled = await ScheduledBroadcast.find({
    userId: req.user.id,
    status: 'pending'
  }).sort({ scheduledTime: 1 });

  const formatted = scheduled.map(s => ({
    broadcastId: s.broadcastId,
    message: s.message.substring(0, 100) + (s.message.length > 100 ? '...' : ''),
    scheduledTime: s.scheduledTime.toISOString(),
    status: s.status
  }));

  res.json({ success: true, scheduled: formatted });
});

app.delete('/api/broadcast/scheduled/:broadcastId', authenticateToken, async (req, res) => {
  const result = await ScheduledBroadcast.deleteOne({
    broadcastId: req.params.broadcastId,
    userId: req.user.id
  });
  if (result.deletedCount === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ success: true });
});

setInterval(async () => {
  const now = new Date();
  const due = await ScheduledBroadcast.find({
    status: 'pending',
    scheduledTime: { $lte: now }
  });

  for (const task of due) {
    task.status = 'sent';
    await task.save();
    executeBroadcast(task.userId, task.message);
  }
}, 60000);

// ==================== ADMIN LIMITS ====================
app.get('/admin-limits', (req, res) => {
  res.send(`
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
          <input type="password" name="password" required>

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
  `);
});

app.post('/admin-limits', (req, res) => {
  const { password, daily_broadcast, max_pages, max_forms } = req.body;

  if (password !== ADMIN_PASSWORD) {
    return res.status(401).send('<h1 style="color:#f44336;text-align:center;margin-top:50vh;transform:translateY(-50%);">Access Denied – Wrong Password</h1>');
  }

  const newDaily = parseInt(daily_broadcast);
  const newPages = parseInt(max_pages);
  const newForms = parseInt(max_forms);

  if (isNaN(newDaily) || isNaN(newPages) || isNaN(newForms) || newDaily < 1 || newPages < 1 || newForms < 1) {
    return res.status(400).send('<h1 style="color:#f44336;text-align:center;margin-top:50vh;transform:translateY(-50%);">Invalid Values</h1>');
  }

  DAILY_BROADCAST_LIMIT = newDaily;
  MAX_LANDING_PAGES = newPages;
  MAX_FORMS = newForms;

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Limits Updated</title>
      <style>
        body { font-family: 'Segoe UI', sans-serif; background: #121212; color: #e0e0e0; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .container { background: #1e1e1e; padding: 40px; border-radius: 12px; text-align: center; }
        h1 { color: #4caf50; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Success!</h1>
        <p>Limits updated:</p>
        <p>Broadcasts/day: \( {DAILY_BROADCAST_LIMIT}<br>Pages: \){MAX_LANDING_PAGES}<br>Forms: ${MAX_FORMS}</p>
        <p><a href="/admin-limits" style="color:#ffd700;">← Back</a></p>
      </div>
    </body>
    </html>
  `);
});

// ==================== CLEANUP & STARTUP ====================
setInterval(async () => {
  const cutoff = Date.now() - 30 * 60 * 1000;
  await Contact.deleteMany({ pendingPayload: { $exists: true }, createdAt: { $lt: new Date(cutoff) } });
}, 60 * 60 * 1000);

mongoose.connection.once('open', async () => {
  const usersWithBots = await User.find({ telegramBotToken: { $exists: true, $ne: null } });
  usersWithBots.forEach(launchUserBot);
  console.log('Launched ' + usersWithBots.length + ' existing Telegram bots');
});

process.on('SIGTERM', () => {
  console.log('Shutting down...');
  process.exit(0);
});

app.use((req, res) => res.status(404).render('404'));

app.listen(PORT, () => {
  console.log('\nSENDEM SERVER (MongoDB Version) – FULLY OPTIMIZED');
  console.log('Server running on http://localhost:' + PORT);
  console.log('Admin panel: http://localhost:' + PORT + '/admin-limits');
  console.log('All data persisted in MongoDB | Fast reads via indexes + cache | Reliable writes\n');
});
