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

const MONTHLY_PRICE_KOBO = 500000;

// Batching config
const BATCH_SIZE = 25;
const BATCH_INTERVAL_MS = 15000;
const MAX_MSG_LENGTH = 4000;

// ==================== PER-USER & PUBLIC CACHE WITH TTL ====================
const userCache = new Map();
const publicCache = new Map();

const TTL = {
  pages: 5 * 60 * 1000,
  forms: 5 * 60 * 1000,
  contacts: 2 * 60 * 1000,
  public: 10 * 60 * 1000
};

function getUserCache(userId) {
  let bucket = userCache.get(userId);
  if (!bucket) {
    bucket = {
      pages: null,
      forms: null,
      contacts: null,
      pagesTs: 0,
      formsTs: 0,
      contactsTs: 0,
      lastAccess: Date.now()
    };
    userCache.set(userId, bucket);
  } else {
    bucket.lastAccess = Date.now();
  }
  return bucket;
}

function invalidateUserCache(userId, type = 'all') {
  const bucket = userCache.get(userId);
  if (!bucket) return;

  if (type === 'pages' || type === 'all') {
    bucket.pages = null;
    bucket.pagesTs = 0;
  }
  if (type === 'forms' || type === 'all') {
    bucket.forms = null;
    bucket.formsTs = 0;
  }
  if (type === 'contacts' || type === 'all') {
    bucket.contacts = null;
    bucket.contactsTs = 0;
  }
  bucket.lastAccess = Date.now();
}

function invalidatePublicCache(key) {
  publicCache.delete(key);
}

setInterval(() => {
  const now = Date.now();
  const INACTIVE_THRESHOLD = 30 * 60 * 1000;

  for (const [key, val] of publicCache.entries()) {
    if (now - val.timestamp > TTL.public) {
      publicCache.delete(key);
    }
  }

  for (const [userId, bucket] of userCache.entries()) {
    if (now - bucket.lastAccess > INACTIVE_THRESHOLD) {
      userCache.delete(userId);
      console.log('🧹 Cleaned cache for inactive user: ' + userId);
    }
  }
}, 10 * 60 * 1000);

// ==================== ADMIN SETTINGS CACHE ====================
let adminSettingsCache = {
  dailyBroadcastLimit: 3,
  maxLandingPages: 5,
  maxForms: 5
};

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
// (All schemas and models unchanged — same as before)
// ... [User, LandingPage, FormPage, Contact, ScheduledBroadcast, BroadcastDaily, AdminSettings] ...

// Indexes, in-memory helpers, utilities (isBotTokenInUse, sanitize, etc.) unchanged

// ==================== JWT AUTH, BOT LAUNCH, MIDDLEWARE, WEBHOOK ====================
// All unchanged

// ==================== AUTH ROUTES WITH ENHANCED LOGGING ====================

app.post('/api/auth/connect-telegram', authenticateToken, async (req, res) => {
  const { botToken } = req.body;
  if (!botToken || !botToken.trim()) return res.status(400).json({ error: 'Bot token required' });

  const token = botToken.trim();

  console.log(`\n[Telegram Connect] User \( {req.user.email} attempting to connect bot token: \){token.substring(0, 10)}...${token.slice(-4)}`);

  const inUse = await isBotTokenInUse(token, req.user.id);
  if (inUse) {
    console.log(`[Telegram Connect] Token already in use by another account`);
    return res.status(409).json({ error: 'Bot already in use by another account' });
  }

  const url = `https://api.telegram.org/bot${token}/getMe`;
  console.log(`[Telegram Connect] Fetching: ${url}`);

  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(10000) }); // 10s timeout

    console.log(`[Telegram Connect] Response status: \( {response.status} \){response.statusText}`);

    if (!response.ok) {
      let errorBody = '';
      try {
        const errorData = await response.json();
        errorBody = JSON.stringify(errorData);
      } catch (_) {
        errorBody = await response.text();
      }
      console.log(`[Telegram Connect] Telegram API error: ${errorBody}`);
      return res.status(400).json({ error: 'Invalid bot token' });
    }

    const data = await response.json();
    console.log(`[Telegram Connect] Success! Bot username: @${data.result.username}`);

    const botUsername = data.result.username.replace(/^@/, '');

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
    console.error('[Telegram Connect] Failed to validate token:');
    console.error('   Message:', err.message);
    if (err.cause) console.error('   Cause:', err.cause);
    if (err.name) console.error('   Name:', err.name);
    console.error('   Stack:', err.stack);
    res.status(500).json({ error: 'Failed to validate bot token (network issue)' });
  }
});

app.post('/api/auth/change-bot-token', authenticateToken, async (req, res) => {
  const { newBotToken } = req.body;
  if (!newBotToken || !newBotToken.trim()) return res.status(400).json({ error: 'New bot token required' });

  const token = newBotToken.trim();

  console.log(`\n[Change Bot Token] User \( {req.user.email} attempting to change to: \){token.substring(0, 10)}...${token.slice(-4)}`);

  const inUse = await isBotTokenInUse(token, req.user.id);
  if (inUse) {
    console.log(`[Change Bot Token] Token already in use by another account`);
    return res.status(409).json({ error: 'Bot already in use by another account' });
  }

  const url = `https://api.telegram.org/bot${token}/getMe`;
  console.log(`[Change Bot Token] Fetching: ${url}`);

  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(10000) });

    console.log(`[Change Bot Token] Response status: \( {response.status} \){response.statusText}`);

    if (!response.ok) {
      let errorBody = '';
      try {
        const errorData = await response.json();
        errorBody = JSON.stringify(errorData);
      } catch (_) {
        errorBody = await response.text();
      }
      console.log(`[Change Bot Token] Telegram API error: ${errorBody}`);
      return res.status(400).json({ error: 'Invalid bot token' });
    }

    const data = await response.json();
    console.log(`[Change Bot Token] Success! New bot username: @${data.result.username}`);

    const botUsername = data.result.username.replace(/^@/, '');

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
    console.error('[Change Bot Token] Failed to validate new token:');
    console.error('   Message:', err.message);
    if (err.cause) console.error('   Cause:', err.cause);
    if (err.name) console.error('   Name:', err.name);
    console.error('   Stack:', err.stack);
    res.status(500).json({ error: 'Failed to validate new token (network issue)' });
  }
});

// ==================== REST OF THE CODE (UNCHANGED) ====================
// All other routes (subscribe validation, broadcasting, admin, etc.) remain exactly as in the previous version.

// Startup logs
mongoose.connection.once('open', async () => {
  await loadAdminSettings();
  const usersWithBots = await User.find({ telegramBotToken: { $exists: true, $ne: null } });
  for (const user of usersWithBots) {
    launchUserBot(user);
  }
  console.log('Launched ' + usersWithBots.length + ' bots in pure webhook mode');
});

app.use((req, res) => {
  res.status(404).render('404');
});

app.listen(PORT, () => {
  console.log('\nSENDEM SERVER — WITH DETAILED TELEGRAM VALIDATION LOGGING');
  console.log('Server running on port ' + PORT + ' | Domain: https://' + DOMAIN + '\n');
});
