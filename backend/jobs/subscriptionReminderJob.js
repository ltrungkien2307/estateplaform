const crypto = require('crypto');
const cron = require('node-cron');
const Message = require('../models/Message');
const Subscription = require('../models/Subscription');
const User = require('../models/User');
const { emitToUser } = require('../services/socketService');

const DAY_IN_MS = 24 * 60 * 60 * 1000;
const REMINDER_DAYS = Number(process.env.SUBSCRIPTION_REMINDER_DAYS || 7);
const REMINDER_CRON = process.env.SUBSCRIPTION_REMINDER_CRON || '0 9 * * *';
const BOT_NAME = process.env.SUBSCRIPTION_BOT_NAME || 'Subcription';
const BOT_EMAIL = String(process.env.SUBSCRIPTION_BOT_EMAIL || 'subscription@estatemanager.local').trim();
const BOT_PASSWORD =
  process.env.SUBSCRIPTION_BOT_PASSWORD || `SubBot@${crypto.randomBytes(8).toString('hex')}`;
const BOT_ADDRESS = process.env.SUBSCRIPTION_BOT_ADDRESS || 'System Automation';
const BOT_PHONE = process.env.SUBSCRIPTION_BOT_PHONE || '';

let reminderTask = null;
let isRunning = false;

const getConversationId = (userA, userB) =>
  [String(userA), String(userB)].sort().join(':');

const formatExpiryDate = (value) => {
  const date = value ? new Date(value) : null;
  if (!date || Number.isNaN(date.getTime())) return 'N/A';
  return date.toLocaleDateString('vi-VN', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
  });
};

const serializeUser = (user) => ({
  _id: String(user._id),
  name: user.name || '',
  avatar: user.avatar || '',
  role: user.role || 'admin',
});

const serializeMessage = (message, sender, receiver) => ({
  _id: String(message._id),
  conversationId: message.conversationId,
  senderId: String(message.senderId),
  receiverId: String(message.receiverId),
  sender: serializeUser(sender),
  receiver: serializeUser(receiver),
  messageType: message.messageType || 'text',
  content: message.content || '',
  imageUrl: message.imageUrl || '',
  propertySnapshot: null,
  isRead: Boolean(message.isRead),
  readAt: message.readAt || null,
  createdAt: message.createdAt,
  updatedAt: message.updatedAt,
});

const ensureSubscriptionBotAdmin = async () => {
  let bot = await User.findOne({ email: BOT_EMAIL });
  if (!bot) {
    bot = await User.create({
      name: BOT_NAME,
      email: BOT_EMAIL,
      password: BOT_PASSWORD,
      role: 'admin',
      address: BOT_ADDRESS,
      phone: BOT_PHONE,
      isVerified: true,
      kycStatus: 'verified',
    });
    console.log(`[Subscription Reminder] Created admin account "${BOT_NAME}" (${BOT_EMAIL}).`);
    return bot;
  }

  let changed = false;
  if (bot.name !== BOT_NAME) {
    bot.name = BOT_NAME;
    changed = true;
  }
  if (bot.role !== 'admin') {
    bot.role = 'admin';
    changed = true;
  }
  if (!String(bot.address || '').trim()) {
    bot.address = BOT_ADDRESS;
    changed = true;
  }
  if (changed) {
    await bot.save({ validateBeforeSave: false });
  }

  return bot;
};

const countUnread = (receiverId) =>
  Message.countDocuments({
    receiverId,
    isRead: false,
  });

const runSubscriptionReminder = async () => {
  if (isRunning) return;
  isRunning = true;

  try {
    const bot = await ensureSubscriptionBotAdmin();
    const now = new Date();
    const startOfToday = new Date(now);
    startOfToday.setHours(0, 0, 0, 0);
    const targetStart = new Date(startOfToday.getTime() + REMINDER_DAYS * DAY_IN_MS);
    const targetEnd = new Date(targetStart.getTime() + DAY_IN_MS);

    const subscriptions = await Subscription.find({
      status: 'active',
      expiresAt: { $gte: targetStart, $lt: targetEnd },
      $or: [
        { reminder7DaysSentAt: { $exists: false } },
        { reminder7DaysSentAt: null },
      ],
    }).sort({ expiresAt: 1 });

    if (!subscriptions.length) {
      return;
    }

    const userIds = Array.from(
      new Set(subscriptions.map((subscription) => String(subscription.userId || '')).filter(Boolean))
    );

    const users = await User.find({ _id: { $in: userIds } }).select('_id name avatar role');
    const userMap = new Map(users.map((user) => [String(user._id), user]));

    let sentCount = 0;
    for (const subscription of subscriptions) {
      const receiver = userMap.get(String(subscription.userId || ''));
      if (!receiver || receiver.role === 'admin') {
        subscription.reminder7DaysSentAt = new Date();
        await subscription.save({ validateBeforeSave: false });
        continue;
      }

      const conversationId = getConversationId(bot._id, receiver._id);
      const content =
        `Gói ${subscription.planType} của bạn sẽ hết hạn sau ${REMINDER_DAYS} ngày ` +
        `(ngày hết hạn: ${formatExpiryDate(subscription.expiresAt)}). ` +
        'Vui lòng gia hạn sớm để tránh gián đoạn quyền đăng tin và các tính năng nâng cao.';

      const message = await Message.create({
        conversationId,
        participants: [bot._id, receiver._id],
        senderId: bot._id,
        receiverId: receiver._id,
        content,
        isRead: false,
        readAt: null,
      });

      subscription.reminder7DaysSentAt = new Date();
      await subscription.save({ validateBeforeSave: false });

      const serializedMessage = serializeMessage(message, bot, receiver);
      emitToUser(receiver._id, 'message:new', {
        status: 'success',
        data: {
          message: serializedMessage,
          conversation: {
            conversationId,
            participant: serializeUser(bot),
            unreadCount: 1,
            updatedAt: message.createdAt,
            lastMessage: serializedMessage,
          },
        },
      });

      const unreadCount = await countUnread(receiver._id);
      emitToUser(receiver._id, 'message:unread_count', {
        status: 'success',
        data: { unreadCount },
      });

      sentCount += 1;
    }

    if (sentCount > 0) {
      console.log(`[Subscription Reminder] Sent ${sentCount} reminder message(s).`);
    }
  } catch (error) {
    console.error('[Subscription Reminder] Failed to send reminders:', error);
  } finally {
    isRunning = false;
  }
};

const startSubscriptionReminderJob = () => {
  if (reminderTask) {
    return reminderTask;
  }

  reminderTask = cron.schedule(REMINDER_CRON, runSubscriptionReminder, {
    scheduled: true,
  });

  console.log(
    `[Subscription Reminder] Scheduler started with cron "${REMINDER_CRON}" for ${REMINDER_DAYS}-day reminders.`
  );

  // Run once on startup to avoid waiting until the next cron tick.
  runSubscriptionReminder().catch((error) => {
    console.error('[Subscription Reminder] Initial run failed:', error);
  });

  return reminderTask;
};

module.exports = {
  startSubscriptionReminderJob,
  runSubscriptionReminder,
};
