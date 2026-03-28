const mongoose = require('mongoose');

let listenersAttached = false;

const connectDB = async () => {
  const mongoUri = (process.env.MONGO_URI || '').trim();
  if (!mongoUri) {
    throw new Error('Database connection error: MONGO_URI is missing');
  }

  try {
    const conn = await mongoose.connect(mongoUri, {
      serverSelectionTimeoutMS: Number(process.env.DB_SERVER_SELECTION_TIMEOUT_MS || 10000),
    });

    if (!listenersAttached) {
      listenersAttached = true;
      mongoose.connection.on('disconnected', () => {
        console.error('[MongoDB] Disconnected from database.');
      });
      mongoose.connection.on('reconnected', () => {
        console.log('[MongoDB] Reconnected to database.');
      });
      mongoose.connection.on('error', (err) => {
        console.error('[MongoDB] Connection error:', err?.message || err);
      });
    }

    console.log(`MongoDB Connected: ${conn.connection.host}`);
    return conn;
  } catch (err) {
    throw new Error(`Database connection error: ${err.message}`);
  }
};

module.exports = connectDB;
