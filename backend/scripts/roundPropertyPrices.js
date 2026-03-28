const dotenv = require('dotenv');
const mongoose = require('mongoose');
const connectDB = require('../config/db');
const Property = require('../models/Property');

dotenv.config({ override: process.env.NODE_ENV !== 'production' });

const ROUND_STEP = Number(process.env.PROPERTY_PRICE_ROUND_STEP || 500_000_000);

const formatVnd = (value) => Number(value || 0).toLocaleString('vi-VN');

const normalizePrice = (price) => {
  const numeric = Number(price);
  if (!Number.isFinite(numeric) || numeric < 0) return null;
  return Math.round(numeric / ROUND_STEP) * ROUND_STEP;
};

const run = async () => {
  if (!Number.isFinite(ROUND_STEP) || ROUND_STEP <= 0) {
    throw new Error('PROPERTY_PRICE_ROUND_STEP must be a positive number');
  }

  await connectDB();

  const properties = await Property.find({}, { _id: 1, price: 1 }).lean();
  if (!properties.length) {
    console.log('No properties found. Nothing to update.');
    return;
  }

  const bulkOps = [];
  let skipped = 0;
  let unchanged = 0;
  const samples = [];

  for (const property of properties) {
    const oldPrice = Number(property.price);
    const roundedPrice = normalizePrice(oldPrice);

    if (roundedPrice === null) {
      skipped += 1;
      continue;
    }

    if (oldPrice === roundedPrice) {
      unchanged += 1;
      continue;
    }

    bulkOps.push({
      updateOne: {
        filter: { _id: property._id },
        update: { $set: { price: roundedPrice } },
      },
    });

    if (samples.length < 10) {
      samples.push({
        id: String(property._id),
        from: oldPrice,
        to: roundedPrice,
      });
    }
  }

  let modified = 0;
  if (bulkOps.length > 0) {
    const result = await Property.bulkWrite(bulkOps, { ordered: false });
    modified = Number(result.modifiedCount || 0);
  }

  console.log(`Rounding step: ${formatVnd(ROUND_STEP)} VND`);
  console.log(`Total properties: ${properties.length}`);
  console.log(`Modified: ${modified}`);
  console.log(`Unchanged: ${unchanged}`);
  console.log(`Skipped: ${skipped}`);

  if (samples.length > 0) {
    console.log('Sample changes:');
    samples.forEach((sample, index) => {
      console.log(
        `${index + 1}. ${sample.id}: ${formatVnd(sample.from)} -> ${formatVnd(sample.to)}`
      );
    });
  }
};

run()
  .catch((error) => {
    console.error('Failed to round property prices:', error.message || error);
    process.exitCode = 1;
  })
  .finally(async () => {
    try {
      await mongoose.connection.close();
    } catch (error) {
      // Ignore close errors
    }
  });

