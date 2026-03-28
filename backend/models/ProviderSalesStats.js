const mongoose = require('mongoose');

const providerSalesStatsSchema = new mongoose.Schema(
  {
    providerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      unique: true,
      index: true,
    },
    totalSoldProperties: {
      type: Number,
      default: 0,
      min: 0,
    },
    totalSoldValue: {
      type: Number,
      default: 0,
      min: 0,
    },
    latestSoldAt: {
      type: Date,
      default: null,
    },
    soldPropertyIds: {
      type: [mongoose.Schema.Types.ObjectId],
      ref: 'Property',
      default: [],
    },
  },
  {
    timestamps: true,
  }
);

providerSalesStatsSchema.index({ providerId: 1, latestSoldAt: -1 });

module.exports = mongoose.model('ProviderSalesStats', providerSalesStatsSchema);

