const mongoose = require('mongoose');

const propertySchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'A property must have a title'],
    trim: true,
  },
  description: {
    type: String,
    required: [true, 'A property must have a description'],
  },
  price: {
    type: Number,
    required: [true, 'A property must have a price'],
  },
  address: {
    type: String,
    required: [true, 'A property must have an address'],
  },
  location: {
    // GeoJSON
    type: {
      type: String,
      default: 'Point', 
      enum: ['Point'],
    },
    coordinates: [Number], // [longitude, latitude]
  },
  amenities: [String],
  images: [String], // Array of image URLs
  
  // Ownership Proof
  ownershipDocuments: [String], // URLs to Property Deeds, Utility Bills, etc.

  // Refactored to ownerId referencing a Provider
  ownerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'A property must belong to a Provider (Owner)'],
  },
  
  // Assigned Broker/Agent (Provider B)
  agentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  },

  type: {
    type: String,
    enum: ['apartment', 'house', 'villa', 'studio', 'office'],
    default: 'apartment',
  },
  bedrooms: Number,
  bathrooms: Number,
  area: Number, // sqft or sqm
  
  // Updated Status Enum including Moderation & Availability
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected', 'available', 'rented', 'sold'],
    default: 'pending',
  },
  
  rejectionReason: String, // Reason if status is rejected

  createdAt: {
    type: Date,
    default: Date.now,
  },
}, {
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Index for geo queries
propertySchema.index({ location: '2dsphere' });
propertySchema.index({ price: 1 });

module.exports = mongoose.model('Property', propertySchema);
