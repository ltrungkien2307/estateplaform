const express = require('express');
const propertyController = require('../controllers/propertyController');
const authController = require('../controllers/authController');
const { verifyOwnership, verifyProviderStatus } = require('../middleware/permissions');
const upload = require('../middleware/upload');
const { validateProperty } = require('../middleware/validator');

const router = express.Router();

// Geo Search
router.route('/properties-within/:distance/center/:latlng/unit/:unit')
  .get(propertyController.getPropertiesWithin);

// Recommendations
router.get('/:id/recommendations', propertyController.getRecommendations);

router
  .route('/')
  .get(propertyController.getAllProperties)
  .post(
    authController.protect,
    authController.restrictTo('admin', 'provider'), // Updated role
    verifyProviderStatus, // Ensure provider is verified
    upload.fields([{ name: 'images', maxCount: 10 }, { name: 'ownershipDocuments', maxCount: 5 }]), // Allow Multiple Files
    validateProperty,
    propertyController.createProperty
  );

router
  .route('/:id')
  .get(propertyController.getProperty)
  .patch(
    authController.protect,
    authController.restrictTo('admin', 'provider'), // Updated role
    verifyOwnership, // Ensure user owns the property
    upload.fields([{ name: 'images', maxCount: 10 }]), // Updates usually just images
    propertyController.updateProperty
  )
  .delete(
    authController.protect,
    authController.restrictTo('admin', 'provider'), // Updated role
    verifyOwnership, // Ensure user owns the property
    propertyController.deleteProperty
  );

module.exports = router;
