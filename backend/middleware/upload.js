const multer = require('multer');

// Use memory storage for Cloudinary uploads (buffer-based)
const storage = multer.memoryStorage();
const MAX_UPLOAD_SIZE_MB = 20;
const MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024;

// File filter: only allow image files
const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/') || file.mimetype === 'application/pdf') {
    cb(null, true);
  } else {
    cb(new Error('Only image files and PDFs are allowed!'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: MAX_UPLOAD_SIZE_BYTES, // 20MB per file
  },
});

module.exports = upload;
