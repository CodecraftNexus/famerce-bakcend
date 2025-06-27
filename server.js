const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Environment variable to choose storage type
const USE_CLOUDINARY = process.env.USE_CLOUDINARY === 'true';

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

mongoose.connection.on('connected', () => {
  console.log('✅ Connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB connection error:', err);
});

// Enhanced CORS Configuration
app.use(cors({
  origin: [
    'http://localhost:3000', 
    'http://localhost:3001', 
    'http://localhost:5173',
    'https://farmersferts.com',
    'https://www.farmersferts.com',
    'https://api.farmersferts.com',
    process.env.FRONTEND_URL
  ].filter(Boolean),
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie'],
}));

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());

// Trust proxy for production
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

// Local Storage Setup
const uploadsDir = path.join(__dirname, 'uploads');
if (!USE_CLOUDINARY && !fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  fs.mkdirSync(path.join(uploadsDir, 'products'), { recursive: true });
  fs.mkdirSync(path.join(uploadsDir, 'documents'), { recursive: true });
}

// Serve static files for local storage
if (!USE_CLOUDINARY) {
  app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
}

// FIXED Cloudinary Configuration
if (USE_CLOUDINARY) {
  // Validate required environment variables
  if (!process.env.CLOUDINARY_CLOUD_NAME || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) {
    console.error('❌ Missing required Cloudinary environment variables');
    console.error('Required: CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET');
    console.error('Current values:');
    console.error('- CLOUDINARY_CLOUD_NAME:', process.env.CLOUDINARY_CLOUD_NAME ? 'Set' : 'Missing');
    console.error('- CLOUDINARY_API_KEY:', process.env.CLOUDINARY_API_KEY ? 'Set' : 'Missing');
    console.error('- CLOUDINARY_API_SECRET:', process.env.CLOUDINARY_API_SECRET ? 'Set' : 'Missing');
    process.exit(1);
  }

  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
    secure: true // Always use HTTPS
  });

  // Test the configuration
  cloudinary.api.ping()
    .then(() => {
      console.log('🔗 Cloudinary storage configured and tested successfully');
      console.log(`📁 Cloud name: ${process.env.CLOUDINARY_CLOUD_NAME}`);
    })
    .catch((error) => {
      console.error('❌ Cloudinary configuration test failed:', error.message);
      console.error('Please check your Cloudinary credentials in .env file');
    });
} else {
  console.log('💾 Local file storage configured');
}

// ENHANCED Multer Configuration with Better Error Handling
const createMulterUpload = () => {
  if (USE_CLOUDINARY) {
    return multer({
      storage: multer.memoryStorage(),
      limits: { 
        fileSize: 50 * 1024 * 1024, // 50MB
        files: 50, // Max 50 files total
        fields: 20, // Max 20 non-file fields
        fieldSize: 50 * 1024 * 1024, // 50MB per field
        fieldNameSize: 200, // Max field name length
        headerPairs: 2000 // Max header pairs
      },
      fileFilter: function (req, file, cb) {
        console.log('🔍 File filter check:', {
          fieldname: file.fieldname,
          mimetype: file.mimetype,
          originalname: file.originalname
        });

        // Image files
        if (file.fieldname === 'image') {
          if (file.mimetype.startsWith('image/')) {
            cb(null, true);
          } else {
            cb(new Error(`Invalid image file type: ${file.mimetype}. Only image files are allowed.`));
          }
        } 
        // Document files - support both array and single file formats
        else if (['npsApprovalFiles', 'msdsFiles', 'certificationsFiles'].includes(file.fieldname) ||
                 file.fieldname.endsWith('[]')) { // Support array notation
          const allowedTypes = [
            'application/pdf', 
            'application/msword', 
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'text/plain'
          ];
          if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
          } else {
            cb(new Error(`Invalid document file type: ${file.mimetype}. Only PDF, DOC, DOCX, and TXT files are allowed.`));
          }
        } else {
          console.warn('⚠️ Unknown field:', file.fieldname);
          // Instead of rejecting, log and accept to prevent unexpected field errors
          cb(null, true);
        }
      }
    });
  } else {
    // Local storage configuration
    const storage = multer.diskStorage({
      destination: function (req, file, cb) {
        let uploadPath = 'uploads/';
        
        if (file.fieldname === 'image') {
          uploadPath += 'products/';
        } else {
          uploadPath += 'documents/';
        }
        
        cb(null, uploadPath);
      },
      filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
      }
    });

    return multer({ 
      storage: storage,
      limits: {
        fileSize: 50 * 1024 * 1024, // 50MB limit
        files: 50,
        fields: 20,
        fieldSize: 50 * 1024 * 1024,
        fieldNameSize: 200,
        headerPairs: 2000
      },
      fileFilter: function (req, file, cb) {
        if (file.fieldname === 'image') {
          if (file.mimetype.startsWith('image/')) {
            cb(null, true);
          } else {
            cb(new Error('Only image files are allowed for product images'));
          }
        } else {
          const allowedTypes = [
            'application/pdf', 
            'application/msword', 
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
          ];
          if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
          } else {
            cb(new Error('Only PDF, DOC, and DOCX files are allowed for documents'));
          }
        }
      }
    });
  }
};

// Create upload instance
const upload = createMulterUpload();

// FIXED: More flexible field configuration for both create and update routes
const uploadFields = upload.fields([
  { name: 'image', maxCount: 1 },
  { name: 'npsApprovalFiles', maxCount: 10 },
  { name: 'msdsFiles', maxCount: 10 },
  { name: 'certificationsFiles', maxCount: 10 },
  // Support array notation as well
  { name: 'npsApprovalFiles[]', maxCount: 10 },
  { name: 'msdsFiles[]', maxCount: 10 },
  { name: 'certificationsFiles[]', maxCount: 10 }
]);



// Enhanced Schemas
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 50
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  role: {
    type: String,
    default: 'admin',
    enum: ['admin', 'user', 'manager']
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastLogin: {
    type: Date
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

const User = mongoose.model('User', userSchema);

// ENHANCED Product Schema with Dynamic Lists Support
const productSchema = new mongoose.Schema({
  productId: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    index: true
  },
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 200
  },
  shortDescription: {
    type: String,
    maxlength: 500
  },
  fullDescription: {
    type: String,
    maxlength: 2000
  },
  imagePath: String,
  npsApproval: String,
  msds: String,
  composition: {
    title: { type: String, default: "Composition" },
    ingredients: [{
      name: { type: String, required: true },
      percentage: { type: String, required: true }
    }],
    advantages: [String]
  },
  application: {
    title: { type: String, default: "Application Details" },
    instructions: [String], // ENHANCED: Changed from String to Array for dynamic lists
    recommendedCrops: [String]
  },
  safety: {
    title: { type: String, default: "Safety Instructions" },
    ppe: {
      title: { type: String, default: "Personal Protective Equipment (PPE)" },
      instructions: [String]
    },
    hygiene: {
      title: { type: String, default: "Work Hygienic Practices" },
      instructions: [String]
    }
  },
  certifications: {
    title: { type: String, default: "Certifications" },
    qualityStandards: String
  },
  contact: {
    title: { type: String, default: "Contact Details" },
    address: String,
    phones: [String],
    email: String,
    website: String
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Create indexes for better performance
productSchema.index({ productId: 1 });
productSchema.index({ name: 'text', shortDescription: 'text' });

productSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

const Product = mongoose.model('Product', productSchema);


const batchSchema = new mongoose.Schema({
  batchId: {
    type: String,
    unique: true,
    uppercase: true,
    index: true
  },
  productId: {
    type: String,
    required: true,
    ref: 'Product',
    index: true
  },
  number: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  sampleNo: {
    type: String,
    trim: true,
    maxlength: 100
  },
  manufacturingDate: {
    type: Date,
    validate: {
      validator: function(v) {
        return !v || v <= new Date();
      },
      message: 'Manufacturing date cannot be in the future'
    }
  },
  expiryDate: {
    type: Date,
    validate: {
      validator: function(v) {
        if (!v || !this.manufacturingDate) return true;
        return v > this.manufacturingDate;
      },
      message: 'Expiry date must be after manufacturing date'
    }
  },
  availablePackageSizes: [String],
  isExpired: {
    type: Boolean,
    default: false
  },
  isActive: {
    type: Boolean,
    default: true
  },
  notes: {
    type: String,
    maxlength: 1000
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Create compound index for better performance
batchSchema.index({ productId: 1, number: 1 }, { unique: true });
batchSchema.index({ batchId: 1 });
batchSchema.index({ expiryDate: 1 });

// Enhanced batch ID generation
async function generateShortBatchId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let attempts = 0;
  const maxAttempts = 10;
  
  while (attempts < maxAttempts) {
    let batchId = '';
    for (let i = 0; i < 8; i++) {
      batchId += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    
    const existingBatch = await Batch.findOne({ batchId: batchId });
    if (!existingBatch) {
      return batchId;
    }
    
    attempts++;
  }
  
  // Fallback with timestamp
  const timestamp = Date.now().toString(36).toUpperCase();
  return 'B' + timestamp;
}

// Enhanced pre-save middleware for batches
batchSchema.pre('save', async function(next) {
  this.updatedAt = Date.now();
  
  if (this.isNew && !this.batchId) {
    try {
      this.batchId = await generateShortBatchId();
    } catch (error) {
      return next(error);
    }
  }
  
  // Auto-calculate expiry status
  if (this.expiryDate) {
    this.isExpired = new Date() > new Date(this.expiryDate);
  }
  
  next();
});

// Virtual for expiry status
batchSchema.virtual('expired').get(function() {
  if (!this.expiryDate) return false;
  return new Date() > new Date(this.expiryDate);
});

batchSchema.virtual('daysUntilExpiry').get(function() {
  if (!this.expiryDate) return null;
  const today = new Date();
  const expiry = new Date(this.expiryDate);
  const diffTime = expiry - today;
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
});

const Batch = mongoose.model('Batch', batchSchema);

// Enhanced JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'farmers-fert-secret-key-' + Date.now();

// Enhanced authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = req.cookies.token || (authHeader && authHeader.split(' ')[1]);

  if (!token) {
    return res.status(401).json({ 
      success: false, 
      message: 'Access token required' 
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error:', err);
      return res.status(403).json({ 
        success: false, 
        message: 'Invalid or expired token' 
      });
    }
    req.user = user;
    next();
  });
};

// ENHANCED Data Processing Helper Functions
const processProductData = (productData) => {
  console.log('🔄 Processing product data:', {
    name: productData.name,
    hasComposition: !!productData.composition,
    hasApplication: !!productData.application,
    hasSafety: !!productData.safety
  });
  
  // Ensure arrays are properly formatted
  if (productData.composition) {
    // Process ingredients array
    if (productData.composition.ingredients && Array.isArray(productData.composition.ingredients)) {
      productData.composition.ingredients = productData.composition.ingredients.filter(ing => 
        ing.name && ing.percentage && ing.name.trim() && ing.percentage.trim()
      );
      console.log('✅ Processed ingredients:', productData.composition.ingredients.length);
    }
    
    // Process advantages array
    if (productData.composition.advantages && Array.isArray(productData.composition.advantages)) {
      productData.composition.advantages = productData.composition.advantages.filter(adv => 
        adv && adv.trim()
      );
      console.log('✅ Processed advantages:', productData.composition.advantages.length);
    }
  }
  
  if (productData.application) {
    // Process instructions array - ENHANCED
    if (productData.application.instructions && Array.isArray(productData.application.instructions)) {
      productData.application.instructions = productData.application.instructions.filter(inst => 
        inst && inst.trim()
      );
      console.log('✅ Processed instructions:', productData.application.instructions.length);
    }
    
    // Process recommended crops array
    if (productData.application.recommendedCrops && Array.isArray(productData.application.recommendedCrops)) {
      productData.application.recommendedCrops = productData.application.recommendedCrops.filter(crop => 
        crop && crop.trim()
      );
      console.log('✅ Processed crops:', productData.application.recommendedCrops.length);
    }
  }
  
  if (productData.safety) {
    // Process PPE instructions
    if (productData.safety.ppe && productData.safety.ppe.instructions && Array.isArray(productData.safety.ppe.instructions)) {
      productData.safety.ppe.instructions = productData.safety.ppe.instructions.filter(inst => 
        inst && inst.trim()
      );
      console.log('✅ Processed PPE instructions:', productData.safety.ppe.instructions.length);
    }
    
    // Process hygiene instructions
    if (productData.safety.hygiene && productData.safety.hygiene.instructions && Array.isArray(productData.safety.hygiene.instructions)) {
      productData.safety.hygiene.instructions = productData.safety.hygiene.instructions.filter(inst => 
        inst && inst.trim()
      );
      console.log('✅ Processed hygiene instructions:', productData.safety.hygiene.instructions.length);
    }
  }
  
  if (productData.contact) {
    // Process phone numbers array
    if (productData.contact.phones && Array.isArray(productData.contact.phones)) {
      productData.contact.phones = productData.contact.phones.filter(phone => 
        phone && phone.trim()
      );
      console.log('✅ Processed phone numbers:', productData.contact.phones.length);
    }
  }
  
  return productData;
};

// Enhanced validation helper
const validateProductData = (productData) => {
  const errors = [];
  
  if (!productData.name || !productData.name.trim()) {
    errors.push('Product name is required');
  }
  
  // Validate ingredients format
  if (productData.composition && productData.composition.ingredients) {
    productData.composition.ingredients.forEach((ingredient, index) => {
      if (!ingredient.name || !ingredient.percentage) {
        errors.push(`Ingredient ${index + 1}: Both name and percentage are required`);
      }
    });
  }
  
  // Validate email format if provided
  if (productData.contact && productData.contact.email && productData.contact.email.trim()) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(productData.contact.email.trim())) {
      errors.push('Invalid email format');
    }
  }
  
  return errors;
};

// FIXED File Upload Handler for Cloudinary
const handleFileUpload = async (file, type = 'document') => {
  if (!USE_CLOUDINARY) {
    throw new Error('Cloudinary upload called but not configured');
  }

  console.log(`📤 Starting ${type} upload for file:`, file.originalname);

  return new Promise((resolve, reject) => {
    // FIXED: Use proper folder structure without hardcoded cloud name
    const uploadOptions = {
      folder: type === 'image' ? 'products' : 'documents', // Removed hardcoded cloud name
      resource_type: type === 'image' ? 'image' : 'raw',
      use_filename: true,
      unique_filename: true,
      timeout: 60000, // 60 second timeout
    };

    if (type === 'image') {
      uploadOptions.transformation = [
        { width: 1200, height: 900, crop: 'limit', quality: 'auto:good' }
      ];
    }

    console.log('Upload options:', uploadOptions);

    const uploadStream = cloudinary.uploader.upload_stream(
      uploadOptions,
      (error, result) => {
        if (error) {
          console.error('❌ Cloudinary upload error:', error);
          reject(new Error(`Cloudinary upload failed: ${error.message}`));
        } else {
          console.log('✅ Cloudinary upload success:', result.secure_url);
          resolve(result.secure_url);
        }
      }
    );

    // Handle stream errors
    uploadStream.on('error', (error) => {
      console.error('❌ Upload stream error:', error);
      reject(new Error(`Upload stream failed: ${error.message}`));
    });

    uploadStream.end(file.buffer);
  });
};

// Enhanced admin initialization
const initializeAdmin = async () => {
  try {
    const adminExists = await User.findOne({ username: 'admin' });
    if (!adminExists) {
      const admin = new User({
        username: 'admin',
        password: 'admin123',
        role: 'admin'
      });
      await admin.save();
      console.log('✅ Default admin user created: username=admin, password=admin123');
    } else {
      console.log('✅ Admin user already exists');
    }
  } catch (error) {
    console.error('❌ Error creating admin user:', error);
  }
};

// Enhanced migration function
const updateExistingBatches = async () => {
  try {
    const batches = await Batch.find({ 
      $or: [
        { batchId: { $exists: false } },
        { batchId: null },
        { batchId: '' }
      ]
    });
    
    if (batches.length > 0) {
      console.log(`🔄 Found ${batches.length} batches without batchId. Updating...`);
      
      for (let batch of batches) {
        try {
          if (!batch.batchId) {
            batch.batchId = await generateShortBatchId();
          }
          
          await batch.save();
          console.log(`✅ Updated batch ${batch.number} with batchId: ${batch.batchId}`);
        } catch (batchError) {
          console.error(`❌ Error updating batch ${batch.number}:`, batchError.message);
          continue;
        }
      }
      
      console.log(`✅ Successfully updated ${batches.length} existing batches`);
    } else {
      console.log('✅ All batches have valid batchId');
    }
  } catch (error) {
    console.error('❌ Error in updateExistingBatches:', error);
  }
};

// ENHANCED ERROR HANDLING - Add this before other routes
app.use((error, req, res, next) => {
  console.error('🚨 Error caught by middleware:', {
    name: error.name,
    message: error.message,
    code: error.code,
    field: error.field,
    url: req.url,
    method: req.method
  });

  // Handle multer errors specifically
  if (error instanceof multer.MulterError) {
    console.error('📁 Multer error details:', error);
    
    switch (error.code) {
      case 'LIMIT_FILE_SIZE':
        return res.status(400).json({ 
          success: false, 
          message: 'File too large. Maximum size is 50MB per file.',
          errorCode: 'FILE_TOO_LARGE'
        });
      
      case 'LIMIT_FILE_COUNT':
        return res.status(400).json({ 
          success: false, 
          message: 'Too many files uploaded. Maximum 10 files per field.',
          errorCode: 'TOO_MANY_FILES'
        });
      
      case 'LIMIT_UNEXPECTED_FILE':
        console.error('🚨 Unexpected field error:', {
          field: error.field,
          expectedFields: ['image', 'npsApprovalFiles', 'msdsFiles', 'certificationsFiles']
        });
        return res.status(400).json({ 
          success: false, 
          message: `Unexpected file field: ${error.field}. Please make sure you're using the correct file input names.`,
          errorCode: 'UNEXPECTED_FIELD',
          details: {
            field: error.field,
            expectedFields: ['image', 'npsApprovalFiles', 'msdsFiles', 'certificationsFiles']
          }
        });
      
      case 'LIMIT_PART_COUNT':
        return res.status(400).json({ 
          success: false, 
          message: 'Too many form parts. Please reduce the number of form fields.',
          errorCode: 'TOO_MANY_PARTS'
        });
      
      case 'LIMIT_FIELD_KEY':
        return res.status(400).json({ 
          success: false, 
          message: 'Field name too long.',
          errorCode: 'FIELD_NAME_TOO_LONG'
        });
      
      case 'LIMIT_FIELD_VALUE':
        return res.status(400).json({ 
          success: false, 
          message: 'Field value too long.',
          errorCode: 'FIELD_VALUE_TOO_LONG'
        });
      
      case 'LIMIT_FIELD_COUNT':
        return res.status(400).json({ 
          success: false, 
          message: 'Too many fields in form.',
          errorCode: 'TOO_MANY_FIELDS'
        });
      
      default:
        return res.status(400).json({ 
          success: false, 
          message: `File upload error: ${error.message}`,
          errorCode: 'UPLOAD_ERROR'
        });
    }
  }

  // Handle file filter errors
  if (error.message && error.message.includes('Invalid') && error.message.includes('file type')) {
    return res.status(400).json({
      success: false,
      message: error.message,
      errorCode: 'INVALID_FILE_TYPE'
    });
  }

  // Handle JSON parsing errors
  if (error instanceof SyntaxError && error.message.includes('JSON')) {
    return res.status(400).json({
      success: false,
      message: 'Invalid JSON data in request',
      errorCode: 'INVALID_JSON'
    });
  }

  // Pass to next error handler
  next(error);
});

// Health check with detailed info
app.get('/health', async (req, res) => {
  try {
    const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
    const productCount = await Product.countDocuments();
    const batchCount = await Batch.countDocuments();
    
    res.json({ 
      status: 'OK', 
      timestamp: new Date().toISOString(),
      database: {
        status: dbStatus,
        products: productCount,
        batches: batchCount
      },
      storage: USE_CLOUDINARY ? 'cloudinary' : 'local',
      cloudinary: USE_CLOUDINARY ? (process.env.CLOUDINARY_CLOUD_NAME ? 'configured' : 'not configured') : 'disabled',
      environment: process.env.NODE_ENV || 'development'
    });
  } catch (error) {
    res.status(500).json({
      status: 'ERROR',
      message: error.message
    });
  }
});

// Debug route to test file uploads
app.post('/api/debug/upload', authenticateToken, uploadFields, (req, res) => {
  try {
    console.log('🧪 Debug upload test');
    console.log('📁 Received files:', req.files);
    console.log('📝 Received body:', Object.keys(req.body));
    
    const fileInfo = {};
    
    if (req.files) {
      Object.keys(req.files).forEach(fieldName => {
        fileInfo[fieldName] = req.files[fieldName].map(file => ({
          originalname: file.originalname,
          mimetype: file.mimetype,
          size: file.size,
          fieldname: file.fieldname
        }));
      });
    }
    
    res.json({
      success: true,
      message: 'Debug upload successful',
      files: fileInfo,
      body: req.body,
      multerConfig: {
        storageType: USE_CLOUDINARY ? 'cloudinary' : 'local',
        limits: {
          fileSize: '50MB',
          files: 'Multiple per field'
        }
      }
    });
  } catch (error) {
    console.error('🧪 Debug upload error:', error);
    res.status(500).json({
      success: false,
      message: 'Debug upload failed',
      error: error.message
    });
  }
});

// Enhanced Authentication Routes
app.post('/signin', async (req, res) => {
  try {
    const { username, password, rememberMe } = req.body;

    // Validation
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Username and password are required' 
      });
    }

    // Find user
    const user = await User.findOne({ 
      username: username.trim(), 
      isActive: true 
    });
    
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid username or password' 
      });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid username or password' 
      });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate token
    const token = jwt.sign(
      { 
        userId: user._id, 
        username: user.username, 
        role: user.role 
      }, 
      JWT_SECRET, 
      { expiresIn: rememberMe ? '30d' : '24h' }
    );

    // Set cookie
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000
    };

    res.cookie('token', token, cookieOptions);

    res.json({
      success: true,
      message: 'Login successful',
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
        lastLogin: user.lastLogin
      },
      token
    });
  } catch (error) {
    console.error('Signin error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
});

app.post('/signout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  });
  res.json({ success: true, message: 'Logout successful' });
});

app.get('/auth/check', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user || !user.isActive) {
      return res.status(401).json({ authenticated: false });
    }

    res.json({
      authenticated: true,
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
        lastLogin: user.lastLogin
      }
    });
  } catch (error) {
    console.error('Auth check error:', error);
    res.status(500).json({ authenticated: false });
  }
});


// Enhanced Product Routes
app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 50, search = '' } = req.query;
    
    let query = { isActive: true };
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { productId: { $regex: search, $options: 'i' } },
        { shortDescription: { $regex: search, $options: 'i' } }
      ];
    }
    
    const products = await Product.find(query)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);
    
    const productsWithBatches = await Promise.all(
      products.map(async (product) => {
        const batches = await Batch.find({ 
          productId: product.productId, 
          isActive: true 
        }).sort({ createdAt: -1 });
        
        const now = new Date();
        const summary = {
          activeBatches: 0,
          expiredBatches: 0,
          expiringSoon: 0
        };

        batches.forEach(batch => {
          if (batch.isExpired || (batch.expiryDate && new Date(batch.expiryDate) <= now)) {
            summary.expiredBatches++;
          } else if (batch.expiryDate) {
            const daysUntilExpiry = Math.ceil((new Date(batch.expiryDate) - now) / (1000 * 60 * 60 * 24));
            if (daysUntilExpiry <= 30) {
              summary.expiringSoon++;
            } else {
              summary.activeBatches++;
            }
          } else {
            summary.activeBatches++;
          }
        });

        return {
          ...product.toJSON(),
          batches,
          summary
        };
      })
    );

    const total = await Product.countDocuments(query);

    res.json({
      success: true,
      products: productsWithBatches,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get products error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch products',
      error: error.message 
    });
  }
});

// ENHANCED Product Creation Route
app.post('/api/products', authenticateToken, uploadFields, async (req, res) => {
  try {
    console.log('🆕 Creating new product...');
    console.log('📁 Received files:', req.files);
    console.log('📝 Received body keys:', Object.keys(req.body));
    
    let productData;
    try {
      productData = JSON.parse(req.body.productData);
      console.log('✅ Parsed product data successfully');
    } catch (parseError) {
      console.error('❌ JSON parse error:', parseError);
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid product data format',
        error: parseError.message
      });
    }
    
    // Validate required fields
    if (!productData.productId || !productData.name) {
      return res.status(400).json({ 
        success: false, 
        message: 'Product ID and name are required' 
      });
    }

    // Check for existing product
    const existingProduct = await Product.findOne({ productId: productData.productId });
    if (existingProduct) {
      return res.status(400).json({ 
        success: false, 
        message: 'Product ID already exists' 
      });
    }

    // Process and validate product data
    productData = processProductData(productData);
    const validationErrors = validateProductData(productData);
    
    if (validationErrors.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: validationErrors
      });
    }

    // Handle file uploads
    if (USE_CLOUDINARY) {
      console.log('🔗 Using Cloudinary for file uploads');
      
      // Upload image
      if (req.files && req.files.image && req.files.image[0]) {
        try {
          console.log('📸 Uploading image to Cloudinary...');
          const imageUrl = await handleFileUpload(req.files.image[0], 'image');
          productData.imagePath = imageUrl;
          console.log('✅ Image uploaded successfully:', imageUrl);
        } catch (error) {
          console.error('❌ Image upload error:', error);
          return res.status(500).json({
            success: false,
            message: 'Failed to upload image: ' + error.message
          });
        }
      }

      // Upload NPS approval files
      if (req.files && req.files.npsApprovalFiles && req.files.npsApprovalFiles.length > 0) {
        try {
          console.log('📄 Uploading NPS approval files...');
          const npsUrls = [];
          for (const file of req.files.npsApprovalFiles) {
            const url = await handleFileUpload(file, 'documents');
            npsUrls.push(url);
          }
          productData.npsApproval = npsUrls.join(', ');
          console.log('✅ NPS files uploaded successfully:', npsUrls);
        } catch (error) {
          console.error('❌ NPS files upload error:', error);
          return res.status(500).json({
            success: false,
            message: 'Failed to upload NPS approval files: ' + error.message
          });
        }
      }

      // Upload MSDS files
      if (req.files && req.files.msdsFiles && req.files.msdsFiles.length > 0) {
        try {
          console.log('📄 Uploading MSDS files...');
          const msdsUrls = [];
          for (const file of req.files.msdsFiles) {
            const url = await handleFileUpload(file, 'documents');
            msdsUrls.push(url);
          }
          productData.msds = msdsUrls.join(', ');
          console.log('✅ MSDS files uploaded successfully:', msdsUrls);
        } catch (error) {
          console.error('❌ MSDS files upload error:', error);
          return res.status(500).json({
            success: false,
            message: 'Failed to upload MSDS files: ' + error.message
          });
        }
      }

      // Upload certification files
      if (req.files && req.files.certificationsFiles && req.files.certificationsFiles.length > 0) {
        try {
          console.log('📄 Uploading certification files...');
          const certUrls = [];
          for (const file of req.files.certificationsFiles) {
            const url = await handleFileUpload(file, 'documents');
            certUrls.push(url);
          }
          if (certUrls.length > 0) {
            productData.certifications = productData.certifications || {};
            productData.certifications.qualityStandards = certUrls.join(', ');
          }
          console.log('✅ Certification files uploaded successfully:', certUrls);
        } catch (error) {
          console.error('❌ Certification files upload error:', error);
          return res.status(500).json({
            success: false,
            message: 'Failed to upload certification files: ' + error.message
          });
        }
      }
    } else {
      // Local file handling
      console.log('💾 Using local storage for file uploads');
      
      if (req.files && req.files.image && req.files.image[0]) {
        productData.imagePath = `/uploads/products/${req.files.image[0].filename}`;
        console.log('✅ Image saved locally:', productData.imagePath);
      }

      if (req.files && req.files.npsApprovalFiles && req.files.npsApprovalFiles.length > 0) {
        productData.npsApproval = req.files.npsApprovalFiles
          .map(file => `/uploads/documents/${file.filename}`)
          .join(', ');
        console.log('✅ NPS files saved locally:', productData.npsApproval);
      }

      if (req.files && req.files.msdsFiles && req.files.msdsFiles.length > 0) {
        productData.msds = req.files.msdsFiles
          .map(file => `/uploads/documents/${file.filename}`)
          .join(', ');
        console.log('✅ MSDS files saved locally:', productData.msds);
      }

      if (req.files && req.files.certificationsFiles && req.files.certificationsFiles.length > 0) {
        productData.certifications = productData.certifications || {};
        productData.certifications.qualityStandards = req.files.certificationsFiles
          .map(file => `/uploads/documents/${file.filename}`)
          .join(', ');
        console.log('✅ Certification files saved locally:', productData.certifications.qualityStandards);
      }
    }

    // Create the product
    console.log('💾 Creating product in database...');
    const product = new Product(productData);
    await product.save();

    console.log('✅ Product created successfully:', product._id);
    res.json({
      success: true,
      message: 'Product created successfully',
      product,
      stats: {
        ingredientsCount: product.composition?.ingredients?.length || 0,
        advantagesCount: product.composition?.advantages?.length || 0,
        instructionsCount: product.application?.instructions?.length || 0,
        cropsCount: product.application?.recommendedCrops?.length || 0,
        ppeCount: product.safety?.ppe?.instructions?.length || 0,
        hygieneCount: product.safety?.hygiene?.instructions?.length || 0,
        phonesCount: product.contact?.phones?.length || 0
      }
    });
  } catch (error) {
    console.error('❌ Create product error:', error);
    res.status(500).json({ 
      success: false, 
      message: error.message || 'Failed to create product',
      error: process.env.NODE_ENV === 'development' ? {
        stack: error.stack,
        name: error.name
      } : undefined
    });
  }
});


// ENHANCED Update Product Route with Dynamic Lists Support
app.put('/api/products/:productId', authenticateToken, uploadFields, async (req, res) => {
  try {
    const { productId } = req.params;
    
    console.log('🔄 Update request for product:', productId);
    console.log('📁 Received files:', req.files);
    console.log('📝 Received body keys:', Object.keys(req.body));

    let productData;
    try {
      productData = JSON.parse(req.body.productData);
      console.log('✅ Parsed product data successfully');
    } catch (parseError) {
      console.error('❌ JSON parse error:', parseError);
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid product data format',
        error: parseError.message
      });
    }

    // Find existing product
    const existingProduct = await Product.findOne({ productId });
    if (!existingProduct) {
      console.log('❌ Product not found:', productId);
      return res.status(404).json({ 
        success: false, 
        message: 'Product not found' 
      });
    }

    console.log('✅ Found existing product:', existingProduct.name);

    // Process and validate product data
    productData = processProductData(productData);
    const validationErrors = validateProductData(productData);
    
    if (validationErrors.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: validationErrors
      });
    }

    // Preserve existing file paths if no new files uploaded
    const preserveExistingFiles = {
      imagePath: existingProduct.imagePath,
      npsApproval: existingProduct.npsApproval,
      msds: existingProduct.msds,
      qualityStandards: existingProduct.certifications?.qualityStandards
    };

    // Handle file uploads with enhanced error handling
    if (USE_CLOUDINARY) {
      console.log('🔗 Using Cloudinary for file updates');
      
      // Update image if provided
      if (req.files && req.files.image && req.files.image[0]) {
        try {
          console.log('📸 Updating product image...');
          const imageUrl = await handleFileUpload(req.files.image[0], 'image');
          productData.imagePath = imageUrl;
          console.log('✅ Image updated:', imageUrl);
        } catch (error) {
          console.error('❌ Image update error:', error);
          return res.status(500).json({
            success: false,
            message: 'Failed to update image: ' + error.message
          });
        }
      } else {
        // Keep existing image
        productData.imagePath = preserveExistingFiles.imagePath;
      }

      // Handle NPS approval files
      if (req.files && req.files.npsApprovalFiles && req.files.npsApprovalFiles.length > 0) {
        try {
          console.log('📄 Updating NPS approval files...');
          const npsUrls = [];
          for (const file of req.files.npsApprovalFiles) {
            const url = await handleFileUpload(file, 'documents');
            npsUrls.push(url);
          }
          productData.npsApproval = npsUrls.join(', ');
          console.log('✅ NPS files updated:', npsUrls.length, 'files');
        } catch (error) {
          console.error('❌ NPS files update error:', error);
          return res.status(500).json({
            success: false,
            message: 'Failed to update NPS approval files: ' + error.message
          });
        }
      } else {
        // Keep existing NPS files
        productData.npsApproval = preserveExistingFiles.npsApproval;
      }

      // Handle MSDS files
      if (req.files && req.files.msdsFiles && req.files.msdsFiles.length > 0) {
        try {
          console.log('📄 Updating MSDS files...');
          const msdsUrls = [];
          for (const file of req.files.msdsFiles) {
            const url = await handleFileUpload(file, 'documents');
            msdsUrls.push(url);
          }
          productData.msds = msdsUrls.join(', ');
          console.log('✅ MSDS files updated:', msdsUrls.length, 'files');
        } catch (error) {
          console.error('❌ MSDS files update error:', error);
          return res.status(500).json({
            success: false,
            message: 'Failed to update MSDS files: ' + error.message
          });
        }
      } else {
        // Keep existing MSDS files
        productData.msds = preserveExistingFiles.msds;
      }

      // Handle certification files
      if (req.files && req.files.certificationsFiles && req.files.certificationsFiles.length > 0) {
        try {
          console.log('📄 Updating certification files...');
          const certUrls = [];
          for (const file of req.files.certificationsFiles) {
            const url = await handleFileUpload(file, 'documents');
            certUrls.push(url);
          }
          if (certUrls.length > 0) {
            productData.certifications = productData.certifications || {};
            productData.certifications.qualityStandards = certUrls.join(', ');
          }
          console.log('✅ Certification files updated:', certUrls.length, 'files');
        } catch (error) {
          console.error('❌ Certification files update error:', error);
          return res.status(500).json({
            success: false,
            message: 'Failed to update certification files: ' + error.message
          });
        }
      } else {
        // Keep existing certification files
        if (!productData.certifications) {
          productData.certifications = {};
        }
        productData.certifications.qualityStandards = preserveExistingFiles.qualityStandards;
      }
    } else {
      // Local file handling for updates
      console.log('💾 Using local storage for file updates');
      
      if (req.files && req.files.image && req.files.image[0]) {
        productData.imagePath = `/uploads/products/${req.files.image[0].filename}`;
        console.log('✅ Image saved locally:', productData.imagePath);
      } else {
        productData.imagePath = preserveExistingFiles.imagePath;
      }

      if (req.files && req.files.npsApprovalFiles && req.files.npsApprovalFiles.length > 0) {
        productData.npsApproval = req.files.npsApprovalFiles
          .map(file => `/uploads/documents/${file.filename}`)
          .join(', ');
        console.log('✅ NPS files saved locally');
      } else {
        productData.npsApproval = preserveExistingFiles.npsApproval;
      }

      if (req.files && req.files.msdsFiles && req.files.msdsFiles.length > 0) {
        productData.msds = req.files.msdsFiles
          .map(file => `/uploads/documents/${file.filename}`)
          .join(', ');
        console.log('✅ MSDS files saved locally');
      } else {
        productData.msds = preserveExistingFiles.msds;
      }

      if (req.files && req.files.certificationsFiles && req.files.certificationsFiles.length > 0) {
        productData.certifications = productData.certifications || {};
        productData.certifications.qualityStandards = req.files.certificationsFiles
          .map(file => `/uploads/documents/${file.filename}`)
          .join(', ');
        console.log('✅ Certification files saved locally');
      } else {
        if (!productData.certifications) {
          productData.certifications = {};
        }
        productData.certifications.qualityStandards = preserveExistingFiles.qualityStandards;
      }
    }

    // Update the product
    console.log('💾 Updating product in database...');
    const updatedProduct = await Product.findOneAndUpdate(
      { productId },
      productData,
      { 
        new: true, 
        runValidators: true,
        upsert: false // Ensure we don't create a new product
      }
    );

    if (!updatedProduct) {
      return res.status(404).json({
        success: false,
        message: 'Product not found during update'
      });
    }

    console.log('✅ Product updated successfully:', updatedProduct._id);
    
    res.json({
      success: true,
      message: 'Product updated successfully',
      product: updatedProduct,
      stats: {
        ingredientsCount: updatedProduct.composition?.ingredients?.length || 0,
        advantagesCount: updatedProduct.composition?.advantages?.length || 0,
        instructionsCount: updatedProduct.application?.instructions?.length || 0,
        cropsCount: updatedProduct.application?.recommendedCrops?.length || 0,
        ppeCount: updatedProduct.safety?.ppe?.instructions?.length || 0,
        hygieneCount: updatedProduct.safety?.hygiene?.instructions?.length || 0,
        phonesCount: updatedProduct.contact?.phones?.length || 0
      }
    });
  } catch (error) {
    console.error('❌ Update product error:', error);
    res.status(500).json({ 
      success: false, 
      message: error.message || 'Failed to update product',
      error: process.env.NODE_ENV === 'development' ? {
        stack: error.stack,
        name: error.name
      } : undefined
    });
  }
});

app.delete('/api/products/:productId', authenticateToken, async (req, res) => {
  try {
    const { productId } = req.params;

    const product = await Product.findOne({ productId });
    if (!product) {
      return res.status(404).json({ 
        success: false, 
        message: 'Product not found' 
      });
    }

    // Soft delete - mark as inactive
    await Product.findOneAndUpdate({ productId }, { isActive: false });
    await Batch.updateMany({ productId }, { isActive: false });

    res.json({
      success: true,
      message: 'Product and all associated batches deleted successfully'
    });
  } catch (error) {
    console.error('Delete product error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to delete product',
      error: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Enhanced Batch Routes
app.get('/api/batches', authenticateToken, async (req, res) => {
  try {
    const { productId, page = 1, limit = 50 } = req.query;
    
    let query = { isActive: true };
    if (productId) {
      query.productId = productId;
    }
    
    const batches = await Batch.find(query)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Batch.countDocuments(query);

    res.json({
      success: true,
      batches,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get batches error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch batches',
      error: error.message 
    });
  }
});

app.post('/api/batches', authenticateToken, async (req, res) => {
  try {
    const { productId, number, manufacturingDate, expiryDate, sampleNo, availablePackageSizes, notes } = req.body;

    // Validate required fields
    if (!productId || !number) {
      return res.status(400).json({ 
        success: false, 
        message: 'Product ID and batch number are required' 
      });
    }

    // Check if product exists
    const product = await Product.findOne({ productId, isActive: true });
    if (!product) {
      return res.status(404).json({ 
        success: false, 
        message: 'Product not found' 
      });
    }

    // Check for existing batch
    const existingBatch = await Batch.findOne({ 
      productId, 
      number: number.trim(),
      isActive: true 
    });
    if (existingBatch) {
      return res.status(400).json({ 
        success: false, 
        message: 'Batch number already exists for this product' 
      });
    }

    const batch = new Batch({
      productId,
      number: number.trim(),
      sampleNo: sampleNo ? sampleNo.trim() : undefined,
      manufacturingDate: manufacturingDate || null,
      expiryDate: expiryDate || null,
      availablePackageSizes: availablePackageSizes || [],
      notes: notes ? notes.trim() : undefined
    });

    await batch.save();

    res.json({
      success: true,
      message: 'Batch created successfully',
      batch
    });
  } catch (error) {
    console.error('Create batch error:', error);
    res.status(500).json({ 
      success: false, 
      message: error.message || 'Failed to create batch',
      error: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

app.put('/api/batches/:batchId', authenticateToken, async (req, res) => {
  try {
    const { batchId } = req.params;
    const { number, manufacturingDate, expiryDate, sampleNo, availablePackageSizes, notes } = req.body;

    const batch = await Batch.findOne({ batchId, isActive: true });
    if (!batch) {
      return res.status(404).json({ 
        success: false, 
        message: 'Batch not found' 
      });
    }

    // Check for duplicate batch number if changing
    if (number && number.trim() !== batch.number) {
      const existingBatch = await Batch.findOne({ 
        productId: batch.productId, 
        number: number.trim(), 
        batchId: { $ne: batchId },
        isActive: true
      });
      if (existingBatch) {
        return res.status(400).json({ 
          success: false, 
          message: 'Batch number already exists for this product' 
        });
      }
    }

    const updatedBatch = await Batch.findOneAndUpdate(
      { batchId },
      { 
        number: number ? number.trim() : batch.number,
        sampleNo: sampleNo !== undefined ? (sampleNo ? sampleNo.trim() : null) : batch.sampleNo,
        manufacturingDate: manufacturingDate !== undefined ? manufacturingDate : batch.manufacturingDate,
        expiryDate: expiryDate !== undefined ? expiryDate : batch.expiryDate,
        availablePackageSizes: availablePackageSizes !== undefined ? availablePackageSizes : batch.availablePackageSizes,
        notes: notes !== undefined ? (notes ? notes.trim() : null) : batch.notes
      },
      { new: true, runValidators: true }
    );

    res.json({
      success: true,
      message: 'Batch updated successfully',
      batch: updatedBatch
    });
  } catch (error) {
    console.error('Update batch error:', error);
    res.status(500).json({ 
      success: false, 
      message: error.message || 'Failed to update batch',
      error: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

app.delete('/api/batches/:batchId', authenticateToken, async (req, res) => {
  try {
    const { batchId } = req.params;

    const batch = await Batch.findOne({ batchId, isActive: true });
    if (!batch) {
      return res.status(404).json({ 
        success: false, 
        message: 'Batch not found' 
      });
    }

    // Soft delete
    await Batch.findOneAndUpdate({ batchId }, { isActive: false });

    res.json({
      success: true,
      message: 'Batch deleted successfully'
    });
  } catch (error) {
    console.error('Delete batch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to delete batch',
      error: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});


// Enhanced Product View Route (for QR code access)
app.get('/api/product-view/:batchId', async (req, res) => {
  try {
    const { batchId } = req.params;

    const batch = await Batch.findOne({ batchId, isActive: true });
    if (!batch) {
      return res.status(404).json({ 
        success: false, 
        message: 'Batch not found or inactive' 
      });
    }

    const product = await Product.findOne({ productId: batch.productId, isActive: true });
    if (!product) {
      return res.status(404).json({ 
        success: false, 
        message: 'Product not found or inactive' 
      });
    }

    // Update expiry status
    if (batch.expiryDate) {
      const isExpired = new Date() > new Date(batch.expiryDate);
      if (batch.isExpired !== isExpired) {
        batch.isExpired = isExpired;
        await batch.save();
      }
    }

    // Enhanced product data with better structure
    const enhancedProduct = {
      ...product.toJSON(),
      batchInfo: batch.toJSON(),
      // Add some helpful counts for the frontend
      stats: {
        ingredientsCount: product.composition?.ingredients?.length || 0,
        advantagesCount: product.composition?.advantages?.length || 0,
        instructionsCount: product.application?.instructions?.length || 0,
        cropsCount: product.application?.recommendedCrops?.length || 0,
        ppeCount: product.safety?.ppe?.instructions?.length || 0,
        hygieneCount: product.safety?.hygiene?.instructions?.length || 0,
        phonesCount: product.contact?.phones?.length || 0
      }
    };

    res.json({
      success: true,
      data: enhancedProduct
    });
  } catch (error) {
    console.error('❌ Get product view error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch product information',
      error: error.message
    });
  }
});

// Analytics Routes
app.get('/api/analytics/dashboard', authenticateToken, async (req, res) => {
  try {
    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

    const stats = {
      totalProducts: await Product.countDocuments({ isActive: true }),
      totalBatches: await Batch.countDocuments({ isActive: true }),
      expiredBatches: await Batch.countDocuments({ 
        isActive: true, 
        isExpired: true 
      }),
      expiringSoon: await Batch.countDocuments({ 
        isActive: true, 
        isExpired: false,
        expiryDate: { $lte: new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000) }
      }),
      recentProducts: await Product.countDocuments({ 
        isActive: true,
        createdAt: { $gte: thirtyDaysAgo } 
      }),
      recentBatches: await Batch.countDocuments({ 
        isActive: true,
        createdAt: { $gte: thirtyDaysAgo } 
      })
    };

    res.json({
      success: true,
      stats
    });
  } catch (error) {
    console.error('Analytics error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch analytics',
      error: error.message 
    });
  }
});

// Enhanced Error Handling - Final error handler
app.use((error, req, res, next) => {
  console.error('🚨 Unhandled error:', error);

  if (error.name === 'ValidationError') {
    return res.status(400).json({
      success: false,
      message: 'Validation error',
      errors: Object.values(error.errors).map(err => err.message),
      errorCode: 'VALIDATION_ERROR'
    });
  }

  if (error.name === 'CastError') {
    return res.status(400).json({
      success: false,
      message: 'Invalid ID format',
      errorCode: 'INVALID_ID'
    });
  }

  if (error.code === 11000) {
    return res.status(400).json({
      success: false,
      message: 'Duplicate entry detected',
      errorCode: 'DUPLICATE_ENTRY'
    });
  }

  // Cloudinary errors
  if (error.message && error.message.includes('cloudinary')) {
    return res.status(500).json({
      success: false,
      message: 'File storage error. Please try again.',
      errorCode: 'STORAGE_ERROR'
    });
  }
  
  res.status(500).json({ 
    success: false, 
    message: error.message || 'Internal server error',
    errorCode: 'INTERNAL_ERROR',
    error: process.env.NODE_ENV === 'development' ? error.stack : undefined
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    success: false, 
    message: `Route ${req.method} ${req.path} not found`,
    availableRoutes: [
      'GET /health',
      'POST /signin',
      'POST /signout', 
      'GET /auth/check',
      'GET /api/products',
      'POST /api/products',
      'PUT /api/products/:productId',
      'DELETE /api/products/:productId',
      'GET /api/batches',
      'POST /api/batches',
      'PUT /api/batches/:batchId',
      'DELETE /api/batches/:batchId',
      'GET /api/product-view/:batchId',
      'GET /api/analytics/dashboard',
      'POST /api/debug/upload'
    ]
  });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('🔄 SIGTERM received, shutting down gracefully...');
  try {
    await mongoose.connection.close();
    console.log('✅ Database connection closed');
    process.exit(0);
  } catch (error) {
    console.error('❌ Error during shutdown:', error);
    process.exit(1);
  }
});

process.on('SIGINT', async () => {
  console.log('🔄 SIGINT received, shutting down gracefully...');
  try {
    await mongoose.connection.close();
    console.log('✅ Database connection closed');
    process.exit(0);
  } catch (error) {
    console.error('❌ Error during shutdown:', error);
    process.exit(1);
  }
});

// Start server
app.listen(PORT, async () => {
  console.log('🚀 ===================================');
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📁 Storage: ${USE_CLOUDINARY ? 'Cloudinary' : 'Local'}`);
  console.log('🔧 Enhanced Features:');
  console.log('   ✅ Dynamic Lists Support');
  console.log('   ✅ Enhanced File Handling');
  console.log('   ✅ Better Error Handling');
  console.log('   ✅ Smart Data Validation');
  console.log('   ✅ Enhanced Logging');
  console.log('   ✅ Fixed Upload Fields Configuration');
  
  if (USE_CLOUDINARY) {
    console.log('🔗 Cloudinary file storage configured');
  } else {
    console.log('💾 Local file storage configured');
    console.log(`📁 Static files served at: /uploads`);
  }
  
  console.log('🔧 API Routes:');
  console.log(`   GET  /health - Health check`);
  console.log(`   POST /signin - User authentication`);
  console.log(`   GET  /api/products - Get all products`);
  console.log(`   POST /api/products - Create product (Enhanced)`);
  console.log(`   PUT  /api/products/:productId - Update product (Enhanced)`);
  console.log(`   GET  /api/product-view/:batchId - Public product view`);
  console.log(`   GET  /api/analytics/dashboard - Analytics`);
  console.log(`   POST /api/debug/upload - File upload debug (New)`);
  console.log('🚀 ===================================');
  
  await initializeAdmin();
  await updateExistingBatches();
  
  console.log('✅ Server initialization complete!');
  console.log('🎯 Ready to handle dynamic lists and fixed file uploads!');
  console.log('🔧 File upload issues should now be resolved!');
});
