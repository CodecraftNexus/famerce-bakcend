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
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/fertilizer_management', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

mongoose.connection.on('connected', () => {
  console.log('Connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

// Middleware
app.use(cors({
  origin: [
    'http://localhost:3000', 
    'http://localhost:3001', 
    'http://localhost:5173',
    process.env.FRONTEND_URL
  ].filter(Boolean),
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

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

// Cloudinary Configuration
if (USE_CLOUDINARY) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
  });

  console.log('🔗 Cloudinary storage configured');
} else {
  console.log('💾 Local file storage configured');
}

// Storage Configuration
let upload;

if (USE_CLOUDINARY) {
  // Cloudinary Storage
  const imageStorage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
      folder: 'famerce/products',
      allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
      transformation: [
        { width: 800, height: 600, crop: 'limit', quality: 'auto' }
      ]
    }
  });

  const documentStorage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
      folder: 'famerce/documents',
      allowed_formats: ['pdf', 'doc', 'docx'],
      resource_type: 'raw'
    }
  });

  upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 }
  });
} else {
  // Local Storage
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

  upload = multer({ 
    storage: storage,
    limits: {
      fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: function (req, file, cb) {
      if (file.fieldname === 'image') {
        if (file.mimetype.startsWith('image/')) {
          cb(null, true);
        } else {
          cb(new Error('Only image files are allowed for product images'));
        }
      } else {
        const allowedTypes = ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
        if (allowedTypes.includes(file.mimetype)) {
          cb(null, true);
        } else {
          cb(new Error('Only PDF, DOC, and DOCX files are allowed for documents'));
        }
      }
    }
  });
}

// File Upload Handler for Cloudinary
const handleFileUpload = async (file, type = 'document') => {
  if (!USE_CLOUDINARY) {
    throw new Error('Cloudinary upload called but not configured');
  }

  return new Promise((resolve, reject) => {
    const uploadOptions = {
      folder: type === 'image' ? 'famerce/products' : 'famerce/documents',
      resource_type: type === 'image' ? 'image' : 'raw',
    };

    if (type === 'image') {
      uploadOptions.transformation = [
        { width: 800, height: 600, crop: 'limit', quality: 'auto' }
      ];
    }

    const uploadStream = cloudinary.uploader.upload_stream(
      uploadOptions,
      (error, result) => {
        if (error) {
          reject(error);
        } else {
          resolve(result.secure_url);
        }
      }
    );

    uploadStream.end(file.buffer);
  });
};

// Schemas
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: String,
    default: 'admin',
    enum: ['admin', 'user']
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const User = mongoose.model('User', userSchema);

const productSchema = new mongoose.Schema({
  productId: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  shortDescription: String,
  fullDescription: String,
  imagePath: String,
  npsApproval: String,
  msds: String,
  composition: {
    title: { type: String, default: "Composition" },
    ingredients: [{
      name: String,
      percentage: String
    }],
    advantages: [String]
  },
  application: {
    title: { type: String, default: "Application Details" },
    instructions: String,
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
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

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
  },
  productId: {
    type: String,
    required: true,
    ref: 'Product'
  },
  number: {
    type: String,
    required: true,
    trim: true
  },
  sampleNo: {
    type: String,
    trim: true
  },
  manufacturingDate: Date,
  expiryDate: Date,
  availablePackageSizes: [String],
  isExpired: {
    type: Boolean,
    default: false
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

// Function to generate short batch ID
async function generateShortBatchId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let batchId = '';
  
  for (let i = 0; i < 8; i++) {
    batchId += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  
  const existingBatch = await Batch.findOne({ batchId: batchId });
  if (existingBatch) {
    return generateShortBatchId();
  }
  
  return batchId;
}

// Pre-save middleware for batches
batchSchema.pre('save', async function(next) {
  this.updatedAt = Date.now();
  
  if (this.isNew && !this.batchId) {
    try {
      this.batchId = await generateShortBatchId();
    } catch (error) {
      return next(error);
    }
  }
  
  if (this.expiryDate) {
    this.isExpired = new Date() > new Date(this.expiryDate);
  }
  
  next();
});

batchSchema.virtual('expired').get(function() {
  if (!this.expiryDate) return false;
  return new Date() > new Date(this.expiryDate);
});

const Batch = mongoose.model('Batch', batchSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Initialize admin user
const initializeAdmin = async () => {
  try {
    const adminExists = await User.findOne({ username: 'admin' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      const admin = new User({
        username: 'admin',
        password: hashedPassword,
        role: 'admin'
      });
      await admin.save();
      console.log('Default admin user created: username=admin, password=admin123');
    }
  } catch (error) {
    console.error('Error creating admin user:', error);
  }
};

// Migration function for existing batches
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
      console.log(`Found ${batches.length} batches without batchId. Updating...`);
      
      for (let batch of batches) {
        try {
          if (!batch.batchId) {
            batch.batchId = await generateShortBatchId();
          }
          
          await batch.save({ validateBeforeSave: false });
          await batch.save();
          
          console.log(`Updated batch ${batch.number} with batchId: ${batch.batchId}`);
        } catch (batchError) {
          console.error(`Error updating batch ${batch.number}:`, batchError.message);
          continue;
        }
      }
      
      console.log(`Successfully updated ${batches.length} existing batches with new batchId`);
    }
  } catch (error) {
    console.error('Error in updateExistingBatches:', error);
  }
};

// ROUTES

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    storage: USE_CLOUDINARY ? 'cloudinary' : 'local',
    cloudinary: USE_CLOUDINARY ? (process.env.CLOUDINARY_CLOUD_NAME ? 'configured' : 'not configured') : 'disabled'
  });
});

// File Access Routes (Cloudinary only)
if (USE_CLOUDINARY) {
  app.get('/api/files/:type/:publicId(*)', (req, res) => {
    try {
      const { type, publicId } = req.params;
      
      const folder = type === 'image' ? 'famerce/products' : 'famerce/documents';
      const resourceType = type === 'image' ? 'image' : 'raw';
      
      const cloudinaryUrl = cloudinary.url(`${folder}/${publicId}`, {
        resource_type: resourceType,
        secure: true
      });
      
      res.redirect(cloudinaryUrl);
      
    } catch (error) {
      console.error('File access error:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Failed to access file',
        error: error.message 
      });
    }
  });

  app.get('/api/documents/download-url/:publicId', async (req, res) => {
    try {
      const { publicId } = req.params;
      
      const downloadUrl = cloudinary.url(`famerce/documents/${publicId}`, {
        resource_type: 'raw',
        secure: true,
        flags: 'attachment'
      });
      
      res.json({
        success: true,
        downloadUrl
      });
      
    } catch (error) {
      console.error('Download URL error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to generate download URL',
        error: error.message
      });
    }
  });

  app.get('/api/debug/list-files/:type?', async (req, res) => {
    try {
      const { type } = req.params;
      
      const searchOptions = {
        type: 'upload',
        max_results: 50
      };
      
      if (type) {
        searchOptions.prefix = `famerce/${type}`;
      } else {
        searchOptions.prefix = 'famerce';
      }
      
      const result = await cloudinary.search
        .expression(`folder:${searchOptions.prefix}`)
        .max_results(searchOptions.max_results)
        .execute();
      
      const files = result.resources.map(resource => ({
        public_id: resource.public_id,
        secure_url: resource.secure_url,
        resource_type: resource.resource_type,
        format: resource.format,
        bytes: resource.bytes,
        created_at: resource.created_at
      }));
      
      res.json({
        success: true,
        files,
        total: result.total_count
      });
      
    } catch (error) {
      console.error('List files error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to list files',
        error: error.message
      });
    }
  });
}

// Authentication routes
app.post('/signin', async (req, res) => {
  try {
    const { username, password, rememberMe } = req.body;

    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Username and password are required' 
      });
    }

    const user = await User.findOne({ username: username.trim() });
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid username or password' 
      });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid username or password' 
      });
    }

    const token = jwt.sign(
      { 
        userId: user._id, 
        username: user.username, 
        role: user.role 
      }, 
      JWT_SECRET, 
      { expiresIn: rememberMe ? '30d' : '24h' }
    );

    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000
    };

    res.cookie('token', token, cookieOptions);

    res.json({
      success: true,
      message: 'Login successful',
      user: {
        id: user._id,
        username: user.username,
        role: user.role
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
  res.clearCookie('token');
  res.json({ success: true, message: 'Logout successful' });
});

app.get('/auth/check', authenticateToken, (req, res) => {
  res.json({
    authenticated: true,
    user: {
      id: req.user.userId,
      username: req.user.username,
      role: req.user.role
    }
  });
});

// Product routes
app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 });
    
    const productsWithBatches = await Promise.all(
      products.map(async (product) => {
        const batches = await Batch.find({ productId: product.productId }).sort({ createdAt: -1 });
        
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

    res.json({
      success: true,
      products: productsWithBatches
    });
  } catch (error) {
    console.error('Get products error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch products' 
    });
  }
});

app.post('/api/products', authenticateToken, upload.fields([
  { name: 'image', maxCount: 1 },
  { name: 'npsApprovalFiles[]', maxCount: 10 },
  { name: 'msdsFiles[]', maxCount: 10 },
  { name: 'certificationsFiles[]', maxCount: 10 }
]), async (req, res) => {
  try {
    const productData = JSON.parse(req.body.productData);
    
    const existingProduct = await Product.findOne({ productId: productData.productId });
    if (existingProduct) {
      return res.status(400).json({ 
        success: false, 
        message: 'Product ID already exists' 
      });
    }

    // Handle file uploads based on storage type
    if (USE_CLOUDINARY) {
      const uploadPromises = [];

      // Upload image
      if (req.files.image && req.files.image[0]) {
        uploadPromises.push(
          handleFileUpload(req.files.image[0], 'image').then(url => {
            productData.imagePath = url;
          })
        );
      }

      // Upload NPS approval files
      if (req.files['npsApprovalFiles[]']) {
        req.files['npsApprovalFiles[]'].forEach(file => {
          uploadPromises.push(
            handleFileUpload(file, 'document').then(url => {
              productData.npsApproval = productData.npsApproval ? `${productData.npsApproval}, ${url}` : url;
            })
          );
        });
      }

      // Upload MSDS files  
      if (req.files['msdsFiles[]']) {
        req.files['msdsFiles[]'].forEach(file => {
          uploadPromises.push(
            handleFileUpload(file, 'document').then(url => {
              productData.msds = productData.msds ? `${productData.msds}, ${url}` : url;
            })
          );
        });
      }

      // Upload certification files
      if (req.files['certificationsFiles[]']) {
        req.files['certificationsFiles[]'].forEach(file => {
          uploadPromises.push(
            handleFileUpload(file, 'document').then(url => {
              productData.certifications = productData.certifications || { qualityStandards: '' };
              productData.certifications.qualityStandards = productData.certifications.qualityStandards
                ? `${productData.certifications.qualityStandards}, ${url}`
                : url;
            })
          );
        });
      }

      await Promise.all(uploadPromises);
    } else {
      // Local file handling
      if (req.files.image && req.files.image[0]) {
        productData.imagePath = `/uploads/products/${req.files.image[0].filename}`;
      }

      if (req.files['npsApprovalFiles[]']) {
        productData.npsApproval = req.files['npsApprovalFiles[]'].map(file => file.filename).join(', ');
      }

      if (req.files['msdsFiles[]']) {
        productData.msds = req.files['msdsFiles[]'].map(file => file.filename).join(', ');
      }

      if (req.files['certificationsFiles[]']) {
        productData.certifications.qualityStandards = req.files['certificationsFiles[]'].map(file => file.filename).join(', ');
      }
    }

    const product = new Product(productData);
    await product.save();

    res.json({
      success: true,
      message: 'Product created successfully',
      product
    });
  } catch (error) {
    console.error('Create product error:', error);
    res.status(500).json({ 
      success: false, 
      message: error.message || 'Failed to create product' 
    });
  }
});

app.put('/api/products/:productId', authenticateToken, upload.fields([
  { name: 'image', maxCount: 1 },
  { name: 'npsApprovalFiles', maxCount: 10 },
  { name: 'msdsFiles', maxCount: 10 },
  { name: 'certificationsFiles', maxCount: 10 }
]), async (req, res) => {
  try {
    const { productId } = req.params;
    const productData = JSON.parse(req.body.productData);

    const existingProduct = await Product.findOne({ productId });
    if (!existingProduct) {
      return res.status(404).json({ 
        success: false, 
        message: 'Product not found' 
      });
    }

    // Handle file uploads based on storage type
    if (USE_CLOUDINARY) {
      const uploadPromises = [];

      if (req.files.image && req.files.image[0]) {
        uploadPromises.push(
          handleFileUpload(req.files.image[0], 'image').then(url => {
            productData.imagePath = url;
          })
        );
      }

      if (req.files.npsApprovalFiles && req.files.npsApprovalFiles.length > 0) {
        req.files.npsApprovalFiles.forEach(file => {
          uploadPromises.push(
            handleFileUpload(file, 'document').then(url => {
              productData.npsApproval = productData.npsApproval ? `${productData.npsApproval}, ${url}` : url;
            })
          );
        });
      }

      if (req.files.msdsFiles && req.files.msdsFiles.length > 0) {
        req.files.msdsFiles.forEach(file => {
          uploadPromises.push(
            handleFileUpload(file, 'document').then(url => {
              productData.msds = productData.msds ? `${productData.msds}, ${url}` : url;
            })
          );
        });
      }

      if (req.files.certificationsFiles && req.files.certificationsFiles.length > 0) {
        req.files.certificationsFiles.forEach(file => {
          uploadPromises.push(
            handleFileUpload(file, 'document').then(url => {
              productData.certifications = productData.certifications || { qualityStandards: '' };
              productData.certifications.qualityStandards = productData.certifications.qualityStandards
                ? `${productData.certifications.qualityStandards}, ${url}`
                : url;
            })
          );
        });
      }

      await Promise.all(uploadPromises);
    } else {
      // Local file handling
      if (req.files.image && req.files.image[0]) {
        productData.imagePath = `/uploads/products/${req.files.image[0].filename}`;
      }

      if (req.files.npsApprovalFiles && req.files.npsApprovalFiles.length > 0) {
        productData.npsApproval = req.files.npsApprovalFiles.map(file => file.filename).join(', ');
      }

      if (req.files.msdsFiles && req.files.msdsFiles.length > 0) {
        productData.msds = req.files.msdsFiles.map(file => file.filename).join(', ');
      }

      if (req.files.certificationsFiles && req.files.certificationsFiles.length > 0) {
        productData.certifications.qualityStandards = req.files.certificationsFiles.map(file => file.filename).join(', ');
      }
    }

    const updatedProduct = await Product.findOneAndUpdate(
      { productId },
      productData,
      { new: true, runValidators: true }
    );

    res.json({
      success: true,
      message: 'Product updated successfully',
      product: updatedProduct
    });
  } catch (error) {
    console.error('Update product error:', error);
    res.status(500).json({ 
      success: false, 
      message: error.message || 'Failed to update product' 
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

    await Batch.deleteMany({ productId });
    await Product.deleteOne({ productId });

    res.json({
      success: true,
      message: 'Product and all associated batches deleted successfully'
    });
  } catch (error) {
    console.error('Delete product error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to delete product' 
    });
  }
});

// Batch routes
app.post('/api/batches', authenticateToken, async (req, res) => {
  try {
    const { productId, number, manufacturingDate, expiryDate } = req.body;

    const product = await Product.findOne({ productId });
    if (!product) {
      return res.status(404).json({ 
        success: false, 
        message: 'Product not found' 
      });
    }

    const existingBatch = await Batch.findOne({ productId, number });
    if (existingBatch) {
      return res.status(400).json({ 
        success: false, 
        message: 'Batch number already exists for this product' 
      });
    }

    const batch = new Batch({
      productId,
      number,
      manufacturingDate: manufacturingDate || null,
      expiryDate: expiryDate || null
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
      message: error.message || 'Failed to create batch' 
    });
  }
});

app.put('/api/batches/:batchId', authenticateToken, async (req, res) => {
  try {
    const { batchId } = req.params;
    const { number, manufacturingDate, expiryDate } = req.body;

    const batch = await Batch.findOne({ batchId });
    if (!batch) {
      return res.status(404).json({ 
        success: false, 
        message: 'Batch not found' 
      });
    }

    if (number && number !== batch.number) {
      const existingBatch = await Batch.findOne({ 
        productId: batch.productId, 
        number, 
        batchId: { $ne: batchId } 
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
        number: number || batch.number,
        manufacturingDate: manufacturingDate !== undefined ? manufacturingDate : batch.manufacturingDate,
        expiryDate: expiryDate !== undefined ? expiryDate : batch.expiryDate
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
      message: error.message || 'Failed to update batch' 
    });
  }
});

app.delete('/api/batches/:batchId', authenticateToken, async (req, res) => {
  try {
    const { batchId } = req.params;

    const batch = await Batch.findOne({ batchId });
    if (!batch) {
      return res.status(404).json({ 
        success: false, 
        message: 'Batch not found' 
      });
    }

    await Batch.findOneAndDelete({ batchId });

    res.json({
      success: true,
      message: 'Batch deleted successfully'
    });
  } catch (error) {
    console.error('Delete batch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to delete batch' 
    });
  }
});

// Product view route (for QR code access)
app.get('/api/product-view/:batchId', async (req, res) => {
  try {
    const { batchId } = req.params;

    const batch = await Batch.findOne({ batchId });
    if (!batch) {
      return res.status(404).json({ 
        success: false, 
        message: 'Batch not found' 
      });
    }

    const product = await Product.findOne({ productId: batch.productId });
    if (!product) {
      return res.status(404).json({ 
        success: false, 
        message: 'Product not found' 
      });
    }

    if (batch.expiryDate) {
      batch.isExpired = new Date() > new Date(batch.expiryDate);
      await batch.save();
    }

    res.json({
      success: true,
      data: {
        ...product.toJSON(),
        batchInfo: batch.toJSON()
      }
    });
  } catch (error) {
    console.error('Get product view error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch product information' 
    });
  }
});

// Additional utility routes
app.get('/api/storage-info', (req, res) => {
  res.json({
    success: true,
    storageType: USE_CLOUDINARY ? 'cloudinary' : 'local',
    config: {
      useCloudinary: USE_CLOUDINARY,
      cloudinaryConfigured: USE_CLOUDINARY ? !!process.env.CLOUDINARY_CLOUD_NAME : false
    }
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ 
        success: false, 
        message: 'File too large. Maximum size is 5MB.' 
      });
    }
  }
  
  console.error('Unhandled error:', error);
  res.status(500).json({ 
    success: false, 
    message: error.message || 'Internal server error' 
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    success: false, 
    message: 'Route not found' 
  });
});

// Start server
app.listen(PORT, async () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📁 Storage: ${USE_CLOUDINARY ? 'Cloudinary' : 'Local'}`);
  
  if (USE_CLOUDINARY) {
    console.log('🔗 Cloudinary file storage configured');
    console.log('📁 File access routes:');
    console.log(`   GET  /api/files/:type/:publicId`);
    console.log(`   GET  /api/documents/download-url/:publicId`);
    console.log(`   GET  /api/debug/list-files/:type`);
  } else {
    console.log('💾 Local file storage configured');
    console.log(`📁 Static files served at: /uploads`);
  }
  
  console.log('🔧 Additional routes:');
  console.log(`   GET  /api/storage-info`);
  console.log(`   GET  /health`);
  
  await initializeAdmin();
  await updateExistingBatches();
});

module.exports = app;
