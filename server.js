const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

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
  origin: ['http://localhost:3000', 'http://localhost:3001', process.env.FRONTEND_URL],
  credentials: true,
  optionsSuccessStatus: 200
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  fs.mkdirSync(path.join(uploadsDir, 'products'), { recursive: true });
  fs.mkdirSync(path.join(uploadsDir, 'documents'), { recursive: true });
}

// Serve static files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Multer configuration for file uploads
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

const upload = multer({ 
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

// User Schema
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

// Product Schema
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

// Update the updatedAt field on save
productSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

const Product = mongoose.model('Product', productSchema);

// Updated Batch Schema with short auto-generated ID
const batchSchema = new mongoose.Schema({
  batchId: {
    type: String,
    unique: true,
    uppercase: true,
    // Remove required: true to allow migration of existing data
    // We'll handle this in the pre-save middleware
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
  
  // Check if this ID already exists
  const existingBatch = await Batch.findOne({ batchId: batchId });
  if (existingBatch) {
    // If exists, generate a new one recursively
    return generateShortBatchId();
  }
  
  return batchId;
}

// Pre-save middleware to generate batchId and update expiry status
batchSchema.pre('save', async function(next) {
  this.updatedAt = Date.now();
  
  // Generate batchId if it's a new document and batchId is not provided
  if (this.isNew && !this.batchId) {
    try {
      this.batchId = await generateShortBatchId();
    } catch (error) {
      return next(error);
    }
  }
  
  // Update expiry status
  if (this.expiryDate) {
    this.isExpired = new Date() > new Date(this.expiryDate);
  }
  
  next();
});

// Virtual to check if batch is expired
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

// Migration function to add batchId to existing batches
const updateExistingBatches = async () => {
  try {
    const batches = await Batch.find({ 
      $or: [
        { batchId: { $exists: false } },
        { batchId: null },
        { batchId: '' }
      ]
    });
    console.log(`Found ${batches.length} batches without batchId. Updating...`);
    
    for (let batch of batches) {
      try {
        // Generate batchId manually for existing batches
        if (!batch.batchId) {
          batch.batchId = await generateShortBatchId();
        }
        
        // Save with validation disabled temporarily for migration
        await batch.save({ validateBeforeSave: false });
        
        // Now save again with validation to ensure everything is correct
        await batch.save();
        
        console.log(`Updated batch ${batch.number} with batchId: ${batch.batchId}`);
      } catch (batchError) {
        console.error(`Error updating batch ${batch.number}:`, batchError.message);
        // Continue with next batch even if one fails
        continue;
      }
    }
    
    if (batches.length > 0) {
      console.log(`Successfully updated ${batches.length} existing batches with new batchId`);
    }
  } catch (error) {
    console.error('Error in updateExistingBatches:', error);
  }
};

// Routes

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

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
    
    // Get batches for each product
    const productsWithBatches = await Promise.all(
      products.map(async (product) => {
        const batches = await Batch.find({ productId: product.productId }).sort({ createdAt: -1 });
        
        // Calculate batch summaries
        const now = new Date();
        const summary = {
          activeBatches: 0,
          expiredBatches: 0,
          expiringSoon: 0 // within 30 days
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
    
    // Check if product ID already exists
    const existingProduct = await Product.findOne({ productId: productData.productId });
    if (existingProduct) {
      return res.status(400).json({ 
        success: false, 
        message: 'Product ID already exists' 
      });
    }

    // Handle file uploads
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

    // Handle file uploads
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

    // Delete all batches associated with this product
    await Batch.deleteMany({ productId });

    // Delete the product
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

// Updated Batch routes using batchId
app.post('/api/batches', authenticateToken, async (req, res) => {
  try {
    const { productId, number, manufacturingDate, expiryDate } = req.body;

    // Check if product exists
    const product = await Product.findOne({ productId });
    if (!product) {
      return res.status(404).json({ 
        success: false, 
        message: 'Product not found' 
      });
    }

    // Check if batch number already exists for this product
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
      // batchId will be auto-generated by the pre-save middleware
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

    // Find by batchId instead of _id
    const batch = await Batch.findOne({ batchId });
    if (!batch) {
      return res.status(404).json({ 
        success: false, 
        message: 'Batch not found' 
      });
    }

    // Check if new batch number conflicts with existing batches (excluding current batch)
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

    // Find by batchId instead of _id
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

// Updated Product view route (for QR code access)
app.get('/api/product-view/:batchId', async (req, res) => {
  try {
    const { batchId } = req.params;

    // Find by batchId instead of _id
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

    // Update batch expiry status
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
  console.log(`Server running on port ${PORT}`);
  await initializeAdmin();
  await updateExistingBatches(); // Migration for existing batches
});

module.exports = app;