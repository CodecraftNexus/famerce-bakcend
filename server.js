const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const path = require('path');
const { Storage } = require('@google-cloud/storage');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());
app.use(cors({
  origin: [process.env.FRONTEND_URL || 'http://localhost:3000', 'http://localhost:5173'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).catch(err => {
  console.error('MongoDB initial connection error:', err);
});

mongoose.connection.on('connected', () => {
  console.log('Connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

// Google Cloud Storage Configuration
const storage = new Storage({
  projectId: process.env.GCP_PROJECT_ID,
  credentials: {
    client_email: process.env.GCP_CLIENT_EMAIL,
    private_key: process.env.GCP_PRIVATE_KEY ? process.env.GCP_PRIVATE_KEY.replace(/\\n/g, '\n') : undefined,
  },
});

const bucket = storage.bucket(process.env.GCP_BUCKET_NAME);

// Multer configuration for Google Cloud Storage
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
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
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      ];
      if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
      } else {
        cb(new Error('Only PDF, DOC, and DOCX files are allowed for documents'));
      }
    }
  },
});

// Middleware to handle file upload to GCS
const uploadToGCS = (req, file, cb) => {
  if (!file) return cb(new Error('No file provided'));
  const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
  const folder = file.fieldname === 'image' ? 'products' : 'documents';
  const fileName = `${folder}/${file.fieldname}-${uniqueSuffix}${path.extname(file.originalname)}`;
  const blob = bucket.file(fileName);
  const blobStream = blob.createWriteStream({
    resumable: false,
    metadata: {
      contentType: file.mimetype,
    },
  });

  blobStream.on('error', (err) => {
    cb(err);
  });

  blobStream.on('finish', () => {
    const publicUrl = `https://storage.googleapis.com/${process.env.GCP_BUCKET_NAME}/${fileName}`;
    cb(null, publicUrl);
  });

  blobStream.end(file.buffer);
};

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  password: { type: String, required: true },
  role: { type: String, default: 'admin', enum: ['admin', 'user'] },
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);

// Product Schema
const productSchema = new mongoose.Schema({
  productId: { type: String, required: true, unique: true, trim: true },
  name: { type: String, required: true, trim: true },
  shortDescription: String,
  fullDescription: String,
  imagePath: String,
  npsApproval: String,
  msds: String,
  composition: {
    title: { type: String, default: 'Composition' },
    ingredients: [{ name: String, percentage: String }],
    advantages: [String],
  },
  application: {
    title: { type: String, default: 'Application Details' },
    instructions: String,
    recommendedCrops: [String],
  },
  safety: {
    title: { type: String, default: 'Safety Instructions' },
    ppe: { title: { type: String, default: 'Personal Protective Equipment (PPE)' }, instructions: [String] },
    hygiene: { title: { type: String, default: 'Work Hygienic Practices' }, instructions: [String] },
  },
  certifications: { title: { type: String, default: 'Certifications' }, qualityStandards: String },
  contact: {
    title: { type: String, default: 'Contact Details' },
    address: String,
    phones: [String],
    email: String,
    website: String,
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

productSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

const Product = mongoose.model('Product', productSchema);

// Batch Schema
const batchSchema = new mongoose.Schema({
  batchId: { type: String, unique: true, uppercase: true },
  productId: { type: String, required: true, ref: 'Product' },
  number: { type: String, required: true, trim: true },
  sampleNo: { type: String, trim: true },
  manufacturingDate: Date,
  expiryDate: Date,
  availablePackageSizes: [String],
  isExpired: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

async function generateShortBatchId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let batchId = '';
  for (let i = 0; i < 8; i++) {
    batchId += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  const existingBatch = await Batch.findOne({ batchId });
  return existingBatch ? generateShortBatchId() : batchId;
}

batchSchema.pre('save', async function (next) {
  this.updatedAt = Date.now();
  if (this.isNew && !this.batchId) {
    this.batchId = await generateShortBatchId();
  }
  if (this.expiryDate) {
    this.isExpired = new Date() > new Date(this.expiryDate);
  }
  next();
});

batchSchema.virtual('expired').get(function () {
  return this.expiryDate ? new Date() > new Date(this.expiryDate) : false;
});

const Batch = mongoose.model('Batch', batchSchema);

// JWT Secret Validation
if (!process.env.JWT_SECRET) {
  console.error('FATAL ERROR: JWT_SECRET is not defined');
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;

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
      const admin = new User({ username: 'admin', password: hashedPassword, role: 'admin' });
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
      $or: [{ batchId: { $exists: false } }, { batchId: null }, { batchId: '' }],
    });
    console.log(`Found ${batches.length} batches without batchId. Updating...`);
    for (let batch of batches) {
      batch.batchId = await generateShortBatchId();
      await batch.save({ validateBeforeSave: false });
      console.log(`Updated batch ${batch.number} with batchId: ${batch.batchId}`);
    }
    if (batches.length > 0) {
      console.log(`Successfully updated ${batches.length} batches with new batchId`);
    }
  } catch (error) {
    console.error('Error in updateExistingBatches:', error);
  }
};

// Routes
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
  });
});

app.post('/signin', async (req, res) => {
  try {
    const { username, password, rememberMe } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password are required' });
    }
    const user = await User.findOne({ username: username.trim() });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid username or password' });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Invalid username or password' });
    }
    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: rememberMe ? '30d' : '24h' }
    );
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000,
    });
    res.json({
      success: true,
      message: 'Login successful',
      user: { id: user._id, username: user.username, role: user.role },
      token,
    });
  } catch (error) {
    console.error('Signin error:', error.message, error.stack);
    res.status(500).json({ success: false, message: 'Internal server error', error: error.message });
  }
});

app.post('/signout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true, message: 'Logout successful' });
});

app.get('/auth/check', authenticateToken, (req, res) => {
  res.json({
    authenticated: true,
    user: { id: req.user.userId, username: req.user.username, role: req.user.role },
  });
});

app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 });
    const productsWithBatches = await Promise.all(
      products.map(async (product) => {
        const batches = await Batch.find({ productId: product.productId }).sort({ createdAt: -1 });
        const now = new Date();
        const summary = { activeBatches: 0, expiredBatches: 0, expiringSoon: 0 };
        batches.forEach((batch) => {
          if (batch.isExpired || (batch.expiryDate && new Date(batch.expiryDate) <= now)) {
            summary.expiredBatches++;
          } else if (batch.expiryDate) {
            const daysUntilExpiry = Math.ceil((new Date(batch.expiryDate) - now) / (1000 * 60 * 60 * 24));
            daysUntilExpiry <= 30 ? summary.expiringSoon++ : summary.activeBatches++;
          } else {
            summary.activeBatches++;
          }
        });
        return { ...product.toJSON(), batches, summary };
      })
    );
    res.json({ success: true, products: productsWithBatches });
  } catch (error) {
    console.error('Get products error:', error.message, error.stack);
    res.status(500).json({ success: false, message: 'Failed to fetch products', error: error.message });
  }
});

app.post('/api/products', authenticateToken, upload.fields([
  { name: 'image', maxCount: 1 },
  { name: 'npsApprovalFiles[]', maxCount: 10 },
  { name: 'msdsFiles[]', maxCount: 10 },
  { name: 'certificationsFiles[]', maxCount: 10 },
]), async (req, res, next) => {
  try {
    const productData = JSON.parse(req.body.productData || '{}');
    const existingProduct = await Product.findOne({ productId: productData.productId });
    if (existingProduct) {
      return res.status(400).json({ success: false, message: 'Product ID already exists' });
    }

    const uploadPromises = [];
    if (req.files.image && req.files.image[0]) {
      uploadPromises.push(
        new Promise((resolve, reject) => {
          uploadToGCS(req, req.files.image[0], (err, url) => {
            if (err) return reject(err);
            productData.imagePath = url;
            resolve();
          });
        })
      );
    }
    if (req.files['npsApprovalFiles[]']) {
      req.files['npsApprovalFiles[]'].forEach((file) => {
        uploadPromises.push(
          new Promise((resolve, reject) => {
            uploadToGCS(req, file, (err, url) => {
              if (err) return reject(err);
              productData.npsApproval = productData.npsApproval ? `${productData.npsApproval}, ${url}` : url;
              resolve();
            });
          })
        );
      });
    }
    if (req.files['msdsFiles[]']) {
      req.files['msdsFiles[]'].forEach((file) => {
        uploadPromises.push(
          new Promise((resolve, reject) => {
            uploadToGCS(req, file, (err, url) => {
              if (err) return reject(err);
              productData.msds = productData.msds ? `${productData.msds}, ${url}` : url;
              resolve();
            });
          })
        );
      });
    }
    if (req.files['certificationsFiles[]']) {
      req.files['certificationsFiles[]'].forEach((file) => {
        uploadPromises.push(
          new Promise((resolve, reject) => {
            uploadToGCS(req, file, (err, url) => {
              if (err) return reject(err);
              productData.certifications = productData.certifications || { qualityStandards: '' };
              productData.certifications.qualityStandards = productData.certifications.qualityStandards
                ? `${productData.certifications.qualityStandards}, ${url}`
                : url;
              resolve();
            });
          })
        );
      });
    }

    await Promise.all(uploadPromises);
    const product = new Product(productData);
    await product.save();
    res.json({ success: true, message: 'Product created successfully', product });
  } catch (error) {
    console.error('Create product error:', error.message, error.stack);
    res.status(500).json({ success: false, message: 'Failed to create product', error: error.message });
  }
});

app.put('/api/products/:productId', authenticateToken, upload.fields([
  { name: 'image', maxCount: 1 },
  { name: 'npsApprovalFiles', maxCount: 10 },
  { name: 'msdsFiles', maxCount: 10 },
  { name: 'certificationsFiles', maxCount: 10 },
]), async (req, res, next) => {
  try {
    const { productId } = req.params;
    const productData = JSON.parse(req.body.productData || '{}');
    const existingProduct = await Product.findOne({ productId });
    if (!existingProduct) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }

    const uploadPromises = [];
    if (req.files.image && req.files.image[0]) {
      uploadPromises.push(
        new Promise((resolve, reject) => {
          uploadToGCS(req, req.files.image[0], (err, url) => {
            if (err) return reject(err);
            productData.imagePath = url;
            resolve();
          });
        })
      );
    }
    if (req.files.npsApprovalFiles && req.files.npsApprovalFiles.length > 0) {
      req.files.npsApprovalFiles.forEach((file) => {
        uploadPromises.push(
          new Promise((resolve, reject) => {
            uploadToGCS(req, file, (err, url) => {
              if (err) return reject(err);
              productData.npsApproval = productData.npsApproval ? `${productData.npsApproval}, ${url}` : url;
              resolve();
            });
          })
        );
      });
    }
    if (req.files.msdsFiles && req.files.msdsFiles.length > 0) {
      req.files.msdsFiles.forEach((file) => {
        uploadPromises.push(
          new Promise((resolve, reject) => {
            uploadToGCS(req, file, (err, url) => {
              if (err) return reject(err);
              productData.msds = productData.msds ? `${productData.msds}, ${url}` : url;
              resolve();
            });
          })
        );
      });
    }
    if (req.files.certificationsFiles && req.files.certificationsFiles.length > 0) {
      req.files.certificationsFiles.forEach((file) => {
        uploadPromises.push(
          new Promise((resolve, reject) => {
            uploadToGCS(req, file, (err, url) => {
              if (err) return reject(err);
              productData.certifications = productData.certifications || { qualityStandards: '' };
              productData.certifications.qualityStandards = productData.certifications.qualityStandards
                ? `${productData.certifications.qualityStandards}, ${url}`
                : url;
              resolve();
            });
          })
        );
      });
    }

    await Promise.all(uploadPromises);
    const updatedProduct = await Product.findOneAndUpdate(
      { productId },
      { $set: productData },
      { new: true, runValidators: true }
    );
    res.json({ success: true, message: 'Product updated successfully', product: updatedProduct });
  } catch (error) {
    console.error('Update product error:', error.message, error.stack);
    res.status(500).json({ success: false, message: 'Failed to update product', error: error.message });
  }
});

app.delete('/api/products/:productId', authenticateToken, async (req, res) => {
  try {
    const { productId } = req.params;
    const product = await Product.findOne({ productId });
    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }
    await Batch.deleteMany({ productId });
    await Product.deleteOne({ productId });
    res.json({ success: true, message: 'Product and all associated batches deleted successfully' });
  } catch (error) {
    console.error('Delete product error:', error.message, error.stack);
    res.status(500).json({ success: false, message: 'Failed to delete product', error: error.message });
  }
});

app.post('/api/batches', authenticateToken, async (req, res) => {
  try {
    const { productId, number, manufacturingDate, expiryDate } = req.body;
    const product = await Product.findOne({ productId });
    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }
    const existingBatch = await Batch.findOne({ productId, number });
    if (existingBatch) {
      return res.status(400).json({ success: false, message: 'Batch number already exists for this product' });
    }
    const batch = new Batch({
      productId,
      number,
      manufacturingDate: manufacturingDate || null,
      expiryDate: expiryDate || null,
    });
    await batch.save();
    res.json({ success: true, message: 'Batch created successfully', batch });
  } catch (error) {
    console.error('Create batch error:', error.message, error.stack);
    res.status(500).json({ success: false, message: 'Failed to create batch', error: error.message });
  }
});

app.put('/api/batches/:batchId', authenticateToken, async (req, res) => {
  try {
    const { batchId } = req.params;
    const { number, manufacturingDate, expiryDate } = req.body;
    const batch = await Batch.findOne({ batchId });
    if (!batch) {
      return res.status(404).json({ success: false, message: 'Batch not found' });
    }
    if (number && number !== batch.number) {
      const existingBatch = await Batch.findOne({ productId: batch.productId, number, batchId: { $ne: batchId } });
      if (existingBatch) {
        return res.status(400).json({ success: false, message: 'Batch number already exists for this product' });
      }
    }
    const updatedBatch = await Batch.findOneAndUpdate(
      { batchId },
      {
        number: number || batch.number,
        manufacturingDate: manufacturingDate !== undefined ? manufacturingDate : batch.manufacturingDate,
        expiryDate: expiryDate !== undefined ? expiryDate : batch.expiryDate,
      },
      { new: true, runValidators: true }
    );
    res.json({ success: true, message: 'Batch updated successfully', batch: updatedBatch });
  } catch (error) {
    console.error('Update batch error:', error.message, error.stack);
    res.status(500).json({ success: false, message: 'Failed to update batch', error: error.message });
  }
});

app.delete('/api/batches/:batchId', authenticateToken, async (req, res) => {
  try {
    const { batchId } = req.params;
    const batch = await Batch.findOne({ batchId });
    if (!batch) {
      return res.status(404).json({ success: false, message: 'Batch not found' });
    }
    await Batch.findOneAndDelete({ batchId });
    res.json({ success: true, message: 'Batch deleted successfully' });
  } catch (error) {
    console.error('Delete batch error:', error.message, error.stack);
    res.status(500).json({ success: false, message: 'Failed to delete batch', error: error.message });
  }
});

app.get('/api/product-view/:batchId', async (req, res) => {
  try {
    const { batchId } = req.params;
    const batch = await Batch.findOne({ batchId });
    if (!batch) {
      return res.status(404).json({ success: false, message: 'Batch not found' });
    }
    const product = await Product.findOne({ productId: batch.productId });
    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }
    if (batch.expiryDate) {
      batch.isExpired = new Date() > new Date(batch.expiryDate);
      await batch.save();
    }
    res.json({ success: true, data: { ...product.toJSON(), batchInfo: batch.toJSON() } });
  } catch (error) {
    console.error('Get product view error:', error.message, error.stack);
    res.status(500).json({ success: false, message: 'Failed to fetch product information', error: error.message });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ success: false, message: 'File too large. Maximum size is 5MB.' });
    }
  }
  console.error('Unhandled error:', error.message, error.stack);
  res.status(500).json({ success: false, message: error.message || 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

// Start server
app.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  await initializeAdmin();
  await updateExistingBatches();
});

module.exports = app;