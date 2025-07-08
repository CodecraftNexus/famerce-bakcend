const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;
const fetch = require('node-fetch');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

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

if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

// Cloudinary Configuration
if (!process.env.CLOUDINARY_CLOUD_NAME || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) {
  console.error('❌ Missing required Cloudinary environment variables');
  process.exit(1);
}

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true
});

cloudinary.api.ping()
  .then(() => console.log('🔗 Cloudinary configured successfully'))
  .catch((error) => {
    console.error('❌ Cloudinary configuration failed:', error.message);
    process.exit(1);
  });

// Multer Configuration
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { 
    fileSize: 50 * 1024 * 1024, // 50MB
    files: 50,
    fields: 20,
    fieldSize: 50 * 1024 * 1024,
    fieldNameSize: 200,
    headerPairs: 2000
  },
  fileFilter: (req, file, cb) => {
    console.log('🔍 File filter check:', {
      fieldname: file.fieldname,
      mimetype: file.mimetype,
      originalname: file.originalname,
      size: file.size
    });

    if (file.fieldname === 'image') {
      if (file.mimetype.startsWith('image/')) {
        cb(null, true);
      } else {
        cb(new Error(`Invalid image file type: ${file.mimetype}. Only image files are allowed.`));
      }
    } else if (['npsApprovalFiles', 'msdsFiles', 'certificationsFiles', 'npsApprovalFiles[]', 'msdsFiles[]', 'certificationsFiles[]'].includes(file.fieldname)) {
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
      cb(null, true);
    }
  }
});

const uploadFields = upload.fields([
  { name: 'image', maxCount: 1 },
  { name: 'npsApprovalFiles', maxCount: 10 },
  { name: 'msdsFiles', maxCount: 10 },
  { name: 'certificationsFiles', maxCount: 10 },
  { name: 'npsApprovalFiles[]', maxCount: 10 },
  { name: 'msdsFiles[]', maxCount: 10 },
  { name: 'certificationsFiles[]', maxCount: 10 }
]);

// File Upload Handler
const handleFileUpload = async (file, type = 'document') => {
  console.log(`📤 Starting ${type} upload for file:`, {
    originalname: file.originalname,
    mimetype: file.mimetype,
    size: file.size
  });

  return new Promise((resolve, reject) => {
    const uploadOptions = {
      folder: type === 'image' ? 'fertilizer_products' : 'fertilizer_documents',
      resource_type: type === 'image' ? 'image' : 'raw',
      use_filename: true,
      unique_filename: true,
      timeout: 180000,
      public_id: type !== 'image' ? `documents/${Date.now()}_${file.originalname.replace(/[^a-zA-Z0-9.]/g, '_')}` : undefined
    };

    if (type === 'image') {
      uploadOptions.transformation = [{ width: 1200, height: 900, crop: 'limit', quality: 'auto:good' }];
    }

    const uploadStream = cloudinary.uploader.upload_stream(uploadOptions, (error, result) => {
      if (error) {
        console.error('❌ Cloudinary upload error:', error.message);
        reject(new Error(`Upload failed for ${file.originalname}: ${error.message}`));
      } else {
        console.log('✅ Upload success:', result.secure_url);
        resolve(result.secure_url);
      }
    });

    uploadStream.on('error', (error) => {
      console.error('❌ Upload stream error:', error);
      reject(new Error(`Upload stream failed for ${file.originalname}: ${error.message}`));
    });

    uploadStream.end(file.buffer);
  });
};

// Schemas
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, minlength: 3, maxlength: 50 },
  password: { type: String, required: true, minlength: 6 },
  role: { type: String, default: 'admin', enum: ['admin', 'user', 'manager'] },
  isActive: { type: Boolean, default: true },
  lastLogin: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

const User = mongoose.model('User', userSchema);

const productSchema = new mongoose.Schema({
  productId: { type: String, required: true, unique: true, trim: true, index: true },
  name: { type: String, required: true, trim: true, maxlength: 200 },
  shortDescription: { type: String, maxlength: 500 },
  fullDescription: { type: String, maxlength: 2000 },
  imagePath: String,
  npsApproval: String,
  msds: String,
  composition: {
    title: { type: String, default: "Composition" },
    ingredients: [{ name: String, percentage: String }],
    advantages: [String]
  },
  application: {
    title: { type: String, default: "Application Details" },
    instructions: [String],
    recommendedCrops: [String]
  },
  safety: {
    title: { type: String, default: "Safety Instructions" },
    ppe: { title: String, instructions: [String] },
    hygiene: { title: String, instructions: [String] }
  },
  certifications: { title: String, qualityStandards: String },
  contact: { title: String, address: String, phones: [String], email: String, website: String },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

productSchema.index({ name: 'text', shortDescription: 'text' });
productSchema.pre('save', function(next) { this.updatedAt = Date.now(); next(); });

const Product = mongoose.model('Product', productSchema);

const batchSchema = new mongoose.Schema({
  batchId: { type: String, unique: true, uppercase: true, index: true },
  productId: { type: String, required: true, ref: 'Product', index: true },
  number: { type: String, required: true, trim: true, maxlength: 100 },
  sampleNo: { type: String, trim: true, maxlength: 100 },
  manufacturingDate: { type: Date },
  expiryDate: { type: Date },
  availablePackageSizes: [String],
  isExpired: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  notes: { type: String, maxlength: 1000 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

batchSchema.index({ productId: 1, number: 1 }, { unique: true });
batchSchema.pre('save', async function(next) {
  this.updatedAt = Date.now();
  if (this.isNew && !this.batchId) {
    this.batchId = await generateShortBatchId();
  }
  if (this.expiryDate) {
    this.isExpired = new Date() > new Date(this.expiryDate);
  }
  next();
});

const Batch = mongoose.model('Batch', batchSchema);

async function generateShortBatchId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  for (let attempts = 0; attempts < 10; attempts++) {
    let batchId = '';
    for (let i = 0; i < 8; i++) {
      batchId += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    const existingBatch = await Batch.findOne({ batchId });
    if (!existingBatch) return batchId;
  }
  return 'B' + Date.now().toString(36).toUpperCase();
}

const JWT_SECRET = process.env.JWT_SECRET || 'farmers-fert-secret-key-' + Date.now();

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token || (req.headers.authorization && req.headers.authorization.split(' ')[1]);
  if (!token) return res.status(401).json({ success: false, message: 'Access token required' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// Process Product Data
const processProductData = (productData) => {
  if (productData.composition) {
    productData.composition.ingredients = productData.composition.ingredients?.filter(ing => ing.name && ing.percentage) || [];
    productData.composition.advantages = productData.composition.advantages?.filter(adv => adv && adv.trim()) || [];
  }
  if (productData.application) {
    productData.application.instructions = productData.application.instructions?.filter(inst => inst && inst.trim()) || [];
    productData.application.recommendedCrops = productData.application.recommendedCrops?.filter(crop => crop && crop.trim()) || [];
  }
  if (productData.safety) {
    productData.safety.ppe = productData.safety.ppe || {};
    productData.safety.ppe.instructions = productData.safety.ppe.instructions?.filter(inst => inst && inst.trim()) || [];
    productData.safety.hygiene = productData.safety.hygiene || {};
    productData.safety.hygiene.instructions = productData.safety.hygiene.instructions?.filter(inst => inst && inst.trim()) || [];
  }
  if (productData.contact) {
    productData.contact.phones = productData.contact.phones?.filter(phone => phone && phone.trim()) || [];
  }
  return productData;
};

// Validate Product Data
const validateProductData = (productData) => {
  const errors = [];
  if (!productData.name || !productData.name.trim()) errors.push('Product name is required');
  if (productData.composition?.ingredients) {
    productData.composition.ingredients.forEach((ingredient, index) => {
      if (!ingredient.name || !ingredient.percentage) {
        errors.push(`Ingredient ${index + 1}: Both name and percentage are required`);
      }
    });
  }
  if (productData.contact?.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(productData.contact.email.trim())) {
    errors.push('Invalid email format');
  }
  return errors;
};

// Enhanced Download Route
app.get('/api/download/:filename', async (req, res) => {
  try {
    const { filename } = req.params;
    const { download = 'true' } = req.query; // Add download query parameter
    console.log('📥 Download request for:', filename, 'Download mode:', download);

    if (!filename) {
      return res.status(400).json({ success: false, message: 'Filename is required' });
    }

    let publicId = decodeURIComponent(filename);
    let originalFilename = publicId;

    // Handle Cloudinary URL or relative path
    if (publicId.startsWith('https://res.cloudinary.com/')) {
      const urlParts = publicId.split('/');
      const uploadIndex = urlParts.findIndex(part => part === 'upload');
      if (uploadIndex !== -1) {
        let startIndex = uploadIndex + 1;
        if (urlParts[startIndex] && urlParts[startIndex].startsWith('v')) startIndex++;
        publicId = urlParts.slice(startIndex).join('/').replace(/\.[^/.]+$/, '');
        originalFilename = urlParts[urlParts.length - 1]; // Preserve original filename with extension
      }
    } else {
      publicId = publicId.replace(/\.[^/.]+$/, ''); // Remove extension for public_id
      originalFilename = publicId.split('/').pop() + '.pdf'; // Default to .pdf if no extension
    }

    console.log('📋 Extracted public_id:', publicId);

    try {
      // Get file metadata from Cloudinary
      const fileInfo = await cloudinary.api.resource(publicId, { resource_type: 'raw' });
      console.log('📋 File info:', {
        public_id: fileInfo.public_id,
        format: fileInfo.format,
        bytes: fileInfo.bytes
      });

      // Generate download URL
      const downloadUrl = cloudinary.url(publicId, {
        resource_type: 'raw',
        secure: true,
        sign_url: true,
        type: 'upload',
        flags: download === 'true' ? 'attachment' : undefined
      });

      if (download === 'true') {
        // Fetch and stream the file
        const response = await fetch(downloadUrl);
        if (!response.ok) throw new Error(`HTTP ${response.status}: ${response.statusText}`);

        // Use the original filename from Cloudinary or fallback
        const finalFilename = fileInfo.format ? `${originalFilename.split('.').slice(0, -1).join('.')}.${fileInfo.format}` : originalFilename;

        res.setHeader('Content-Type', response.headers.get('content-type') || 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${finalFilename}"`);
        res.setHeader('Content-Length', response.headers.get('content-length') || fileInfo.bytes);
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');

        console.log('✅ Streaming download:', finalFilename);
        response.body.pipe(res);
      } else {
        // Redirect for preview
        console.log('👁️ Redirecting for preview:', downloadUrl);
        res.redirect(downloadUrl);
      }
    } catch (cloudError) {
      console.error('❌ Cloudinary API error:', cloudError.message);
      // Fallback to direct URL
      const directUrl = `https://res.cloudinary.com/${process.env.CLOUDINARY_CLOUD_NAME}/raw/upload/${publicId}`;
      const response = await fetch(directUrl);
      if (!response.ok) throw new Error(`Direct URL failed: HTTP ${response.status}`);

      res.setHeader('Content-Type', response.headers.get('content-type') || 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${originalFilename}"`);
      response.body.pipe(res);
    }
  } catch (error) {
    console.error('❌ Download error:', error);
    res.status(500).json({ success: false, message: `Download failed: ${error.message}` });
  }
});

// Signed URL Generation Route
app.post('/api/documents/get-signed-url', authenticateToken, async (req, res) => {
  try {
    const { filePath } = req.body;
    console.log('🔐 Generating signed URL for:', filePath);

    if (!filePath) return res.status(400).json({ success: false, message: 'File path is required' });

    let publicId = filePath.trim();
    let originalFilename = publicId.split('/').pop();

    if (publicId.startsWith('https://res.cloudinary.com/')) {
      const urlParts = publicId.split('/');
      const uploadIndex = urlParts.findIndex(part => part === 'upload');
      if (uploadIndex !== -1) {
        let startIndex = uploadIndex + 1;
        if (urlParts[startIndex] && urlParts[startIndex].startsWith('v')) startIndex++;
        publicId = urlParts.slice(startIndex).join('/').replace(/\.[^/.]+$/, '');
        originalFilename = urlParts[urlParts.length - 1];
      }
    } else {
      publicId = publicId.replace(/\.[^/.]+$/, '');
    }

    console.log('📋 Extracted public_id:', publicId);

    const signedUrl = cloudinary.url(publicId, {
      resource_type: 'raw',
      secure: true,
      sign_url: true,
      type: 'upload',
      flags: 'attachment'
    });

    res.json({
      success: true,
      signedUrl,
      serverDownloadUrl: `/api/download/${encodeURIComponent(filePath)}`,
      fileInfo: { publicId, originalPath: filePath, originalFilename }
    });
  } catch (error) {
    console.error('❌ Signed URL generation error:', error);
    res.status(500).json({ success: false, message: `Failed to generate signed URL: ${error.message}` });
  }
});

// Health Check
app.get('/health', async (req, res) => {
  try {
    const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
    const productCount = await Product.countDocuments();
    const batchCount = await Batch.countDocuments();

    res.json({ 
      status: 'OK', 
      timestamp: new Date().toISOString(),
      database: { status: dbStatus, products: productCount, batches: batchCount },
      storage: 'cloudinary',
      environment: process.env.NODE_ENV || 'development'
    });
  } catch (error) {
    res.status(500).json({ status: 'ERROR', message: error.message });
  }
});

// Authentication Routes
app.post('/signin', async (req, res) => {
  try {
    const { username, password, rememberMe } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: 'Username and password required' });

    const user = await User.findOne({ username: username.trim(), isActive: true });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign({ userId: user._id, username: user.username, role: user.role }, JWT_SECRET, {
      expiresIn: rememberMe ? '30d' : '24h'
    });

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000
    });

    res.json({ success: true, message: 'Login successful', user: { id: user._id, username: user.username, role: user.role }, token });
  } catch (error) {
    console.error('Signin error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
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
    if (!user || !user.isActive) return res.status(401).json({ authenticated: false });
    res.json({ authenticated: true, user: { id: user._id, username: user.username, role: user.role, lastLogin: user.lastLogin } });
  } catch (error) {
    console.error('Auth check error:', error);
    res.status(500).json({ authenticated: false });
  }
});

// Product Routes
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
        const batches = await Batch.find({ productId: product.productId, isActive: true }).sort({ createdAt: -1 });
        const summary = {
          activeBatches: 0,
          expiredBatches: 0,
          expiringSoon: 0
        };
        const now = new Date();
        batches.forEach(batch => {
          if (batch.isExpired || (batch.expiryDate && new Date(batch.expiryDate) <= now)) {
            summary.expiredBatches++;
          } else if (batch.expiryDate && Math.ceil((new Date(batch.expiryDate) - now) / (1000 * 60 * 60 * 24)) <= 30) {
            summary.expiringSoon++;
          } else {
            summary.activeBatches++;
          }
        });
        return { ...product.toJSON(), batches, summary };
      })
    );

    const total = await Product.countDocuments(query);
    res.json({ success: true, products: productsWithBatches, pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / limit) } });
  } catch (error) {
    console.error('Get products error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch products', error: error.message });
  }
});

app.post('/api/products', authenticateToken, uploadFields, async (req, res) => {
  try {
    let productData = JSON.parse(req.body.productData);
    if (!productData.productId || !productData.name) return res.status(400).json({ success: false, message: 'Product ID and name required' });

    const existingProduct = await Product.findOne({ productId: productData.productId });
    if (existingProduct) return res.status(400).json({ success: false, message: 'Product ID already exists' });

    productData = processProductData(productData);
    const validationErrors = validateProductData(productData);
    if (validationErrors.length > 0) return res.status(400).json({ success: false, message: 'Validation failed', errors: validationErrors });

    if (req.files?.image?.[0]) productData.imagePath = await handleFileUpload(req.files.image[0], 'image');
    if (req.files?.npsApprovalFiles?.length) {
      productData.npsApproval = (await Promise.all(req.files.npsApprovalFiles.map(file => handleFileUpload(file, 'documents')))).join(', ');
    }
    if (req.files?.msdsFiles?.length) {
      productData.msds = (await Promise.all(req.files.msdsFiles.map(file => handleFileUpload(file, 'documents')))).join(', ');
    }
    if (req.files?.certificationsFiles?.length) {
      productData.certifications = { qualityStandards: (await Promise.all(req.files.certificationsFiles.map(file => handleFileUpload(file, 'documents')))).join(', ') };
    }

    const product = new Product(productData);
    await product.save();

    res.json({ success: true, message: 'Product created successfully', product });
  } catch (error) {
    console.error('Create product error:', error);
    res.status(500).json({ success: false, message: 'Failed to create product', error: error.message });
  }
});

app.put('/api/products/:productId', authenticateToken, uploadFields, async (req, res) => {
  try {
    const { productId } = req.params;
    let productData = JSON.parse(req.body.productData);

    const existingProduct = await Product.findOne({ productId });
    if (!existingProduct) return res.status(404).json({ success: false, message: 'Product not found' });

    productData = processProductData(productData);
    const validationErrors = validateProductData(productData);
    if (validationErrors.length > 0) return res.status(400).json({ success: false, message: 'Validation failed', errors: validationErrors });

    if (req.files?.image?.[0]) {
      productData.imagePath = await handleFileUpload(req.files.image[0], 'image');
    } else {
      productData.imagePath = existingProduct.imagePath;
    }
    if (req.files?.npsApprovalFiles?.length) {
      productData.npsApproval = (await Promise.all(req.files.npsApprovalFiles.map(file => handleFileUpload(file, 'documents')))).join(', ');
    } else {
      productData.npsApproval = existingProduct.npsApproval;
    }
    if (req.files?.msdsFiles?.length) {
      productData.msds = (await Promise.all(req.files.msdsFiles.map(file => handleFileUpload(file, 'documents')))).join(', ');
    } else {
      productData.msds = existingProduct.msds;
    }
    if (req.files?.certificationsFiles?.length) {
      productData.certifications = { qualityStandards: (await Promise.all(req.files.certificationsFiles.map(file => handleFileUpload(file, 'documents')))).join(', ') };
    } else {
      productData.certifications = existingProduct.certifications;
    }

    const updatedProduct = await Product.findOneAndUpdate({ productId }, productData, { new: true, runValidators: true });
    if (!updatedProduct) return res.status(404).json({ success: false, message: 'Product not found during update' });

    res.json({ success: true, message: 'Product updated successfully', product: updatedProduct });
  } catch (error) {
    console.error('Update product error:', error);
    res.status(500).json({ success: false, message: 'Failed to update product', error: error.message });
  }
});

app.delete('/api/products/:productId', authenticateToken, async (req, res) => {
  try {
    const { productId } = req.params;
    const product = await Product.findOne({ productId });
    if (!product) return res.status(404).json({ success: false, message: 'Product not found' });

    await Product.findOneAndUpdate({ productId }, { isActive: false });
    await Batch.updateMany({ productId }, { isActive: false });

    res.json({ success: true, message: 'Product and associated batches deleted successfully' });
  } catch (error) {
    console.error('Delete product error:', error);
    res.status(500).json({ success: false, message: 'Failed to delete product', error: error.message });
  }
});

// Batch Routes
app.get('/api/batches', authenticateToken, async (req, res) => {
  try {
    const { productId, page = 1, limit = 50 } = req.query;
    let query = { isActive: true };
    if (productId) query.productId = productId;

    const batches = await Batch.find(query).sort({ createdAt: -1 }).limit(limit * 1).skip((page - 1) * limit);
    const total = await Batch.countDocuments(query);

    res.json({ success: true, batches, pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / limit) } });
  } catch (error) {
    console.error('Get batches error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch batches', error: error.message });
  }
});

app.post('/api/batches', authenticateToken, async (req, res) => {
  try {
    const { productId, number, manufacturingDate, expiryDate, sampleNo, availablePackageSizes, notes } = req.body;
    if (!productId || !number) return res.status(400).json({ success: false, message: 'Product ID and batch number required' });

    const product = await Product.findOne({ productId, isActive: true });
    if (!product) return res.status(404).json({ success: false, message: 'Product not found' });

    const existingBatch = await Batch.findOne({ productId, number: number.trim(), isActive: true });
    if (existingBatch) return res.status(400).json({ success: false, message: 'Batch number already exists for this product' });

    const batch = new Batch({
      productId,
      number: number.trim(),
      sampleNo: sampleNo?.trim(),
      manufacturingDate: manufacturingDate || null,
      expiryDate: expiryDate || null,
      availablePackageSizes: availablePackageSizes || [],
      notes: notes?.trim()
    });

    await batch.save();
    res.json({ success: true, message: 'Batch created successfully', batch });
  } catch (error) {
    console.error('Create batch error:', error);
    res.status(500).json({ success: false, message: 'Failed to create batch', error: error.message });
  }
});

app.put('/api/batches/:batchId', authenticateToken, async (req, res) => {
  try {
    const { batchId } = req.params;
    const { number, manufacturingDate, expiryDate, sampleNo, availablePackageSizes, notes } = req.body;

    const batch = await Batch.findOne({ batchId, isActive: true });
    if (!batch) return res.status(404).json({ success: false, message: 'Batch not found' });

    if (number && number.trim() !== batch.number) {
      const existingBatch = await Batch.findOne({ productId: batch.productId, number: number.trim(), batchId: { $ne: batchId }, isActive: true });
      if (existingBatch) return res.status(400).json({ success: false, message: 'Batch number already exists for this product' });
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

    res.json({ success: true, message: 'Batch updated successfully', batch: updatedBatch });
  } catch (error) {
    console.error('Update batch error:', error);
    res.status(500).json({ success: false, message: 'Failed to update batch', error: error.message });
  }
});

app.delete('/api/batches/:batchId', authenticateToken, async (req, res) => {
  try {
    const { batchId } = req.params;
    const batch = await Batch.findOne({ batchId, isActive: true });
    if (!batch) return res.status(404).json({ success: false, message: 'Batch not found' });

    await Batch.findOneAndUpdate({ batchId }, { isActive: false });
    res.json({ success: true, message: 'Batch deleted successfully' });
  } catch (error) {
    console.error('Delete batch error:', error);
    res.status(500).json({ success: false, message: 'Failed to delete batch', error: error.message });
  }
});

// Product View Route
app.get('/api/product-view/:batchId', async (req, res) => {
  try {
    const { batchId } = req.params;
    const batch = await Batch.findOne({ batchId, isActive: true });
    if (!batch) return res.status(404).json({ success: false, message: 'Batch not found or inactive' });

    const product = await Product.findOne({ productId: batch.productId, isActive: true });
    if (!product) return res.status(404).json({ success: false, message: 'Product not found or inactive' });

    if (batch.expiryDate) {
      const isExpired = new Date() > new Date(batch.expiryDate);
      if (batch.isExpired !== isExpired) {
        batch.isExpired = isExpired;
        await batch.save();
      }
    }

    res.json({ success: true, data: { ...product.toJSON(), batchInfo: batch.toJSON() } });
  } catch (error) {
    console.error('Get product view error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch product information', error: error.message });
  }
});

// Analytics Route
app.get('/api/analytics/dashboard', authenticateToken, async (req, res) => {
  try {
    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

    const stats = {
      totalProducts: await Product.countDocuments({ isActive: true }),
      totalBatches: await Batch.countDocuments({ isActive: true }),
      expiredBatches: await Batch.countDocuments({ isActive: true, isExpired: true }),
      expiringSoon: await Batch.countDocuments({ 
        isActive: true, 
        isExpired: false,
        expiryDate: { $lte: new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000) }
      }),
      recentProducts: await Product.countDocuments({ isActive: true, createdAt: { $gte: thirtyDaysAgo } }),
      recentBatches: await Batch.countDocuments({ isActive: true, createdAt: { $gte: thirtyDaysAgo } })
    };

    res.json({ success: true, stats });
  } catch (error) {
    console.error('Analytics error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch analytics', error: error.message });
  }
});

// Error Handling Middleware
app.use((error, req, res, next) => {
  console.error('🚨 Unhandled error:', error);

  if (error instanceof multer.MulterError) {
    return res.status(400).json({ success: false, message: `File upload error: ${error.message}`, errorCode: error.code });
  }
  if (error.name === 'ValidationError') {
    return res.status(400).json({ success: false, message: 'Validation error', errors: Object.values(error.errors).map(err => err.message) });
  }
  if (error.code === 11000) {
    return res.status(400).json({ success: false, message: 'Duplicate entry detected', errorCode: 'DUPLICATE_ENTRY' });
  }
  res.status(500).json({ success: false, message: 'Internal server error', error: process.env.NODE_ENV === 'development' ? error.stack : undefined });
});

// 404 Handler
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
      'GET /api/download/:filename',
      'POST /api/documents/get-signed-url'
    ]
  });
});

// Graceful Shutdown
process.on('SIGTERM', async () => {
  console.log('🔄 SIGTERM received, shutting down...');
  await mongoose.connection.close();
  console.log('✅ Database connection closed');
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('🔄 SIGINT received, shutting down...');
  await mongoose.connection.close();
  console.log('✅ Database connection closed');
  process.exit(0);
});

// Initialize Admin and Start Server
app.listen(PORT, async () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log('🔗 Enhanced Cloudinary file storage configured');
  console.log(`☁️ Cloud name: ${process.env.CLOUDINARY_CLOUD_NAME}`);
  console.log('🔧 API Routes:');
  console.log('   GET  /health - Health check');
  console.log('   POST /signin - User authentication');
  console.log('   POST /signout - User logout');
  console.log('   GET  /api/products - Get all products');
  console.log('   POST /api/products - Create product');
  console.log('   PUT  /api/products/:productId - Update product');
  console.log('   DELETE /api/products/:productId - Delete product');
  console.log('   GET  /api/batches - Get batches');
  console.log('   POST /api/batches - Create batch');
  console.log('   PUT  /api/batches/:batchId - Update batch');
  console.log('   DELETE /api/batches/:batchId - Delete batch');
  console.log('   GET  /api/product-view/:batchId - Public product view');
  console.log('   GET  /api/analytics/dashboard - Analytics');
  console.log('   GET  /api/download/:filename - Download file');
  console.log('   POST /api/documents/get-signed-url - Generate signed URLs');

  await initializeAdmin();
  await updateExistingBatches();
  console.log('✅ Server initialization complete!');
});

async function initializeAdmin() {
  const adminExists = await User.findOne({ username: 'admin' });
  if (!adminExists) {
    await new User({ username: 'admin', password: 'admin123', role: 'admin' }).save();
    console.log('✅ Default admin created: username=admin, password=admin123');
  } else {
    console.log('✅ Admin user already exists');
  }
}

async function updateExistingBatches() {
  const batches = await Batch.find({ $or: [{ batchId: { $exists: false } }, { batchId: null }, { batchId: '' }] });
  for (let batch of batches) {
    batch.batchId = await generateShortBatchId();
    await batch.save();
    console.log(`✅ Updated batch ${batch.number} with batchId: ${batch.batchId}`);
  }
  console.log('✅ All batches updated');
}
