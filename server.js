const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
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
}).then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB initial connection error:', err));

// Cloudinary Configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Cloudinary Storage for Images
const imageStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'famerce/products',
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
    transformation: [{ width: 800, height: 600, crop: 'limit', quality: 'auto' }],
  },
});

// Cloudinary Storage for Documents
const documentStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'famerce/documents',
    allowed_formats: ['pdf', 'doc', 'docx'],
    resource_type: 'raw',
  },
});

// Multer Configuration
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
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
  },
});

// Custom File Upload Handler
const handleFileUpload = (file, type = 'document') => {
  return new Promise((resolve, reject) => {
    const uploadOptions = {
      folder: type === 'image' ? 'famerce/products' : 'famerce/documents',
      resource_type: type === 'image' ? 'image' : 'raw',
    };
    if (type === 'image') {
      uploadOptions.transformation = [{ width: 800, height: 600, crop: 'limit', quality: 'auto' }];
    }
    cloudinary.uploader.upload_stream(uploadOptions, (error, result) => {
      if (error) {
        console.error(`Error uploading ${type}:`, error);
        reject(error);
      } else {
        resolve({
          secure_url: result.secure_url,
          public_id: result.public_id,
        });
      }
    }).end(file.buffer);
  });
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
  imagePath: String, // Store Cloudinary secure_url
  imagePublicId: String, // Store Cloudinary public_id for deletion
  npsApproval: String, // Store comma-separated secure_urls
  npsApprovalPublicIds: [String], // Store public_ids for deletion
  msds: String, // Store comma-separated secure_urls
  msdsPublicIds: [String], // Store public_ids for deletion
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
  certifications: {
    title: { type: String, default: 'Certifications' },
    qualityStandards: String, // Store comma-separated secure_urls
    qualityStandardsPublicIds: [String], // Store public_ids for deletion
  },
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

// Authentication Middleware
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

// File Access Routes

// Get file (image or document)
app.get('/api/files/:type/:publicId(*)', (req, res) => {
  try {
    const { type, publicId } = req.params;
    const folder = type === 'image' ? 'famerce/products' : 'famerce/documents';
    const resourceType = type === 'image' ? 'image' : 'raw';
    const cloudinaryUrl = cloudinary.url(`${folder}/${publicId}`, {
      resource_type: resourceType,
      secure: true,
    });
    res.redirect(cloudinaryUrl);
  } catch (error) {
    console.error('File access error:', error);
    res.status(500).json({ success: false, message: 'Failed to access file', error: error.message });
  }
});

// Get download URL for documents
app.get('/api/documents/download-url/:publicId(*)', async (req, res) => {
  try {
    const { publicId } = req.params;
    const downloadUrl = cloudinary.url(`famerce/documents/${publicId}`, {
      resource_type: 'raw',
      secure: true,
      flags: 'attachment',
    });
    res.json({ success: true, downloadUrl });
  } catch (error) {
    console.error('Download URL error:', error);
    res.status(500).json({ success: false, message: 'Failed to generate download URL', error: error.message });
  }
});

// Debug: List uploaded files
app.get('/api/debug/list-files/:type?', async (req, res) => {
  try {
    const { type } = req.params;
    const searchOptions = {
      type: 'upload',
      max_results: 50,
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
      created_at: resource.created_at,
    }));
    res.json({ success: true, files, total: result.total_count });
  } catch (error) {
    console.error('List files error:', error);
    res.status(500).json({ success: false, message: 'Failed to list files', error: error.message });
  }
});

// Product Routes

app.post('/api/products', authenticateToken, upload.fields([
  { name: 'image', maxCount: 1 },
  { name: 'npsApprovalFiles[]', maxCount: 10 },
  { name: 'msdsFiles[]', maxCount: 10 },
  { name: 'certificationsFiles[]', maxCount: 10 },
]), async (req, res) => {
  try {
    const productData = JSON.parse(req.body.productData || '{}');
    const existingProduct = await Product.findOne({ productId: productData.productId });
    if (existingProduct) {
      return res.status(400).json({ success: false, message: 'Product ID already exists' });
    }

    const uploadPromises = [];
    const publicIds = {
      imagePublicId: null,
      npsApprovalPublicIds: [],
      msdsPublicIds: [],
      qualityStandardsPublicIds: [],
    };

    // Upload image
    if (req.files.image && req.files.image[0]) {
      uploadPromises.push(
        handleFileUpload(req.files.image[0], 'image').then(result => {
          productData.imagePath = result.secure_url;
          publicIds.imagePublicId = result.public_id;
        })
      );
    }

    // Upload NPS approval files
    if (req.files['npsApprovalFiles[]']) {
      req.files['npsApprovalFiles[]'].forEach(file => {
        uploadPromises.push(
          handleFileUpload(file, 'document').then(result => {
            productData.npsApproval = productData.npsApproval ? `${productData.npsApproval}, ${result.secure_url}` : result.secure_url;
            publicIds.npsApprovalPublicIds.push(result.public_id);
          })
        );
      });
    }

    // Upload MSDS files
    if (req.files['msdsFiles[]']) {
      req.files['msdsFiles[]'].forEach(file => {
        uploadPromises.push(
          handleFileUpload(file, 'document').then(result => {
            productData.msds = productData.msds ? `${productData.msds}, ${result.secure_url}` : result.secure_url;
            publicIds.msdsPublicIds.push(result.public_id);
          })
        );
      });
    }

    // Upload certification files
    if (req.files['certificationsFiles[]']) {
      req.files['certificationsFiles[]'].forEach(file => {
        uploadPromises.push(
          handleFileUpload(file, 'document').then(result => {
            productData.certifications = productData.certifications || { qualityStandards: '' };
            productData.certifications.qualityStandards = productData.certifications.qualityStandards
              ? `${productData.certifications.qualityStandards}, ${result.secure_url}`
              : result.secure_url;
            publicIds.qualityStandardsPublicIds.push(result.public_id);
          })
        );
      });
    }

    await Promise.all(uploadPromises);
    const product = new Product({
      ...productData,
      imagePublicId: publicIds.imagePublicId,
      npsApprovalPublicIds: publicIds.npsApprovalPublicIds,
      msdsPublicIds: publicIds.msdsPublicIds,
      certifications: {
        ...productData.certifications,
        qualityStandardsPublicIds: publicIds.qualityStandardsPublicIds,
      },
    });
    await product.save();
    res.json({ success: true, message: 'Product created successfully', product });
  } catch (error) {
    console.error('Create product error:', error.message, error.stack);
    res.status(500).json({ success: false, message: 'Failed to create product', error: error.message });
  }
});

app.put('/api/products/:productId', authenticateToken, upload.fields([
  { name: 'image', maxCount: 1 },
  { name: 'npsApprovalFiles[]', maxCount: 10 },
  { name: 'msdsFiles[]', maxCount: 10 },
  { name: 'certificationsFiles[]', maxCount: 10 },
]), async (req, res) => {
  try {
    const { productId } = req.params;
    const productData = JSON.parse(req.body.productData || '{}');
    const existingProduct = await Product.findOne({ productId });
    if (!existingProduct) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }

    const uploadPromises = [];
    const publicIds = {
      imagePublicId: existingProduct.imagePublicId,
      npsApprovalPublicIds: existingProduct.npsApprovalPublicIds || [],
      msdsPublicIds: existingProduct.msdsPublicIds || [],
      qualityStandardsPublicIds: existingProduct.certifications?.qualityStandardsPublicIds || [],
    };

    // Upload new image (replace existing)
    if (req.files.image && req.files.image[0]) {
      uploadPromises.push(
        handleFileUpload(req.files.image[0], 'image').then(result => {
          productData.imagePath = result.secure_url;
          publicIds.imagePublicId = result.public_id;
          // Delete old image if it exists
          if (existingProduct.imagePublicId) {
            cloudinary.uploader.destroy(existingProduct.imagePublicId);
          }
        })
      );
    }

    // Upload new NPS approval files (append or replace)
    if (req.files['npsApprovalFiles[]']) {
      req.files['npsApprovalFiles[]'].forEach(file => {
        uploadPromises.push(
          handleFileUpload(file, 'document').then(result => {
            productData.npsApproval = productData.npsApproval ? `${productData.npsApproval}, ${result.secure_url}` : result.secure_url;
            publicIds.npsApprovalPublicIds.push(result.public_id);
          })
        );
      });
    }

    // Upload new MSDS files (append or replace)
    if (req.files['msdsFiles[]']) {
      req.files['msdsFiles[]'].forEach(file => {
        uploadPromises.push(
          handleFileUpload(file, 'document').then(result => {
            productData.msds = productData.msds ? `${productData.msds}, ${result.secure_url}` : result.secure_url;
            publicIds.msdsPublicIds.push(result.public_id);
          })
        );
      });
    }

    // Upload new certification files (append or replace)
    if (req.files['certificationsFiles[]']) {
      req.files['certificationsFiles[]'].forEach(file => {
        uploadPromises.push(
          handleFileUpload(file, 'document').then(result => {
            productData.certifications = productData.certifications || { qualityStandards: '' };
            productData.certifications.qualityStandards = productData.certifications.qualityStandards
              ? `${productData.certifications.qualityStandards}, ${result.secure_url}`
              : result.secure_url;
            publicIds.qualityStandardsPublicIds.push(result.public_id);
          })
        );
      });
    }

    await Promise.all(uploadPromises);
    const updatedProduct = await Product.findOneAndUpdate(
      { productId },
      {
        $set: {
          ...productData,
          imagePublicId: publicIds.imagePublicId,
          npsApprovalPublicIds: publicIds.npsApprovalPublicIds,
          msdsPublicIds: publicIds.msdsPublicIds,
          certifications: {
            ...productData.certifications,
            qualityStandardsPublicIds: publicIds.qualityStandardsPublicIds,
          },
        },
      },
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
    // Delete associated files from Cloudinary
    const publicIds = [
      product.imagePublicId,
      ...(product.npsApprovalPublicIds || []),
      ...(product.msdsPublicIds || []),
      ...(product.certifications?.qualityStandardsPublicIds || []),
    ].filter(id => id);
    if (publicIds.length > 0) {
      await cloudinary.api.delete_resources(publicIds);
    }
    await Batch.deleteMany({ productId });
    await Product.deleteOne({ productId });
    res.json({ success: true, message: 'Product and all associated files and batches deleted successfully' });
  } catch (error) {
    console.error('Delete product error:', error.message, error.stack);
    res.status(500).json({ success: false, message: 'Failed to delete product', error: error.message });
  }
});

// Other Routes (Signin, Signout, Batches, etc.)
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    cloudinary: process.env.CLOUDINARY_CLOUD_NAME ? 'configured' : 'not configured',
  });
});

app.post('/signin', async (req, res) => {
  try {
    const { username, password, rememberMe } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password are required' });
    }
    const user = await User.findOne({ username: username.trim() });
    if (!user || !await bcrypt.compare(password, user.password)) {
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
    res.json({ success: true, message: 'Login successful', user: { id: user._id, username: user.username, role: user.role }, token });
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
  res.json({ authenticated: true, user: { id: req.user.userId, username: req.user.username, role: req.user.role } });
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

// Initialize Admin User
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

// Error Handling Middleware
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ success: false, message: 'File too large. Maximum size is 10MB.' });
    }
  }
  console.error('Unhandled error:', error.message, error.stack);
  res.status(500).json({ success: false, message: error.message || 'Internal server error' });
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

// Start Server
app.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  console.log('🔗 Cloudinary file storage configured');
  console.log('📁 File access routes:');
  console.log('   GET  /api/files/:type/:publicId');
  console.log('   GET  /api/documents/download-url/:publicId');
  console.log('   GET  /api/debug/list-files/:type');
  await initializeAdmin();
});

module.exports = app;
