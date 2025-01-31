require('dotenv').config();
const express = require('express');
const cors = require('cors');
const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const adminRoutes = require('./routes/adminRoutes');

// Authentication Middleware
const auth = require('./middleware/auth');


const app = express();

// Connect to MongoDB
connectDB();

// Define allowed origins for CORS
const allowedOrigins = [
  process.env.FRONTEND_URL, // From .env (for local or production)
  'https://react-auth-with-admin.vercel.app/', // Your production frontend domain
];

// Middleware to handle CORS
app.use(cors({
  origin: (origin, callback) => {
    // Check if the origin is allowed
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true, // Allow cookies to be sent with the request
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true })); // For parsing form data

// Make frontend URL available globally
app.locals.FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

// Routes
app.use('/api/auth', authRoutes); // Auth for Users
app.use('/api/users', userRoutes); // Profile for Users

app.use('/api/admin', adminRoutes); // admin can access all the Users, changed it and Delete Users

app.get('/', (req, res) => {
  res.send('Hello, World!');
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        success: false,
        message: 'Something went wrong!',
        error: err.message
    });
});

// 404 handler
app.use((req, res, next) => {
    res.status(404).json({
        success: false,
        message: 'Route not found'
    });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
}); 
