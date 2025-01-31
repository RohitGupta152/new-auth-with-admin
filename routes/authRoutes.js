const express = require('express');
const router = express.Router();
const { 
    register, 
    login, 
    verifyEmail, 
    forgotPassword, 
    resetPassword,
    checkEmail,
    resendVerification,
    verifyLogin,
    getUserProfile
} = require('../controllers/authController');

const auth = require('../middleware/auth');

// Public routes
router.post('/register', register);
router.get('/verify/:token', verifyEmail);

router.post('/login', login);
router.get('/verify-login/:token', verifyLogin);

router.post('/check-email', checkEmail);
router.post('/resend-verification', resendVerification);

router.post('/forgot-password', forgotPassword);
router.post('/reset-password/:token', resetPassword);


// Protected routes
router.get('/profile', auth, getUserProfile);



module.exports = router; 