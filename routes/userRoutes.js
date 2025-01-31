// routes/userRoutes.js
const express = require('express');
const { body, validationResult } = require('express-validator');
const router = express.Router();

const auth = require('../middleware/auth');
const {
    getUserProfile,
    updateUserProfile,
    partialUpdateUserProfile,
    requestAccountDeletion,
    cancelAccountDeletionRequest,
    confirmAccountDeletion,
    resetPassword
} = require('../controllers/userController');


// Validation middleware
const validateRequest = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ 
            success: false, 
            errors: errors.array() 
        });
    }
    next();
};

// Get User Profile
router.get('/profile', auth, getUserProfile);

// Update Full Profile
router.put('/profile', [
    auth,
    body('name').optional().trim().isLength({ min: 2, max: 50 }).withMessage('Name must be 2-50 characters long'),
    body('mobileNumber').optional().isMobilePhone().withMessage('Invalid mobile number'),
    body('bio').optional().isLength({ max: 500 }).withMessage('Bio must be max 500 characters'),
    validateRequest
], updateUserProfile);

// Partial Profile Update
router.patch('/profile', [
    auth,
    body('name').optional().trim().isLength({ min: 2, max: 50 }).withMessage('Name must be 2-50 characters long'),
    body('bio').optional().isLength({ max: 500 }).withMessage('Bio must be max 500 characters'),
    validateRequest
], partialUpdateUserProfile);

// Request Account Deletion
router.post('/delete-account/request', [
    auth,
    body('reason')
        .optional()
        .trim()
        .isLength({ max: 500 })
        .withMessage('Reason must be max 500 characters'),
    validateRequest
], requestAccountDeletion);

// Cancel Account Deletion Request
router.post('/delete-account/cancel', auth, cancelAccountDeletionRequest);

// Confirm Account Deletion with Password
router.post('/delete-account/confirm', [
    auth,
    body('password')
        .notEmpty()
        .withMessage('Password is required for account deletion'),
    validateRequest
], confirmAccountDeletion);

// Password Reset Route
router.post('/reset-password', [
    auth,
    body('password').notEmpty().withMessage('Password is required').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
    body('confirmPassword').notEmpty().withMessage('Confirm Password is required'),
    validateRequest
], resetPassword);



module.exports = router;
