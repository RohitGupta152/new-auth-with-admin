// controllers/userController.js
const mongoose = require('mongoose');
const User = require('../models/User');
const DeletedUser = require('../models/DeletedUser');

const bcrypt = require('bcryptjs');
const crypto = require('crypto');


    // Get User Profile
    const getUserProfile = async (req, res) => {
        try {
            const user = await User.findById(req.userId).select('-password -verificationToken -resetPasswordToken -loginVerificationToken')
            .lean();

            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            if (!user.isVerified) {
                return res.status(403).json({
                    success: false,
                    message: 'Account not verified. Please verify your email first.'
                });
            }

            res.json({
                success: true,
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    role: user.role,
                    mobileNumber: user.mobileNumber || '', 
                    bio: user.bio || '',
                    isVerified: user.isVerified,
                    createdAt: user.createdAt,
                    updatedAt: user.updatedAt,
                    lastLoginAttempt: user.lastLoginAttempt
                }
            });
        } catch (error) {
            console.error('Get Profile Error:', error);
            res.status(500).json({
                success: false,
                message: 'Server error',
                error: error.message
            });
        }
    }

    // Update Full Profile
    const updateUserProfile = async (req, res) => {
        try {
            const { name, mobileNumber, bio } = req.body;

            const updateFields = {};
            if (name) updateFields.name = name;
            if (mobileNumber) updateFields.mobileNumber = mobileNumber;
            if (bio !== undefined) {
                updateFields.bio = bio.trim() || ''; // Trim whitespace, set to empty string if only whitespace
            }

            const updatedUser = await User.findByIdAndUpdate(
                req.userId, 
                { $set: updateFields }, 
                { 
                    new: true, 
                    runValidators: true 
                }
            ).select('-password');

            if (!updatedUser) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            res.json({
                success: true,
                message: 'Profile updated successfully',
                user: updatedUser
            });
        } catch (error) {
            console.error('Update Profile Error:', error);
            res.status(500).json({
                success: false,
                message: 'Server error',
                error: error.message
            });
        }
    }

    // Partial Profile Update
    const partialUpdateUserProfile = async (req, res) => {
        try {
            const updateFields = {};
            const allowedFields = ['name', 'bio'];

            // Only allow specific fields to be updated
            Object.keys(req.body).forEach(key => {
                if (allowedFields.includes(key)) {
                    updateFields[key] = req.body[key];
                }
            });

            const updatedUser = await User.findByIdAndUpdate(
                req.userId, 
                { $set: updateFields }, 
                { 
                    new: true, 
                    runValidators: true 
                }
            ).select('-password');

            if (!updatedUser) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            res.json({
                success: true,
                message: 'Profile partially updated',
                user: updatedUser
            });
        } catch (error) {
            console.error('Partial Update Error:', error);
            res.status(500).json({
                success: false,
                message: 'Server error',
                error: error.message
            });
        }
    }

    const requestAccountDeletion = async (req, res) => {
        try {
            const { reason } = req.body;
    
            // Check if user is already in deletion process
            const user = await User.findById(req.userId);
            
            if (user.accountDeletionRequest.requested) {
                return res.status(400).json({
                    success: false,
                    message: 'Account deletion request is already in progress'
                });
            }
    
            // Generate deletion token
            const deletionToken = crypto.randomBytes(32).toString('hex');
            const deletionTokenExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    
            // Update user with deletion request details
            await User.findByIdAndUpdate(req.userId, {
                $set: {
                    'accountDeletionRequest.requested': true,
                    'accountDeletionRequest.requestedAt': new Date(),
                    'accountDeletionRequest.reason': reason || '',
                    'accountDeletionRequest.deletionToken': deletionToken,
                    'accountDeletionRequest.deletionTokenExpiry': deletionTokenExpiry
                }
            });
    
            // Optional: Send email notification about deletion request
            // sendAccountDeletionRequestEmail(user.email, deletionToken);
    
            res.json({
                success: true,
                message: 'Account deletion request submitted. You have 7 days to cancel the request.',
                expiresAt: deletionTokenExpiry
            });
        } catch (error) {
            console.error('Account Deletion Request Error:', error);
            res.status(500).json({
                success: false,
                message: 'Server error',
                error: error.message
            });
        }
    };
    
    const cancelAccountDeletionRequest = async (req, res) => {
        try {
            const user = await User.findById(req.userId);
    
            if (!user.accountDeletionRequest.requested) {
                return res.status(400).json({
                    success: false,
                    message: 'No active account deletion request found'
                });
            }
    
            // Reset deletion request fields
            await User.findByIdAndUpdate(req.userId, {
                $set: {
                    'accountDeletionRequest.requested': false,
                    'accountDeletionRequest.requestedAt': null,
                    'accountDeletionRequest.reason': null,
                    'accountDeletionRequest.deletionToken': null,
                    'accountDeletionRequest.deletionTokenExpiry': null
                }
            });
    
            res.json({
                success: true,
                message: 'Account deletion request cancelled successfully'
            });
        } catch (error) {
            console.error('Cancel Deletion Request Error:', error);
            res.status(500).json({
                success: false,
                message: 'Server error',
                error: error.message
            });
        }
    };
    
    const confirmAccountDeletion = async (req, res) => {
        const session = await mongoose.startSession();
        
        try {
            // Start a database transaction
            await session.startTransaction();
    
            const { password } = req.body;
            const user = await User.findById(req.userId).session(session);
    
            // Validate password
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                await session.abortTransaction();
                return res.status(400).json({
                    success: false,
                    message: 'Invalid password. Account deletion Failed.'
                });
            }
    
            // Check if deletion request is active
            if (!user.accountDeletionRequest.requested) {
                await session.abortTransaction();
                return res.status(400).json({
                    success: false,
                    message: 'No active account deletion request found'
                });
            }
    
            // Create a copy of user's email in DeletedUser collection
            const deletedUser = new DeletedUser({
                originalUserId: user._id,
                email: user.email,
                originalUserData: {
                    // Preserve any specific fields you want
                    name: user.name,
                    email: user.email,
                    mobileNumber: user.mobileNumber,
                    createdAt: user.createdAt,
                    // Add other fields as needed
                }
            });
    
            // Save the deleted user record
            await deletedUser.save({ session });
    
            // Perform account deletion
            await User.findByIdAndDelete(req.userId, { session });
    
            // Commit the transaction
            await session.commitTransaction();
    
            res.json({
                success: true,
                message: 'Account deleted successfully'
            });
        } catch (error) {
            // Abort the transaction in case of any error
            await session.abortTransaction();
    
            console.error('Account Deletion Error:', error);
            res.status(500).json({
                success: false,
                message: 'Server error',
                error: error.message
            });
        } finally {
            // End the session
            session.endSession();
        }
    };

    // Reset Password
    const resetPassword = async (req, res) => {
    try {
        const { password, confirmPassword } = req.body;

        // Check if both passwords match
        if (password !== confirmPassword) {
            return res.status(400).json({
                success: false,
                message: 'Passwords do not match'
            });
        }

        // Validate password length (this is handled in the route validation but can be checked again here if needed)
        if (password.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 6 characters long'
            });
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Update the password in the database
        const updatedUser = await User.findByIdAndUpdate(
            req.userId,
            { password: hashedPassword },
            { new: true, runValidators: true }
        ).select('-password');  // Ensure the password isn't returned in the response

        if (!updatedUser) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            message: 'Password updated successfully'
        });
    } catch (error) {
        console.error('Password Reset Error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: error.message
        });
    }
    };

module.exports ={
    getUserProfile,
    updateUserProfile,
    partialUpdateUserProfile,
    requestAccountDeletion,
    cancelAccountDeletionRequest,
    confirmAccountDeletion,
    resetPassword
}
