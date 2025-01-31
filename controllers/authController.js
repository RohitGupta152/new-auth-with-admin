const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { sendVerificationEmail, sendResetPasswordEmail, sendLoginVerificationEmail } = require('../utils/emailService');


const register = async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Check if user already exists
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Create verification token
        const verificationToken = crypto.randomBytes(32).toString('hex');
        const verificationTokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        user = new User({
            name,
            email,
            password: hashedPassword,
            verificationToken,
            verificationTokenExpiry
        });

        await user.save();

        // Generate verification URL using frontend URL
        const verificationUrl = `${req.app.locals.FRONTEND_URL}/verify-email?token=${verificationToken}`;

        // Send email with verification link
        await sendVerificationEmail(user.email, verificationUrl);

        res.status(201).json({
            success: true,
            message: 'Registration successful. Please check your email to verify your account.'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Registration failed',
            error: error.message
        });
    }
};

const verifyEmail = async (req, res) => {
    try {
        const { token } = req.params;

        const user = await User.findOne({
            verificationToken: token,
            verificationTokenExpiry: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired verification token' });
        }

        user.isVerified = true;
        user.verificationToken = undefined;
        user.verificationTokenExpiry = undefined;
        await user.save();

        res.json({ message: 'Email verified successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
};

const login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ 
                success: false,
                message: 'User Not Found !! Please Register Your Account' 
            });
        }

        // Check if user is verified
        if (!user.isVerified) {
            return res.status(400).json({ 
                success: false,
                message: 'Please verify your email first',
                needsVerification: true 
            });
        }

        // Verify password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ 
                success: false,
                message: 'Invalid credentials' 
            });
        }

        // Generate login verification token
        const loginVerificationToken = crypto.randomBytes(32).toString('hex');
        user.loginVerificationToken = loginVerificationToken;
        user.loginVerificationTokenExpiry = Date.now() + 900000; // 15 minutes
        user.lastLoginAttempt = Date.now();

        await user.save();

        try {
            // Create verification URL using frontend URL
            const loginVerificationUrl = `${req.app.locals.FRONTEND_URL}/verify-login?token=${loginVerificationToken}`;
            
            // Send login verification email
            await sendLoginVerificationEmail(email, loginVerificationUrl);
            res.json({ 
                success: true,
                message: 'Please check your email to complete login',
                requiresVerification: true,
                email: user.email,
                verificationToken: loginVerificationToken // This will be stored in localStorage
            });
        } catch (emailError) {
            console.error('Login verification email failed:', emailError);
            return res.status(500).json({ 
                success: false,
                message: 'Error sending login verification email' 
            });
        }
    } catch (error) {
        res.status(500).json({ 
            success: false,
            message: 'Server error', 
            error: error.message 
        });
    }
};

const verifyLogin = async (req, res) => {
    try {
        const { token } = req.params;

        const user = await User.findOne({
            loginVerificationToken: token,
            loginVerificationTokenExpiry: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ 
                success: false,
                message: 'Invalid or expired login verification link' 
            });
        }

        // Clear login verification data
        user.loginVerificationToken = undefined;
        user.loginVerificationTokenExpiry = undefined;
        await user.save();

        // Generate JWT
        const jwtToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
            expiresIn: '1d'
        });

        // Send response with redirect URL
        res.json({ 
            success: true,
            message: 'Login successful',
            token: jwtToken,
            user: {
                id: user._id,
                name: user.name,
                email: user.email
            },
            redirectUrl: `${req.app.locals.FRONTEND_URL}/dashboard` // Redirect to dashboard after verification
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            message: 'Server error', 
            error: error.message 
        });
    }
};

const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ 
                success: false,
                message: 'No account found with this email' 
            });
        }

        // Check if user is verified
        if (!user.isVerified) {
            return res.status(400).json({
                success: false,
                message: 'Please verify your email first',
                needsVerification: true
            });
        }

        // Generate reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        user.resetPasswordToken = resetToken;
        user.resetPasswordExpiry = Date.now() + 3600000; // 1 hour

        await user.save();

        try {
            // Create reset password URL using frontend URL
            const resetPasswordUrl = `${req.app.locals.FRONTEND_URL}/reset-password?token=${resetToken}`;
            
            await sendResetPasswordEmail(email, resetPasswordUrl);
            res.json({ 
                success: true,
                message: 'Password reset instructions sent to your email',
                resetToken: resetToken // This will be stored in localStorage
            });
        } catch (emailError) {
            user.resetPasswordToken = undefined;
            user.resetPasswordExpiry = undefined;
            await user.save();
            
            return res.status(500).json({ 
                success: false,
                message: 'Error sending password reset email'
            });
        }
    } catch (error) {
        res.status(500).json({ 
            success: false,
            message: 'Server error', 
            error: error.message 
        });
    }
};

const resetPassword = async (req, res) => {
    try {
        const { token } = req.params;
        const { password, confirmPassword } = req.body;

        // Validate password requirements
        if (password.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 6 characters long'
            });
        }

        if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,}$/.test(password)) {
            return res.status(400).json({
                success: false,
                message: 'Password must contain at least one uppercase letter, one lowercase letter, and one number'
            });
        }

        // Validate password match
        if (password !== confirmPassword) {
            return res.status(400).json({ 
                success: false,
                message: 'Passwords do not match'
            });
        }

        // Find user with valid reset token
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpiry: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ 
                success: false,
                message: 'Invalid or expired password reset link'
            });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Update user password
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpiry = undefined;
        await user.save();

        res.json({ 
            success: true,
            message: 'Password reset successful. You can now login with your new password.',
            redirectUrl: `${req.app.locals.FRONTEND_URL}/login` // Redirect to login page
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            message: 'Server error', 
            error: error.message 
        });
    }
};

const checkEmail = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        
        if (!user) {
            return res.status(404).json({ 
                success: false,
                message: 'No account found with this email' 
            });
        }

        res.json({ 
            success: true,
            message: 'Account found',
            isVerified: user.isVerified
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            message: 'Server error', 
            error: error.message 
        });
    }
};

const resendVerification = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (user.isVerified) {
            return res.status(400).json({ message: 'Email is already verified' });
        }

        // Generate new verification token
        const verificationToken = crypto.randomBytes(32).toString('hex');
        user.verificationToken = verificationToken;
        user.verificationTokenExpiry = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

        await user.save();

        // Create verification URL using frontend URL
        const verificationUrl = `${req.app.locals.FRONTEND_URL}/verify-email?token=${verificationToken}`;

        // Send new verification email
        await sendVerificationEmail(email, verificationUrl);
        res.json({ 
            success: true,
            message: 'Verification email resent successfully' 
        });
    } catch (error) {
        res.status(500).json({ 
            success: false,
            message: 'Server error', 
            error: error.message 
        });
    }
};

const getUserProfile = async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('-password -verificationToken -resetPasswordToken -loginVerificationToken');
        
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
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: error.message
        });
    }
};


module.exports = {
    register,
    login,
    verifyEmail,
    forgotPassword,
    resetPassword,
    checkEmail,
    resendVerification,
    verifyLogin,
    getUserProfile
}; 