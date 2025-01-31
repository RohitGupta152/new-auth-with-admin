const jwt = require('jsonwebtoken');
const User = require('../models/User');

const auth = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        
        if (!token) {
            return res.status(401).json({ 
                success: false,
                message: 'Authentication required' 
            });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Find user and check verification status
        const user = await User.findById(decoded.userId);
        
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

        req.userId = decoded.userId;
        req.user = user;
        next();
    } catch (error) {
        res.status(401).json({ 
            success: false,
            message: 'Invalid or expired token' 
        });
    }
};

module.exports = auth; 