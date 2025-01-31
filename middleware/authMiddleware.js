const jwt = require('jsonwebtoken');
const User = require('../models/User');

const isAdmin = async (req, res, next) => {
    try {
        // Get token from Authorization header
        const token = req.header('Authorization')?.replace('Bearer ', '');
        
        if (!token) {
            return res.status(401).json({ 
                success: false,
                message: 'No authentication token provided' 
            });
        }

        // Verify the JWT token
        let decoded;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET);
        } catch (verifyError) {
            console.error('Token Verification Error:', verifyError);
            return res.status(401).json({ 
                success: false,
                message: 'Invalid or expired token' 
            });
        }

        // Find the user by the decoded userId
        const user = await User.findById(decoded.userId);
        
        if (!user) {
            return res.status(401).json({ 
                success: false,
                message: 'User not found' 
            });
        }

        // Check if the user is an admin or superadmin
        if (!['admin', 'superadmin'].includes(user.role)) {
            return res.status(403).json({ 
                success: false,
                message: 'Access denied. Admin privileges required.' 
            });
        }

        // Attach the user information to the request for further use
        req.user = user;
        req.token = token;
        next();
    } catch (error) {
        console.error('Admin Middleware Error:', error);
        res.status(500).json({ 
            success: false,
            message: 'Internal server error' 
        });
    }
};

module.exports = isAdmin;
