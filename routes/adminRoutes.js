const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const authMiddleware = require('../middleware/authMiddleware');  // Import the auth middleware
const auth = require('../middleware/auth');

const router = express.Router();

// Admin Register (to create a new admin or superadmin user)
router.post('/register', async (req, res) => {
    const { name, email, password, role, mobileNumber, bio } = req.body;

    if (!['admin', 'superadmin'].includes(role)) {
        return res.status(400).json({ message: 'Invalid role' });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            name,
            email,
            password: hashedPassword,
            role: role || 'user',
            mobileNumber,
            bio,
            isVerified: true
        });

        await newUser.save();
        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Admin Login (to issue JWT token)
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Validate input
        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email and password are required' 
            });
        }

        // Find user by email 
        const user = await User.findOne({ 
            email: { $regex: new RegExp(email, 'i') }
        });

        if (!user) {
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid admin credentials' 
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

        // Check if user is admin
        if (!['admin', 'superadmin'].includes(user.role)) {
            return res.status(403).json({ 
                success: false, 
                message: 'Access denied. Admin privileges required.' 
            });
        }

        // Generate JWT token with correct payload
        const token = jwt.sign(
            { 
                userId: user._id,  // Use userId instead of id
                email: user.email,
                role: user.role 
            }, 
            process.env.JWT_SECRET, 
            { expiresIn: '7d' }
        );

        res.status(200).json({ 
            success: true,
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Admin Login Error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error during admin login' 
        });
    }
});

router.get('/profile', authMiddleware , async (req, res) => {
    try {
        // req.user is already set by the isAdmin middleware
        const profile = await User.findById(req.user._id).select('-password');
        
        if (!profile) {
            return res.status(404).json({ 
                success: false, 
                message: 'Admin profile not found' 
            });
        }

        res.status(200).json({
            success: true,
            profile: {
                _id: profile._id,
                name: profile.name,
                email: profile.email,
                role: profile.role,
                mobileNumber: profile.mobileNumber,
                bio: profile.bio,
                isVerified: profile.isVerified,
                createdAt: profile.createdAt
            }
        });
    } catch (error) {
        res.status(500).json({ 
            success: false, 
            message: 'Server error',
            error: error.message 
        });
    }
});



// Admin Get All Users (only accessible by admins)
router.get('/users', auth, authMiddleware, async (req, res) => {
    try {
        // Fetch all users (excluding sensitive information)
        const users = await User.find({}, '-password').lean();
        
        res.json({
          success: true,
          users: users
        });
      } catch (error) {
        res.status(500).json({ 
          success: false, 
          message: 'Error fetching users' 
        });
      }
    });

// Admin Update User (only accessible by admins)
router.patch('/user/:id',auth, authMiddleware, async (req, res) => {
    const userId = req.params.id;
    const updates = Object.keys(req.body);
    const allowedUpdates = [ 'name' , 'email' , 'mobileNumber' , 'role', 'bio' , 'isVerified' ];

    const isValidOperation = updates.every(update => allowedUpdates.includes(update));
    if (!isValidOperation) {
        return res.status(400).json({ error: 'Invalid updates!' });
    }

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (user._id.toString() === req.user._id.toString()) {
            return res.status(400).json({ message: "Admins cannot modify their own role" });
        }

        updates.forEach(update => user[update] = req.body[update]);
        await user.save();
        res.status(200).json(user);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Admin Delete User (only accessible by admins)
router.delete('/user/:id',auth, authMiddleware, async (req, res) => {
    const userId = req.params.id;

    try {
        // Use `findByIdAndDelete` to delete the user
        const user = await User.findByIdAndDelete(userId);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Admin cannot delete their own account
        if (user._id.toString() === req.user._id.toString()) {
            return res.status(400).json({ message: "Admins cannot delete their own account" });
        }

        res.status(200).json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router;
