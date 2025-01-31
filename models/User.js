const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true,
        minlength: [6, 'Password must be at least 6 characters long'],
        validate: {
            validator: function(password) {
                // At least one uppercase, one lowercase, one number
                return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,}$/.test(password);
            },
            message: 'Password must contain at least one uppercase letter, one lowercase letter, and one number'
        }
    },
    mobileNumber: {
        type: String,
        trim: true,
        validate: {
            validator: function(v) {
                // Validate Indian mobile numbers with +91 or without
                // Supports formats: 
                // +919876543210
                // 9876543210
                // 09876543210
                const indianMobileRegex = /^(\+91|0)?[6-9]\d{9}$/;
                return indianMobileRegex.test(v);
            },
            message: props => `${props.value} is not a valid Indian mobile number!`
        },
        required: [false, 'User phone number']
    },
    bio: {
        type: String,
        trim: true,
        maxlength: [500, 'Bio cannot exceed 500 characters']
    },
    role: {
        type: String,
        enum: ['user', 'admin', 'superadmin'],
        default: 'user'
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    verificationToken: String,
    verificationTokenExpiry: Date,
    resetPasswordToken: String,
    resetPasswordExpiry: Date,
    loginVerificationToken: String,
    loginVerificationTokenExpiry: Date,
    lastLoginAttempt: Date,
    accountDeletionRequest: {
        requested: {
            type: Boolean,
            default: false
        },
        requestedAt: {
            type: Date,
            default: null
        },
        reason: {
            type: String,
            trim: true,
            maxlength: 500
        },
        deletionToken: {
            type: String,
            default: null
        },
        deletionTokenExpiry: {
            type: Date,
            default: null
        }
    }
}, {
    timestamps: true
});

// Pre-save hook to standardize mobile number
userSchema.pre('save', function(next) {
    if (this.mobileNumber) {
        // Remove all non-digit characters
        let cleanedNumber = this.mobileNumber.replace(/\D/g, '');
        
        // If number starts with 0, remove it
        if (cleanedNumber.startsWith('0')) {
            cleanedNumber = cleanedNumber.slice(1);
        }
        
        // If number doesn't start with 91, prepend it
        if (!cleanedNumber.startsWith('91')) {
            cleanedNumber = '91' + cleanedNumber;
        }
        
        // Final format with +91
        this.mobileNumber = '+' + cleanedNumber;
    }
    next();
});

// Method to format mobile number
userSchema.methods.formatMobileNumber = function() {
    if (!this.mobileNumber) return null;
    
    // Remove +91 and format
    const number = this.mobileNumber.replace('+91', '');
    return `+91 ${number.slice(0,5)} ${number.slice(5)}`;
};

// Additional method to mask mobile number
userSchema.methods.maskedMobileNumber = function() {
    if (!this.mobileNumber) return null;
    
    const number = this.mobileNumber.replace('+91', '');
    return `+91 ${number.slice(0,2)}xxx ${number.slice(-4)}`;
};


// Add role-based methods
userSchema.methods.hasPermission = function(permission) {
    // Check if user has specific permission
    return this.permissions.includes(permission);
};

userSchema.methods.isAdmin = function() {
    return ['admin', 'superadmin'].includes(this.role);
};

userSchema.methods.isSuperAdmin = function() {
    return this.role === 'superadmin';
};

module.exports = mongoose.model('User', userSchema); 