// models/DeletedUser.js
const mongoose = require('mongoose');

const deletedUserSchema = new mongoose.Schema({
    originalUserId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true
    },
    email: {
        type: String,
        required: true,
        trim: true,
        lowercase: true
    },
    deletedAt: {
        type: Date,
        default: Date.now
    },
    // You can add more fields you want to preserve
    originalUserData: {
        type: mongoose.Schema.Types.Mixed
    }
}, {
    timestamps: true
});

module.exports = mongoose.model('DeletedUser', deletedUserSchema);