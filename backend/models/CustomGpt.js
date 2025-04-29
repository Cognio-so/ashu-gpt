const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const CustomGptSchema = new Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    description: {
        type: String,
        required: true,
        trim: true
    },
    instructions: {
        type: String,
        required: true,
        maxLength: 10000,
    },
    conversationStarter: {
        type: String,
        default: ""
    },
    model: {
        type: String,
        default: ""
    },
    capabilities: {
        type: Object,
        default: { webBrowsing: true }
    },
    imageUrl: {
        type: String,
        default: null
    },
    knowledgeFiles: [{
        name: String,
        fileUrl: String,
        fileType: String,
    }],
    createdBy: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    isPublic: {
        type: Boolean,
        default: false
    },
    folder: {
        type: String,
        trim: true,
        default: null
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
}, { timestamps: true });

// Add logging to debug Schema registration
const CustomGpt = mongoose.model('CustomGpt', CustomGptSchema);

module.exports = CustomGpt; 