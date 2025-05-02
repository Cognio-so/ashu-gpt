const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userFavoriteSchema = new Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    gpt: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'CustomGpt',
        required: true
    },
    folder: {
        type: String,
        default: 'Uncategorized'
    }
}, { timestamps: true });

// Add a compound index to make sure users can't favorite the same GPT twice
userFavoriteSchema.index({ user: 1, gpt: 1 }, { unique: true });

const UserFavorite = mongoose.model('UserFavorite', userFavoriteSchema);

module.exports = UserFavorite;
