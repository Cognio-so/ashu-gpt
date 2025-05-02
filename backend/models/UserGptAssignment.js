const mongoose = require('mongoose');

const UserGptAssignmentSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  gptId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'CustomGpt',
    required: true
  },
  assignedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  assignedAt: {
    type: Date,
    default: Date.now
  },
  folder: {
    type: String,
    default: 'Uncategorized'
  }
}, { timestamps: true });

UserGptAssignmentSchema.index({ userId: 1, gptId: 1 }, { unique: true });

module.exports = mongoose.model('UserGptAssignment', UserGptAssignmentSchema);