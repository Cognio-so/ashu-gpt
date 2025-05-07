const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcryptjs');

const userSchema = new Schema({
    name:{
        type:String,
        required:true,
    },
    email:{
        type:String,
        required:true,
        unique:true,
    },
    password:{
        type:String,
        required:true,
        select: false
    },
    role:{
        type:String,
        enum:['admin','employee'],
        default:'employee',
    },  
    department: {
        type: String,
        default: 'Not Assigned'
    },
    profilePic: {
        type: String,
        default: null
    },
    lastActive: {
        type: Date,
        default: null
    },
    assignedGpts: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'CustomGpt'
    }],
    apiKeys: {
        type: Object,
        select: false,
        default: {}
    }
}, {timestamps:true});
    
// Password hash middleware
userSchema.pre('save', async function(next) {
    // Only hash the password if it's modified
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

const User = mongoose.model('User', userSchema);

module.exports = User;
