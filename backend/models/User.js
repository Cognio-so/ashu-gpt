const mongoose = require('mongoose');
const Schema = mongoose.Schema;

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
    }]
}, {timestamps:true});
    
const User = mongoose.model('User', userSchema);

module.exports = User;
