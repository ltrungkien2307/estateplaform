const mongoose = require('mongoose');
const bycrypt = require('bcryptjs');

//create user schema
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required:[true, 'Name is required'],
  },
  email:{
    type: String,
    required:[true, 'Email is required'],
    unique: true,
    lowercase: true,
  },
  password:{
    type: String,
    required:[true, 'Password is required'],
    minlength: 8,
    select:false,
    trim: true,
  },
  role:{
    type: String,
    enum: ['user', 'admin', 'provider'],
    default: 'user',
  },
  address:{
    type: String,
    required:[true, 'Address is required'],
  },
  phone: String,
  avatar: String,
  isVerified:{
    type: Boolean,
    default: false,
  },
  kycDocuments: {
    type: [String],
    default: [],
  },
  createdAt:{
    type: Date,
    default: Date.now,
  },
});

//hash password before saving to database
userSchema.pre('save', async function(next){
  if(!this.isModified('password')) return next();
  this.password = await bycrypt.hash(this.password, 12);
  next();
});
//check passwrord method for login
userSchema.methods.correctPassword = async function(candidatePassword, userPassword){
  return await bycrypt.compare(candidatePassword, userPassword);
}
module.exports = mongoose.model('User', userSchema);