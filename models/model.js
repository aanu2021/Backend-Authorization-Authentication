require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const valid = require('validator');
const jwt = require('jsonwebtoken');

const userSchema = new mongoose.Schema({
   firstName : {
      type : String,
      required : true,
   },
   lastName : {
      type : String,
      required : true,
   },
   email : {
      type : String,
      required : true,
      unique : true,
      validate : {
         validator(value){
            if(!valid.isEmail(value)){
               return false;
            }
            else{
               return true;
            }
         },message:"Email formation is incorrect, try again...",
      }
   },
   password : {
      type : String,
      required : true,
      validate : {
         validator(value){
            if(valid.isStrongPassword(value,{
               minLength : 5,
               minLowercase : 1,
               minUppercase : 1,
               minNumbers : 1,
               minSymbols : 1,
            })){
               return true;
            }
            else{
               return false;
            }
         },message:"Your password is not strong enough, try again..."
      }
   },
   tokens : [{
      token : {
         type : String,
         required : true
      }
   }]
})

// Authorize the current user by generating a jwt token corresponding to the user.

userSchema.methods.generateAuthToken = async function(){

   try{
      const token = await jwt.sign({_id : this._id.toString()},process.env.SECRET_KEY);
      this.tokens = this.tokens.concat({token : token});
      // To save all possible changes in our schema
      await this.save();
      // console.log(token);
      return token; 
   }catch(err){
      console.log(err);
   }

}


// Before saving current user's details in our database we need to hash their password using bcrypt.hash method.

userSchema.pre('save',async function(next){
    if(this.isModified('password')){
      this.password = await bcrypt.hash(this.password,10);
    }
    next();
})

const User = new mongoose.model('Userlist',userSchema);
module.exports = User;