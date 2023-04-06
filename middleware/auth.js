require('dotenv').config();
const path = require('path');
const jwt = require('jsonwebtoken');
const User = require('../models/model');

const promptPath = path.join(__dirname,"../templates/views/prompt.hbs");

const auth = async(req,res,next) =>{
    try{
       const token = req.cookies.jwt;
       const verifyUser = await jwt.verify(token,process.env.SECRET_KEY);
    //    console.log(verifyUser); 
       const userData = await User.findOne({_id : verifyUser._id});
       req.userData = userData;
       req.token = token;
    //    console.log(userData);
       next(); 
    }catch(err){
       console.log(err);
       res.render(promptPath,{promptMessage:"Seems like you are not logged into the system yet, please login with your necessary details. Still problems persist, do not hesitate to contact our experts."});
    }
}

module.exports = auth;