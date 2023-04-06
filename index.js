require('dotenv').config();
const express = require('express');
const app = express();
const path = require('path');
const mongoose = require('mongoose');
const hbs = require('hbs');
const User = require('./models/model.js');
const auth = require('./middleware/auth.js');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const valid = require('validator');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');


const port = process.env.PORT||3000;
const staticPath = path.join(__dirname,"public");
const templatePath = path.join(__dirname,"templates/views");
const partialPath = path.join(__dirname,"templates/partials");
const homePath = path.join(__dirname,"public/index.html");
const registerPath = path.join(__dirname,"public/register.html");
const loginPath = path.join(__dirname,"public/login.html");
const errorPath = path.join(__dirname,"templates/views/error.hbs");
const promptPath = path.join(__dirname,"templates/views/prompt.hbs");
const secretPath = path.join(__dirname,"templates/views/secret.hbs");
const successPath = path.join(__dirname,"templates/views/success.hbs");
const success2Path = path.join(__dirname,"templates/views/success2.hbs");


app.use(cookieParser());
app.use(bodyParser.urlencoded({extended : true}));
app.use(express.static(staticPath));
app.use(express.json());
app.set('view engine','hbs');
app.set('views',templatePath);
hbs.registerPartials(partialPath);


mongoose.set('strictQuery',false);
const connectDB = async()=> {
    try{
        const conn = await mongoose.connect(process.env.MONGO_URI);
        console.log(`database is located at ${conn.connection.host}`);
    }catch(err){
        console.log(err);
        process.exit(1);
    }
}


app.get('/',(req,res)=>{
    // console.log(`The cookie currently stored : ${req.cookies.jwt}`);
    res.sendFile(homePath);
})

app.get('/register',(req,res)=>{
    res.sendFile(registerPath);
})

app.get('/login',(req,res)=>{
    res.sendFile(loginPath);
})

app.get('/secret',auth,(req,res)=>{
    // console.log(`Currently stored cookie : ${req.cookies.jwt}`);
    try{
        res.render(secretPath);   
    }catch(err){
        console.log(err);
        res.render(promptPath,{promptMessage:"Seems like you are not logged in to the system yet, please login with your necessary details. Still problems persist, do not hesitate to contact our experts."});
    }
})

app.get('/logout',auth,async(req,res)=>{
    try{ 
       // Way to remove the cookie's jwt value 
       res.clearCookie('jwt');
        //  console.log(req.token);
       console.log(`${req.userData.firstName} Logged out successfully`); 
       // Way to log-out the user from the current device (through which they are logged in)
       // e.g - gmail services.
       req.userData.tokens = req.userData.tokens.filter((ele)=>{
           return ele.token !== req.token;
       });
        // Way to log-out the user from all possible devices
       //  e.g - netflix services.
      //   req.userData.tokens = [];  
       await req.userData.save();   
       res.sendFile(loginPath); 
    }catch(err){
        console.log(err);
        res.render(promptPath,{promptMessage:"Seems like you are not logged in to the system yet, please login with your necessary details. Still problems persist, do not hesitate to contact our experts."});
    }
})

app.post('/register',async(req,res)=>{
    const _firstName = req.body.firstName;
    const _lastName = req.body.lastName;
    const _email = req.body.email;
    const _password = req.body.password;
    const _cpassword = req.body.cpassword;
    // console.log(_firstName,_lastName,_email,_password,_cpassword);
    try{
        if(_password === _cpassword){
                const user = new User({
                    firstName : _firstName,
                    lastName : _lastName,
                    email : _email,
                    password : _password
                });

                // Hashing our password (to enhance the security of our application)
                
                // End Hashing Procedure

                // Token creation for authorization of user 
                
                const token = await user.generateAuthToken();
                
                // After creating token, store it inside our cookie with proper attributes.

                // res.cookie('jwt',token,{
                //     expires : new Date(Date.now() + (30*24*60*60*1000)),
                //     httpOnly : true
                // });

                // console.log(cookie.jwt);

                await user.save();
                // res.send("<h1>User Successfully registered....</h1>")
                res.render(successPath,{username : user.firstName});
        }
        else{
            res.render(promptPath,{promptMessage:"Your entered passwords are not matching with each other . Check your password once, and sign up after few seconds. If problem persists, don't hesitate to contact our experts."});
        }
    }catch(err){
        console.log(err);
        // Customizing error messages
        if(err.code === 11000){
            res.render(promptPath,{promptMessage : "The email you entered for sign up in this website is already taken by someone else. Please use another email, and try to sign up once again. If this email belongs to you then try to login."});    
        }else if(err.message === "Userlist validation failed: email: Email formation is incorrect, try again..."){
            res.render(promptPath,{promptMessage : "Entered email is not correctly structured. Please try another email for signing up. Even though the problem persists, contact our experts immediately."});
        }else if(err.message === "Userlist validation failed: password: Your password is not strong enough, try again..."){
            // res.send(err);
            res.render(promptPath,{promptMessage : "The password you entered for signing up ,is not strong enough for this website. A strong password must have atleast one occurence of lowercase, uppercase, number, and special digit."});
        }
        else if(err.message === "Userlist validation failed: email: Email formation is incorrect, try again..., password: Your password is not strong enough, try again..."){
            res.render(promptPath,{promptMessage : "Invalid Sign up details, check your entered informations one again, and try again after few minutes. Even though the problem persists, contact our experts immediately."});
        }
        else{
            // res.send(err);
            res.render(errorPath,{errormsg : "Something is broken..."});
        }
    }
})

app.post('/login',async(req,res)=>{
    const _email = req.body.email;
    const _password = req.body.password;
    // console.log(_email,_password);
    try{
        const userInfo = await User.findOne({email : _email});
        // console.log(userInfo);
        if(userInfo !== null){
            // Check whether entered password and already available passwordHash matches each other or not.
            const isMatch = await bcrypt.compare(_password,userInfo.password);
            if(isMatch){
                const token = await userInfo.generateAuthToken();
                // console.log(token);
                res.cookie('jwt',token,{
                   expires : new Date(Date.now()+(30*24*60*60*1000)),
                   httpOnly : true
                });
                // We can't do like this, as the cookie is just created.
                // That is why we can't fetch the cookie details then and there.
                // console.log(req.cookies.jwt);
                res.render(success2Path,{username:userInfo.firstName});
            }
            else{
                // res.send("<h1>Invalid Login Details !!!</h1>");
                res.render(promptPath,{promptMessage:"Your password doesn't match with your email id. Please check your password once, and log in after few seconds. If problem persists, don't hesitate to contact our experts."});
            }
        }
        else{
            res.render(promptPath,{promptMessage:"No user exists with this email id. Please check your email id once, and log in after few seconds. If problem persists, don't hesitate to contact our experts."});
        }
    }catch(err){
       console.log(err);
       res.render(errorPath,{errormsg : "your connection is broken"});
    }
})


app.get('*',(req,res)=>{
    // console.log(errorPath);
    res.render(errorPath,{errormsg:"404 error page not found"});
})


connectDB().then(()=>{
    app.listen(port,()=>{
        console.log(`Server is listening at port ${port}`);
    })
})