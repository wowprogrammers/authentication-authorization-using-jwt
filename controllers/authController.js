const User = require('../models/userModel');
const jwt = require('jsonwebtoken');
const { promisify } =  require('util');
const sendEmail = require('../utils/email');

const signToken = id => {
 return jwt.sign({id},process.env.JWT_SECRET,{
    expiresIn:process.env.JWT_EXPIRESIN
})   
}
// Sign Up
const signUp = async(req,res) => {
    try {
    
        const {name,email,photo,password,passwordConfirm,passwordChangedAt} = req.body;

        const user = await User.create({
            name,
            email,
            photo,
            password,
            passwordConfirm,
            passwordChangedAt
        });

        const token = signToken(user._id); 

        if(user){
            res.status(201).json({
                status:"Success",
                token:token,
                data:{
                    user
                }
            })
        }
    } catch (error) {
     res.status(400).json({Error:error.message});   
    }
}
// Login
const login = async (req,res) => {
    try {
        const {email,password} = req.body;

        // 1 Check if email and password really exist
        if(!email || !password){
            return res.status(400).json({Error:"Email or Password is missing"});
        }

  
        // 2 Check if user exist in the database and password is correct 
        
        const user = await User.findOne({email:email}).select('+password');
        if(!user){
            
            // Share General Error Message 
            return res.status(400).json({Error:"Email or Password in Incorrect"});
        }
        // 3 Check Password
        const correct = await user.checkPassword(password,user.password);

        // Share General Error Message 
        if(!user || !correct ){
            return res.status(401).json({Error:"Email Or Password is Incorrect"});
        }
        const token = signToken(user._id);

        res.status(200).json({
            status:"Success",
            token
        })


    } catch (error) {
        res.status(400).json({Error:error.message})
    }
}


const protector = async (req,res,next) => {
    try {
        // Getting token and check if its there
        let token;
        if(req.headers.authorization && req.headers.authorization.startsWith('Bearer')){
            token = req.headers.authorization.split(' ')[1];
        }
        // console.log(token)
        if(!token){
            return res.status(401).json({Error:"You are not logged in!"})
        }

        // Verification of token
      const decodedPayload = await promisify(jwt.verify)(token,process.env.JWT_SECRET)
        // console.log(decodedPayload);

        // If user still exist(Another important security layer)
        const currentUser = await User.findById(decodedPayload.id);
        if(!currentUser){
            return res.status(404).json({Error:"User belongs to the token does not exist"});
        }
        // Check if user has changed the password after token issued

        if(currentUser.passwordChangedAfterTokenIssue(decodedPayload.iat)){
            return res.status(400).json({Error:"User recently change the password.Please Login Again"});
        }
        
        // If all the conditions passes only than move next()
        // Grant Access to protected route
        req.user = currentUser 
        next();
    } catch (error) { 
        res.status(400).json({Error:error.message});
    }
}
//  Authorization
const restricted = (...roles) => {
    return (req,res,next) => {
            // roles = ['admin']
            if(!roles.includes(req.user.role)){
                return res.status(403).json({Error:"You dont have permission to perform this operation"})
            }

            next();
    }
}

const updatePassword = async(req,res) => {
    try {
        // Get user from the collection
        const user = await User.findById(req.user.id).select('+password');

        const {currentPassword,password,passwordConfirm} = req.body;
        // Check if current password is correct
        const correct = await user.checkPassword(currentPassword,user.password);

        if(!correct){
            return res.status(401).json({Error:"Current Password is Incorrect"});
        }


        // If correct,Update the password
        user.password = password;
        user.passwordConfirm = passwordConfirm;

        await user.save();

        // send jwt token 
        const token = signToken(user._id);
        
        res.status(200).json({
            status:"Success",
            token,
            data:{
                user
            }
        })
    } catch (error) {
        res.status(400).json({Error:error.message});
    }
}

const forgetPassword = async(req,res) => {
    try {
      
        const {email} = req.body;
      
        // Get user based on posted email
        const user = await User.findOne({email});
        if(!user){
            return res.status(404).json({Error:"User with this email does not exist"});
        }

        // Generate random token

        const resetToken = user.createPasswordResetToken();
        
        await user.save({validateBeforeSave:false});
        // sends it to user email
        const resetUrl = `${req.protocol}://${req.get('host')}/api/vi/users/resetPassword/${resetToken}`

        const message = `Forget Your Password? Click on the given link to set your new Password: ${resetUrl}. If  you dont want to reset your password.Please ignore this email.`;
 
        try { 
            await sendEmail({  
                email:user.email,
                subject:"Password Reset Link (Only Valid for 10 mints)",
                message
            })
    
            res.status(200).json({
                status:"Success",
                message:"Token sent to an email. Successfully"
            }) 
          
        } catch (error) {
            user.passwordResetToken = undefined;
            user.passwordResetExpires = undefined;
            await user.save({validateBeforeSave:false});
            res.status(400).json({Error:error.message})
                 
        }
        

    } catch (error) {
        res.status(400).json({Error:error.message});
    }
}

const resetPassword = async(req,res) => {
    try {
        const token = req.params.token;
        // console.log(token)
    } catch (error) {
        res.status(400).json({Error:error.message});
    }
}

module.exports = {
    signUp,
    login,
    protector,
    restricted,
    updatePassword,
    forgetPassword,
    resetPassword
}