const express = require('express');
const userRoute = express.Router();
const authController = require('../controllers/authController');
const userController = require('../controllers/userController');

userRoute.post('/signUp',authController.signUp);
userRoute.post('/login',authController.login);
userRoute.get('/',authController.protector,authController.restricted('admin','super admin'),userController.getAllusers)
userRoute.patch('/passwordUpdate',authController.protector,authController.updatePassword);
userRoute.post('/forgetPassword',authController.forgetPassword);
userRoute.patch('/resetPassword/:token',authController.resetPassword);


 

module.exports = userRoute;