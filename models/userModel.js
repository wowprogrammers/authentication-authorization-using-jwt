const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
    name:{
        type:String,
        trim:true,
        required:[true,"Name is required"]
    },
    email:{  
        type:String,
        lowercase:true,
        validate:[validator.isEmail,"Please Provide a valid email Address"],
       
    },
    photo:{
        type:String,
        trim:true
    },
    password:{
        type:String,
        required:[true,"Password is required"],
        minlength:8,
        select:false
    },
    role:{
        type:String,
        enum:['user','admin'],
        default:'user'
    },
    passwordResetToken:String,
    passwordResetExpires:Date,
    passwordConfirm:{
        type:String,
        required:[true,"Confirm password is required"],
        // This validate will only work for Save and create
        validate:{
            validator:function(elem){
                return elem === this.password
            },
            message:"Password and Confirm Password are not same"
        }
    },
    passwordChangedAt:Date

})
// mongoose middleware which will run before saving document into the database

userSchema.pre('save' , async function(next){
    // We want to run this function only when password field will modified
    if(!this.isModified('password')) return next();
    // Hasing the password 
    this.password = await bcrypt.hash(this.password,11);
    // Deleting Confirm password field from database (Good Security Practice)
    this.passwordConfirm = undefined;
    next();
})

//  instance method -> A method available on all document of specific collection

userSchema.methods.checkPassword = async function(enteredPass,userPassword){
    return await bcrypt.compare(enteredPass,userPassword);
}

// Check if password is changed after the token issued

userSchema.methods.passwordChangedAfterTokenIssue = function(JWTtimeStamp){
if(this.passwordChangedAt){
    const changedTimeStamptoMs = parseInt(this.passwordChangedAt.getTime() / 1000,10)
    // console.log(changedTimeStamptoMs,JWTtimeStamp)
    return JWTtimeStamp < changedTimeStamptoMs; //100 < 200
}
        // False means not changed  
        
        return false;

} 

// set passwordChangedAt field when Someone update their passowrd
userSchema.pre('save', function(next){
    if(!this.isModified('password') || this.isNew) return next();

    this.passwordChangedAt = Date.now() - 1000;
    next()
})


userSchema.methods.createPasswordResetToken = function(){
    // A random string we can use built in module to generate random string/bytes
    const resetToken = crypto.randomBytes(32).toString('hex');
    
    this.passwordResetToken =  crypto.createHash('sha256').update(resetToken).digest('hex');
    this.passwordResetExpires = Date.now() + 10 * 60 * 1000; //ms

    return resetToken
}



const User = mongoose.model('User',userSchema);

module.exports = User;