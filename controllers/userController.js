const User = require('../models/userModel')

//  Get All Users
const getAllusers = async(req,res) => {
    const users = await User.find();
    if(users){
        return res.status(200).json({
            status:"Success",
            length:users.length,
            data:{
                users
            }

        })
    }
}

module.exports = {getAllusers}