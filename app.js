const express = require('express');
const app = express();
const dotenv = require('dotenv');
dotenv.config();
require('./Db/conn');
app.use(express.json());
// app.use(dotenv.config())


// importing Routes
const userRoute = require('./routes/userRoute'); 


 
// Custom middlewares

app.use('/api/v1/users',userRoute)




const port = process.env.PORT;
app.listen(port,()=>{
    console.log(`Server is running on the port ${port}`);
});