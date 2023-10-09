const nodemailer = require('nodemailer');

const sendEmail = async options => {
    try {
         // Create transporter(Its just a service we defined here to send emails like gmails)
    const transporter = nodemailer.createTransport({
        host:process.env.Email_Host,
        port:2525, 
        auth:{
            user:process.env.Email_User,
            pass:process.env.Password_User 
        }   
    });
    // Define the email options 

    const mailOptions = {
        from:"Waleed Bukhari dummy@gmail.com",
        to:options.email,
        subject:options.subject,
        text:options.message,
    };

        // Actually send the email
        await transporter.sendMail(mailOptions)
        // console.log('Email sent successfully');


    } catch (error) {
    console.error('Error sending email:');
    // throw error; // Rethrow the error for higher-level handling if needed
    }
}


module.exports = sendEmail;