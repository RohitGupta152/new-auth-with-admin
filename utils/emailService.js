const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const sendVerificationEmail = async (email, verificationUrl) => {
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
        subject: 'Verify Your Email',
            html: `
            <h1>Email Verification</h1>
            <p>Please click the link below to verify your email address:</p>
            <a href="${verificationUrl}">Verify Email</a>
            <p>This link will expire in 24 hours.</p>
            <p>If you didn't request this verification, please ignore this email.</p>
            `
        };

        await transporter.sendMail(mailOptions);
};

const sendResetPasswordEmail = async (email, resetPasswordUrl) => {
    try {
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Reset Your Password',
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        .email-container {
                            max-width: 600px;
                            margin: 0 auto;
                            font-family: Arial, sans-serif;
                            line-height: 1.6;
                            color: #333333;
                        }
                        .header {
                            background-color: #FF6B6B;
                            padding: 20px;
                            text-align: center;
                            color: white;
                        }
                        .content {
                            padding: 20px;
                            background-color: #ffffff;
                        }
                        .button {
                            display: inline-block;
                            padding: 12px 24px;
                            background-color: #FF6B6B;
                            color: white;
                            text-decoration: none;
                            border-radius: 5px;
                            margin: 20px 0;
                        }
                    </style>
                </head>
                <body>
                    <div class="email-container">
                        <div class="header">
                            <h1>Reset Your Password</h1>
                        </div>
                        <div class="content">
                            <h2>Password Reset Request</h2>
                            <p>Click the button below to reset your password:</p>
                            
                            <div style="text-align: center;">
                                <a href="${resetPasswordUrl}" class="button">Reset Password</a>
                            </div>
                            
                            <p>Or copy and paste this link in your browser:</p>
                            <p>${resetPasswordUrl}</p>
                            
                            <p>This link will expire in 1 hour.</p>
                            <p>If you didn't request this password reset, please ignore this email.</p>
                        </div>
                    </div>
                </body>
                </html>
            `
        };

        await transporter.sendMail(mailOptions);
    } catch (error) {
        console.error('Error sending password reset email:', error);
        throw new Error('Failed to send password reset email');
    }
};

const sendLoginVerificationEmail = async (email, loginVerificationUrl) => {
    try {
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Verify Your Login Attempt',
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        .email-container {
                            max-width: 600px;
                            margin: 0 auto;
                            font-family: Arial, sans-serif;
                            line-height: 1.6;
                            color: #333333;
                        }
                        .header {
                            background-color: #2ECC71;
                            padding: 20px;
                            text-align: center;
                            color: white;
                        }
                        .content {
                            padding: 20px;
                            background-color: #ffffff;
                        }
                        .button {
                            display: inline-block;
                            padding: 12px 24px;
                            background-color: #2ECC71;
                            color: white;
                            text-decoration: none;
                            border-radius: 5px;
                            margin: 20px 0;
                        }
                    </style>
                </head>
                <body>
                    <div class="email-container">
                        <div class="header">
                            <h1>Verify Your Login</h1>
                        </div>
                        <div class="content">
                            <h2>Complete Your Login</h2>
                            <p>Click the button below to verify your login attempt:</p>
                            
                            <div style="text-align: center;">
                                <a href="${loginVerificationUrl}" class="button">Verify Login</a>
                            </div>
                            
                            <p>Or copy and paste this link in your browser:</p>
                            <p>${loginVerificationUrl}</p>
                            
                            <p>This link will expire in 15 minutes.</p>
                            <p>If you didn't attempt to login, please ignore this email.</p>
                        </div>
                    </div>
                </body>
                </html>
            `
        };

        await transporter.sendMail(mailOptions);
    } catch (error) {
        console.error('Error sending login verification email:', error);
        throw new Error('Failed to send login verification email');
    }
};

module.exports = {
    sendVerificationEmail,
    sendResetPasswordEmail,
    sendLoginVerificationEmail
}; 