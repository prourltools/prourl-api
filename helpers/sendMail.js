const nodemailer = require('nodemailer');
const { SMTP_HOST, SMTP_PORT, SMTP_NAME, SMTP_USER, SMTP_PASS } = process.env;

const sendMail = async (email, subject, body) => {
    try {
        const transporter = nodemailer.createTransport({
            host: SMTP_HOST,
            port: SMTP_PORT,
            secure: SMTP_PORT === 465 ? true : false,
            requireTLS: SMTP_PORT === 587 ? true : false,
            auth: {
                user: SMTP_USER,
                pass: SMTP_PASS
            }
        });

        const mailOptions = {
            from: '"'+ SMTP_NAME +'" <'+ SMTP_USER +'>',
            to: email,
            subject: subject,
            html: body
        };

        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                console.log(err);
            } else {
                console.log(info);
            }
        });

    } catch (error) {
        console.log(error);
    }
}

module.exports = sendMail;