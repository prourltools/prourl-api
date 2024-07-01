const { validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const db = require('../configs/connection');
const randomstring = require('randomstring');
const sendMail = require('../helpers/sendMail');
const jwt = require('jsonwebtoken');
const { SITENAME, DOMAIN, JWT_SECRET } = process.env;

const signUp = (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    db.query(`SELECT * FROM users WHERE LOWER(email) = LOWER(${db.escape(req.body.email)});`, (err, result) => {
        if (result.length) {
            return res.status(409).json({ message: 'Email already exists' });
        } else {
            bcrypt.hash(req.body.password, 10, (err, hash) => {
                if (err) {
                    return res.status(400).json({ message: err });
                } else {
                    db.query(`INSERT INTO users (name, email, password) VALUES (${db.escape(req.body.name)}, ${db.escape(req.body.email)}, ${db.escape(hash)});`, (err, result) => {
                        if (err) {
                            return res.status(400).json({ message: err });
                        } else {
                            const verificationToken = randomstring.generate();
                            db.query(`UPDATE users SET token=? WHERE email=?;`,[verificationToken, req.body.email] , (err, result) => {
                                if (err) {
                                    return res.status(400).json({ message: err });
                                } else {
                                    let mailSubject = SITENAME + ' Email Verification';
                                    let mailBody = 'Hi, ' + req.body.name + '<br><br>' + 'Thank you for registering on ' + SITENAME + '. Please click on the link below to verify your email address:<br><br>' + '<a href="' + DOMAIN + '/v1/users/verify?token=' + verificationToken + '">Verify Email</a><br><br>' + 'If you did not request this, please ignore this email.<br><br>' + 'Thanks, ' + SITENAME + ' Team';
                                    sendMail(req.body.email, mailSubject, mailBody);
    
                                    return res.status(201).json({ message: 'User created successfully' });
                                }
                            }
                            );
                        }
                    });
                }
            });
        }
    });
}

const resendVerification = (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    db.query(`SELECT * FROM users WHERE LOWER(email) = LOWER(${db.escape(req.body.email)});`, (err, result) => {
        if (!result.length) {
            return res.status(404).json({ message: 'Email not found' });
        } else {
            const userData = result[0];

            if (userData.is_verified) {
                return res.status(400).json({ message: 'Email is already verified' });
            } else if(!userData.is_active) {
                return res.status(400).json({ message: 'Account is deactivated' });
            } else if(userData.is_blocked) {
                return res.status(400).json({ message: 'Account is blocked' });
            } else {
                if (!userData.token) {
                    const verificationToken = randomstring.generate();

                    db.query(`UPDATE users SET token=? WHERE email=?;`, [verificationToken, req.body.email], (err, result) => {
                        if (err) {
                            return res.status(400).json({ message: err });
                        } else {
                            let mailSubject = SITENAME + ' Email Verification';
                            let mailBody = 'Hi, ' + userData.name + '<br><br>' + 'Thank you for registering on ' + SITENAME + '. Please click on the link below to verify your email address:<br><br>' + '<a href="' + DOMAIN + '/v1/users/verify?token=' + verificationToken + '">Verify Email</a><br><br>' + 'If you did not request this, please ignore this email.<br><br>' + 'Thanks, ' + SITENAME + ' Team';
                            sendMail(req.body.email, mailSubject, mailBody);
    
                            return res.status(200).json({ message: 'Verification link has been sent to your email' });
                        }
                    });
                } else {
                    let mailSubject = SITENAME + ' Email Verification';
                    let mailBody = 'Hi, ' + userData.name + '<br><br>' + 'Thank you for registering on ' + SITENAME + '. Please click on the link below to verify your email address:<br><br>' + '<a href="' + DOMAIN + '/v1/users/verify?token=' + userData.token + '">Verify Email</a><br><br>' + 'If you did not request this, please ignore this email.<br><br>' + 'Thanks, ' + SITENAME + ' Team';
                    sendMail(req.body.email, mailSubject, mailBody);
    
                    return res.status(200).json({ message: 'Verification link has been sent to your email' });
                }
            }
        }
    });
}

const verifyMail = (req, res) => {
    var token = req.query.token;

    db.query(`SELECT * FROM users WHERE token=? LIMIT 1;`, [token], (err, result) => {
        if (err) {
            return res.status(400).json({ message: err });
        } else {
            if (!result.length) {
                return res.render('message', { message: 'Invalid or expired token' });
            } else {
                if(result[0].is_blocked) {
                    return res.render('message', { message: 'Account is blocked' });
                } else if(!result[0].is_active) {
                    return res.render('message', { message: 'Account is deactivated' });
                } else if(result[0].is_verified) {
                    return res.render('message', { message: 'Email is already verified' });
                } else {
                    db.query(`UPDATE users SET token=?, is_verified=? WHERE id=?;`, [null, 1, result[0].id], (err, result) => {
                        if (err) {
                            return res.status(400).json({ message: err });
                        } else {
                            return res.render('message', { message: 'Email verified successfully! You can close this window now' });
                        }
                    });
                }
            }
        }
    });
}

const login = (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    db.query(`SELECT * FROM users WHERE LOWER(email) = LOWER(${db.escape(req.body.email)});`, (err, result) => {
        if (!result.length) {
            return res.status(401).json({ message: 'Email or password is incorrect' });
        } else {
            bcrypt.compare(req.body.password, result[0]['password'], (err, isMatch) => {
                if (!isMatch) {
                    return res.status(401).json({ message: 'Email or password is incorrect' });
                } else {
                    if (!result[0]['is_verified']) {
                        return res.status(401).json({ message: 'Email is not verified' });
                    } else {
                        if (!result[0]['is_active']) {
                            return res.status(401).json({ message: 'Account is deactivated' });
                        } else {
                            if(result[0]['is_blocked']) {
                                return res.status(401).json({ message: 'Account is blocked' });
                            } else {
                                const loginToken = jwt.sign({ id: result[0].id, is_admin:result[0].is_admin }, JWT_SECRET, { expiresIn: '1h' });
                                db.query(`UPDATE users SET last_login=NOW() WHERE id=?;`, [result[0].id]);
                                return res.status(200).json({ message: 'Logged In Successfully', token: loginToken, user: result[0] });
                            }
                        }
                    }
                }
            });
        }
    });
}

const getUser = (req, res) => {
    const authToken = req.headers.authorization.split(' ')[1];
    const decodedJwt = jwt.verify(authToken, JWT_SECRET);

    db.query(`SELECT * FROM users WHERE id=${decodedJwt.id};`, (err, result, fields) => {
        if (err) {
            return res.status(400).json({ message: err });
        } else {
            if (!result.length) {
                return res.status(404).json({ message: 'User not found' });
            } else {
                return res.status(200).json({ success:true, message: 'User details fetched successfully', data: result[0]});
            }
        }
    });
}

const forgotPassword = (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    db.query(`SELECT * FROM users WHERE LOWER(email) = LOWER(${db.escape(req.body.email)});`, (err, result) => {
        if (!result.length) {
            return res.status(404).json({ message: 'Email not found' });
        } else {
            if (!result[0].is_verified) {
                return res.status(400).json({ message: 'Email is not verified' });
            } else if (!result[0].is_active) {
                return res.status(400).json({ message: 'Account is deactivated' });
            } else if (result[0].is_blocked) {
                return res.status(400).json({ message: 'Account is blocked' });
            } else {
                const resetToken = randomstring.generate();
                const userInfo = result[0];
                db.query(`UPDATE users SET reset_token=?, reset_at=NOW() WHERE email=?;`, [resetToken, req.body.email], (err, result) => {
                    if (err) {
                        return res.status(400).json({ message: err });
                    } else {
                        let mailSubject = SITENAME + ' Password Reset';
                        let mailBody = 'Hi, ' + userInfo.name + '<br><br>' + 'You recently requested to reset your password for your ' + SITENAME + ' account. Please click on the link below to reset your password:<br><br>' + '<a href="' + DOMAIN + '/v1/users/reset-password?token=' + resetToken + '">Reset Password</a><br><br>' + '(This link will expire within next 24hrs)<br><br>' + 'If you did not request this, please ignore this email.<br><br>' + 'Thanks, ' + SITENAME + ' Team';
                        sendMail(req.body.email, mailSubject, mailBody);
    
                        return res.status(200).json({ message: 'Password reset link has been sent to your email' });
                    }
                });
            }
        }
    });
}

const resetPasswordLoad = (req, res) => {
    const resetToken = req.query.token;
    if(!resetToken) return res.render('message', { message: 'Please provide token' });

    db.query(`SELECT * FROM users WHERE reset_token=? LIMIT 1;`, [resetToken], (err, result) => {
        if (err) {
            return res.status(400).json({ message: err });
        } else {
            if (!result.length) {
                return res.render('message', { message: 'Invalid or expired token' });
            } else {
                if(!result[0].reset_at) {
                    return res.render('message', { message: 'Something went wrong! Cannot reset. Please request a new link' });
                } else {
                    const currentTimestamp = new Date().toISOString();
                    const savedDate = new Date(result[0].reset_on);
                    const currentDate = new Date(currentTimestamp);
                    const differenceInMillis = currentDate - savedDate;
                    const twentyFourHoursInMillis = 24 * 60 * 60 * 1000;
    
                    if (differenceInMillis > twentyFourHoursInMillis) {
                        return res.render('message', { message: 'Invalid or expired token' });
                    }else {
                        return res.render('reset-password', { user: result[0] });
                    }
                }
            }
        }
    });
}

const resetPassword = (req, res) => {
    if(req.body.newpass !== req.body.confpass) {
        return res.render('reset-password', { err_message: 'Passwords do not match', user: {reset_token: req.body.resetToken} });
    }

    else if(req.body.newpass.length < 6) {
        return res.render('reset-password', { err_message: 'Password must be minimum 6 characters long', user: {reset_token: req.body.resetToken} });
    }

    else if(!req.body.resetToken) {
        return res.render('message', { message: 'Please provide token' });
    }

    else {
        db.query(`SELECT * FROM users WHERE reset_token=? LIMIT 1;`, [req.body.resetToken], (err, result) => {
            if (err) {
                return res.status(400).json({ message: err });
            } else {
                if (!result.length) {
                    return res.render('message', { message: 'Invalid or expired token' });
                } else {
                    if(!result[0].reset_at) {
                        return res.render('message', { message: 'Something went wrong! Cannot reset. Please request a new link' });
                    } else {
                        const userData = result[0];
                        const currentTimestamp = new Date().toISOString();
                        const savedDate = new Date(userData.reset_on);
                        const currentDate = new Date(currentTimestamp);
                        const differenceInMillis = currentDate - savedDate;
                        const twentyFourHoursInMillis = 24 * 60 * 60 * 1000;
        
                        if (differenceInMillis > twentyFourHoursInMillis) {
                            return res.render('message', { message: 'Invalid or expired token' });
                        }else {
                            if (!userData.is_verified) {
                                return res.render('message', { message: 'Email is not verified' });
                            } else if (!userData.is_active) {
                                return res.render('message', { message: 'Account is deactivated' });
                            } else if (userData.is_blocked) {
                                return res.render('message', { message: 'Account is blocked' });
                            } else {
                                bcrypt.hash(req.body.newpass, 10, (err, hash) => {
                                    if (err) {
                                        return res.render('reset-password', { err_message: err, user: {reset_token: req.body.resetToken} });
                                    } else {
                                        db.query(`UPDATE users SET password=?, reset_token=?, reset_at=? WHERE id=?;`, [hash, null, null, userData.id], (err, result) => {
                                            if (err) {
                                                return res.render('reset-password', { err_message: err, user: {reset_token: req.body.resetToken} });
                                            } else {
                                                let mailSubject = SITENAME + ' Password Reset Successful';
                                                let mailBody = 'Hi, ' + userData.name + '<br><br>' + 'Your password has been reset successfully on ' + SITENAME + '. If you did not request this, please contact us immediately.<br><br>' + 'Thanks, ' + SITENAME + ' Team';
                                                sendMail(userData.email, mailSubject, mailBody);
        
                                                return res.render('message', { message: 'Password reset successfully! You can close this window now' });
                                            }
                                        });
                                    }
                                });
                            }
                        }
                    }
                }
            }
        });
    }

    bcrypt.hash(req.body.newpass, 10, (err, hash) => {
        if (err) {
            return res.render('reset-password', { err_message: err, user: {id: req.body.user_id, email: req.body.user_email} });
        } else {
            db.query(`UPDATE users SET password=?, reset_token=?, reset_at=? WHERE id=?;`, [hash, null, null, req.body.user_id], (err, result) => {
                if (err) {
                    return res.render('reset-password', { err_message: err, user: {id: req.body.user_id, email: req.body.user_email} });
                } else {
                    let mailSubject = SITENAME + ' Password Reset Successful';
                    let mailBody = 'Hi, ' + req.body.user_email + '<br><br>' + 'Your password has been reset successfully on ' + SITENAME + '. If you did not request this, please contact us immediately.<br><br>' + 'Thanks, ' + SITENAME + ' Team';
                    sendMail(req.body.user_email, mailSubject, mailBody);

                    return res.render('message', { message: 'Password reset successfully! You can close this window now' });
                }
            });
        }
    });
}

const updateProfile = (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const authToken = req.headers.authorization.split(' ')[1];
    const decodedJwt = jwt.verify(authToken, JWT_SECRET);

    db.query(`SELECT * FROM users WHERE id=${decodedJwt.id};`, (err, result, fields) => {
        if (err) {
            return res.status(400).json({ message: err });
        } else {
            if (!result.length) {
                return res.status(404).json({ message: 'User not found' });
            } else {
                if (req.file) {
                    if(req.file.mimetype == "image/jpeg" || req.file.mimetype == "image/png" || req.file.mimetype == "image/jpg" || req.file.mimetype == "image/webp") {
                        if(req.file.size < 1024 * 200) {
                            if(req.body.name === result[0].name) {
                                db.query(`UPDATE users SET image=?, updated_at=NOW() WHERE id=?;`, ['images/users/' + req.file.filename, decodedJwt.id], (err, result) => {
                                    if (err) {
                                        return res.status(400).json({ message: err });
                                    } else {
                                        return res.status(200).json({ message: 'Profile updated successfully' });
                                    }
                                });
                            } else {
                                db.query(`UPDATE users SET name=?, image=?, updated_at=NOW() WHERE id=?;`, [req.body.name, 'images/users/' + req.file.filename, decodedJwt.id], (err, result) => {
                                    if (err) {
                                        return res.status(400).json({ message: err });
                                    } else {
                                        return res.status(200).json({ message: 'Profile updated successfully' });
                                    }
                                });
                            }
                        } else {
                            return res.status(400).json({ message: 'Image size must be less than 200KB' });
                        }
                    } else {
                        return res.status(400).json({ message: 'Image format must be jpeg, png, jpg or webp' });
                    }
                } else {
                    if(req.body.name === result[0].name) {
                        return res.status(400).json({ message: 'No changes detected' });
                    } else {
                        db.query(`UPDATE users SET name=?, updated_at=NOW() WHERE id=?;`, [req.body.name, decodedJwt.id], (err, result) => {
                            if (err) {
                                return res.status(400).json({ message: err });
                            } else {
                                return res.status(200).json({ message: 'Profile updated successfully' });
                            }
                        });
                    }
                }
            }
        }
    });
}

const changeEmail = (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const authToken = req.headers.authorization.split(' ')[1];
    const decodedJwt = jwt.verify(authToken, JWT_SECRET);

    db.query(`SELECT * FROM users WHERE id=${decodedJwt.id};`, (err, result, fields) => {
        if (err) {
            return res.status(400).json({ message: err });
        } else {
            if (!result.length) {
                return res.status(404).json({ message: 'User not found' });
            } else {
                const userData = result[0];

                bcrypt.compare(req.body.password, result[0].password, (err, isMatch) => {
                    if (!isMatch) {
                        return res.status(401).json({ message: 'Password is incorrect' });
                    } else {
                        if (req.body.newemail === userData.email) {
                            return res.status(400).json({ message: 'New email cannot be same as the old one' });
                        } else {
                            db.query(`SELECT * FROM users WHERE LOWER(email) = LOWER(${db.escape(req.body.newemail)});`, (err, result) => {
                                if (result.length) {
                                    return res.status(409).json({ message: 'Email already exists' });
                                } else {
                                    const verificationToken = randomstring.generate();

                                    db.query(`UPDATE users SET email=?, token=?, is_verified=?, updated_at=NOW() WHERE id=?;`, [req.body.email, verificationToken, 0, decodedJwt.id], (err, result) => {
                                        if (err) {
                                            return res.status(400).json({ message: err });
                                        } else {
                                            mailSubject = SITENAME + ' Email Verification';
                                            mailBody = 'Hi, ' + userData.name + '<br><br>' + 'You recently changed your email address on ' + SITENAME + '. Please click on the link below to verify your new email address:<br><br>' + '<a href="' + DOMAIN + '/v1/users/verify?token=' + verificationToken + '">Verify Email</a><br><br>' + 'If you did not request this, please ignore this email.<br><br>' + 'Thanks, ' + SITENAME + ' Team';
                                            sendMail(req.body.newemail, mailSubject, mailBody);

                                            return res.status(200).json({ message: 'Email updated successfully' });
                                        }
                                    });
                                }
                            });
                        }
                    }
                });
            }
        }
    });
}

const changePassword = (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const authToken = req.headers.authorization.split(' ')[1];
    const decodedJwt = jwt.verify(authToken, JWT_SECRET);

    if (req.body.oldpass === req.body.newpass) {
        return res.status(400).json({ message: 'New password cannot be same as the old one' });
    }

    db.query(`SELECT * FROM users WHERE id=${decodedJwt.id};`, (err, result, fields) => {
        if (err) {
            return res.status(400).json({ message: err });
        } else {
            if (!result.length) {
                return res.status(404).json({ message: 'User not found' });
            } else {
                const userData = result[0];

                bcrypt.compare(req.body.oldpass, result[0].password, (err, isMatch) => {
                    if (!isMatch) {
                        return res.status(401).json({ message: 'Password is incorrect' });
                    } else {
                        bcrypt.hash(req.body.newpass, 10, (err, hash) => {
                            if (err) {
                                return res.status(400).json({ message: err });
                            } else {
                                db.query(`UPDATE users SET password=?, updated_at=NOW() WHERE id=?;`, [hash, decodedJwt.id], (err, result) => {
                                    if (err) {
                                        return res.status(400).json({ message: err });
                                    } else {
                                        mailSubject = SITENAME + ' Password Changed';
                                        mailBody = 'Hi, ' + userData.name + '<br><br>' + 'You recently changed your password on ' + SITENAME + '. If you did not request this, please contact us immediately.<br><br>' + 'Thanks, ' + SITENAME + ' Team';
                                        sendMail(userData.email, mailSubject, mailBody);

                                        return res.status(200).json({ message: 'Password updated successfully' });
                                    }
                                });
                            }
                        });
                    }
                });
            }
        }
    });
}

const removeImage = (req, res) => {
    const authToken = req.headers.authorization.split(' ')[1];
    const decodedJwt = jwt.verify(authToken, JWT_SECRET);

    db.query(`SELECT * FROM users WHERE id=${decodedJwt.id};`, (err, result, fields) => {
        if (err) {
            return res.status(400).json({ message: err });
        } else {
            if (!result.length) {
                return res.status(404).json({ message: 'User not found' });
            } else {
                db.query(`UPDATE users SET image=NULL, updated_at=NOW() WHERE id=?;`, [decodedJwt.id], (err, result) => {
                    if (err) {
                        return res.status(400).json({ message: err });
                    } else {
                        return res.status(200).json({ message: 'Profile image removed successfully' });
                    }
                });
            }
        }
    });
}

const deactivateAccount = (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const authToken = req.headers.authorization.split(' ')[1];
    const decodedJwt = jwt.verify(authToken, JWT_SECRET);

    db.query(`SELECT * FROM users WHERE id=${decodedJwt.id};`, (err, result, fields) => {
        if (err) {
            return res.status(400).json({ message: err });
        } else {
            if (!result.length) {
                return res.status(404).json({ message: 'User not found' });
            } else {
                const userData = result[0];

                bcrypt.compare(req.body.password, result[0].password, (err, isMatch) => {
                    if (!isMatch) {
                        return res.status(401).json({ message: 'Password is incorrect' });
                    } else {
                        const reactivationToken = randomstring.generate();

                        db.query(`UPDATE users SET is_active=?, reactivation_token=?, deactivated_at=NOW() WHERE id=?;`, [0, reactivationToken, decodedJwt.id], (err, result) => {
                            if (err) {
                                return res.status(400).json({ message: err });
                            } else {
                                mailSubject = SITENAME + ' Account Deactivated';
                                mailBody = 'Hi, ' + userData.name + '<br><br>' + 'Your account has been deactivated on ' + SITENAME + '. If you did not request this, please contact us immediately.<br><br>' + 'To reactivate your account, please click on the link below:<br><br>' + '<a href="' + DOMAIN + '/v1/users/reactivate?token=' + reactivationToken + '">Reactivate Account</a><br><br>' + '(You can still reactivate your account anytime within next 30days. After 30days you will no longer be able to access your account anymore. Also, you cannot create another account with this email)<br><br>' + 'Thanks, ' + SITENAME + ' Team';
                                sendMail(userData.email, mailSubject, mailBody);

                                return res.status(200).json({ message: 'Account deactivated successfully' });
                            }
                        });
                    }
                });
            }
        }
    });
}

const requestReactivation = (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    db.query(`SELECT * FROM users WHERE LOWER(email) = LOWER(${db.escape(req.body.email)});`, (err, result) => {
        if (!result.length) {
            return res.status(404).json({ message: 'Email not found' });
        } else {
            const userData = result[0];

            if (userData.is_blocked) {
                return res.status(400).json({ message: 'Account is blocked' });
            } else if (userData.is_active) {
                return res.status(400).json({ message: 'Account is already active' });
            } else if (!userData.deactivated_at) {
                return res.status(400).json({ message: 'Something went wrong! Cannot reactivate. Contact us for further assistance' });
            } else {
                const currentTimestamp = new Date().toISOString();
                const savedDate = new Date(userData.deactivated_at);
                const currentDate = new Date(currentTimestamp);
                const differenceInMillis = currentDate - savedDate;
                const thirtyDaysInMillis = 30 * 24 * 60 * 60 * 1000;

                if(differenceInMillis < thirtyDaysInMillis) {
                    if (!userData.reactivation_token) {
                        const reactivationToken = randomstring.generate();
    
                        db.query(`UPDATE users SET reactivation_token=? WHERE email=?;`, [reactivationToken, req.body.email], (err, result) => {
                            if (err) {
                                return res.status(400).json({ message: err });
                            } else {
                                mailSubject = SITENAME + ' Account Reactivation';
                                mailBody = 'Hi, ' + userData.name + '<br><br>' + 'You recently requested to reactivate your account on ' + SITENAME + '. Please click on the link below to reactivate your account:<br><br>' + '<a href="' + DOMAIN + '/v1/users/reactivate?token=' + reactivationToken + '">Reactivate Account</a><br><br>' + 'If you did not request this, please ignore this email.<br><br>' + 'Thanks, ' + SITENAME + ' Team';
                                sendMail(req.body.email, mailSubject, mailBody);
    
                                return res.status(200).json({ message: 'Reactivation link has been sent to your email' });
                            }
                        });
                    } else {
                        mailSubject = SITENAME + ' Account Reactivation';
                        mailBody = 'Hi, ' + userData.name + '<br><br>' + 'You recently requested to reactivate your account on ' + SITENAME + '. Please click on the link below to reactivate your account:<br><br>' + '<a href="' + DOMAIN + '/v1/users/reactivate?token=' + userData.reactivation_token + '">Reactivate Account</a><br><br>' + 'If you did not request this, please ignore this email.<br><br>' + 'Thanks, ' + SITENAME + ' Team';
                        sendMail(req.body.email, mailSubject, mailBody);
        
                        return res.status(200).json({ message: 'Reactivation link has been sent to your email' });
                    }
                } else {
                    return res.status(400).json({ message: 'Reactivation period is over' });
                }
            }
        }
    });
}

const reactivateAccount = (req, res) => {
    const reactivationToken = req.query.token;

    if(!reactivationToken) return res.render('message', { message: 'Please provide token' });

    db.query(`SELECT * FROM users WHERE reactivation_token=? LIMIT 1;`, [reactivationToken], (err, result) => {
        if (err) {
            return res.status(400).json({ message: err });
        } else {
            if (!result.length) {
                return res.render('message', { message: 'Invalid or expired token' });
            } else {
                const userData = result[0];
                if(!userData.deactivated_at) {
                    return res.render('message', { message: 'Something went wrong! Cannot reactivate. Contact us for further assistance' });
                } else {
                    const currentTimestamp = new Date().toISOString();
                    const savedDate = new Date(result[0].deactivated_at);
                    const currentDate = new Date(currentTimestamp);
                    const differenceInMillis = currentDate - savedDate;
                    const thirtyDaysInMillis = 30 * 24 * 60 * 60 * 1000;
    
                    if (differenceInMillis > thirtyDaysInMillis) {
                        return res.render('message', { message: 'Invalid or expired token' });
                    } else {
                        db.query(`UPDATE users SET is_active=?, reactivation_token=?, deactivated_at=? WHERE id=?;`, [1, null, null, userData.id], (err, result) => {
                            if (err) {
                                return res.status(400).json({ message: err });
                            } else {
                                mailSubject = SITENAME + ' Account Reactivated';
                                mailBody = 'Hi, ' + userData.name + '<br><br>' + 'Your account has been reactivated successfully on ' + SITENAME + '. If you did not request this, please contact us immediately.<br><br>' + 'Thanks, ' + SITENAME + ' Team';
                                sendMail(userData.email, mailSubject, mailBody);
    
                                return res.render('message', { message: 'Account reactivated successfully! You can close this window now' });
                            }
                        });
                    }
                }
            }
        }
    });
}

module.exports = {
    signUp,
    resendVerification,
    verifyMail,
    login,
    getUser,
    forgotPassword,
    resetPasswordLoad,
    resetPassword,
    updateProfile,
    changeEmail,
    changePassword,
    removeImage,
    deactivateAccount,
    requestReactivation,
    reactivateAccount
};