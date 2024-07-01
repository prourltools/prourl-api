const { check } = require('express-validator');

exports.signUpValidation = [
    check('name', 'Name is required').not().isEmpty(),
    check('email', 'Email is not valid or empty').isEmail().normalizeEmail({ gmail_remove_dots: true }),
    check('password', 'Password must be minimum 6 charecters long').isLength({ min: 6 })
];

exports.loginValidation = [
    check('email', 'Email is not valid or empty').isEmail().normalizeEmail({ gmail_remove_dots: true }),
    check('password', 'Password must be minimum 6 charecters long').isLength({ min: 6 })
];

exports.emailOnlyValidation = [
    check('email', 'Email is not valid or empty').isEmail().normalizeEmail({ gmail_remove_dots: true })
];

exports.passwordOnlyValidation = [
    check('password', 'Password must be minimum 6 charecters long').isLength({ min: 6 })
];

exports.updateProfileValidation = [
    check('name', 'Name is required').not().isEmpty()
];

exports.changeEmailValidation = [
    check('newemail', 'Email is not valid or empty').isEmail().normalizeEmail({ gmail_remove_dots: true }),
    check('password', 'Password must be minimum 6 charecters long').isLength({ min: 6 })
];

exports.changePasswordValidation = [
    check('oldpass', 'Old Password is required').isLength({ min: 6 }),
    check('newpass', 'New Password must be minimum 6 charecters long').isLength({ min: 6 })
];