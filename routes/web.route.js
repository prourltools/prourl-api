const express = require('express');
const userController = require('../controllers/user.controller');
const userRoute = express();

userRoute.set('view engine', 'ejs');
userRoute.set('views', './views');
userRoute.use(express.static('./public'));

userRoute.get('/v1/users/verify', userController.verifyMail);

userRoute.get('/v1/users/reset-password', userController.resetPasswordLoad);

userRoute.post('/v1/users/reset-password', userController.resetPassword);

userRoute.get('/v1/users/reactivate', userController.reactivateAccount);

module.exports = userRoute;