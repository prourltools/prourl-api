const express = require("express");
const router = express.Router();
const {
signUpValidation,
loginValidation,
emailOnlyValidation,
updateProfileValidation,
changeEmailValidation,
changePasswordValidation,
passwordOnlyValidation
} = require("../helpers/validation");
const { isAuthorized } = require("../middlewares/auth");
const userController = require("../controllers/user.controller");
const path = require("path");
const multer = require("multer");

function generateRandomFileName(filename) {
    const ext = filename.split(".").pop();
    const timestamp = Date.now();
    const randomNum = Math.floor(1000000000 + Math.random() * 9000000000);
    return `${timestamp}-${randomNum}.${ext}`;
}

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, "../public/images/users"));
    },
    filename: function (req, file, cb) {
        cb(null, generateRandomFileName(file.originalname));
    }
});

const imageFilter = (req, file, cb) => {
    if (file.mimetype == "image/jpeg" || file.mimetype == "image/png" || file.mimetype == "image/jpg" || file.mimetype == "image/webp") {
        cb(null, true);
    } else {
        cb(null, false);
    }
};

const upload = multer({ storage: storage, fileFilter: imageFilter, limits: { fileSize: 1024 * 200 }});

router.post("/signup", signUpValidation, userController.signUp);

router.post("/resend-verification", emailOnlyValidation, userController.resendVerification);

router.post("/login", loginValidation, userController.login);

router.get("/get-user", isAuthorized, userController.getUser);

router.post("/forgot-password", emailOnlyValidation, userController.forgotPassword);

router.post("/update-profile", upload.single("image"), updateProfileValidation, isAuthorized, userController.updateProfile);

router.post("/change-email", changeEmailValidation, isAuthorized, userController.changeEmail);

router.post("/change-password", changePasswordValidation, isAuthorized, userController.changePassword);

router.get("/remove-image", isAuthorized, userController.removeImage);

router.post("/deactivate", passwordOnlyValidation, isAuthorized, userController.deactivateAccount);

router.post("/request-reactivation", emailOnlyValidation, userController.requestReactivation);

module.exports = router;