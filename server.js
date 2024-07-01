require("dotenv").config();
require("./configs/connection");

const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const { PORT } = process.env;
const userRouter = require("./routes/user.route");
const webRouter = require("./routes/web.route");

const app = express();
const app_port = PORT || 3005;

app.use(express.json());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

app.use("/", webRouter);
app.use("/v1/users", userRouter);

app.use((err, req, res, next) => {
    err.statusCode = err.statusCode || 500;
    err.message = err.message || "Internal Server Error";
    res.status(err.statusCode).json({ message: err.message });
});

app.listen(app_port, () => {
    console.log("Server is running on port "+ app_port +"!");
});