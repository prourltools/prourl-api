const isAuthorized = async (req, res, next) => {
    try {
        if(!req.headers.authorization || !req.headers.authorization.startsWith('Bearer') || !req.headers.authorization.split(' ')[1]) {
            return res.status(422).json({ message: 'Please provide authorization header with valid token' });
        }
        next();
    }
    catch (error) {
        return res.status(401).json({ message: error });
    }
}

module.exports = { 
    isAuthorized
};