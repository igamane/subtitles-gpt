module.exports = (req, res, next) => {
    req.body.username = req.body.username.toLowerCase().trim();
    next();
}