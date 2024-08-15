if (process.env.NODE_ENV !== "production") {
    require('dotenv').config();
}
 
const admin = process.env.admin;

module.exports = (req, res, next) => {
    res.locals.currentUser = req.user;
    if (!req.isAuthenticated()) {
        req.flash('error', "Please log in to continue");
        return res.redirect('/login');
    }
    if (req.user.username != admin) {
        req.flash('error', "You're not an admin");
       return res.redirect('/login');
    }
    next(); 
} 
