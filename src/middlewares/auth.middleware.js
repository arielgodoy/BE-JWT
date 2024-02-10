function authentication(req, res, next) {    
    if (req.session.user && req.session.user.role === 'admin') {
        next();
    } else {
        res.status(401).send({ status: 'error', message: 'No autorizado' });
    }
}
module.exports = authentication;
