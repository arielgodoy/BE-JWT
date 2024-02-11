const { Router } = require("express");
const authentication = require("../../middlewares/auth.middleware.js");
const { isValidPassword, createHash } = require("../../utils/hashPassword.js");
const passport = require("passport");
const { createToken, authenticationToken } = require('./../../utils/jwt.js')
const UserDaoMongo = require('../../dao/usersDaoMongo.js')
const userservice = new UserDaoMongo()
const router = Router();

router
    .get('/github', passport.authenticate('github', { scope: ['user:email'] }))
    .get('/githubcallback', passport.authenticate('github', { failureRedirect: '/login' }), (req, res) => {
        req.session.user = req.user;
        res.redirect('/products');
    })
    .post('/register', async (req, res) => {
        const { first_name, last_name, email, password } = req.body
        if (first_name === '' || password === "" || email === '') {
            return res.send('faltan completar campos obligatorios')
        }
        const userFound = await userservice.getBy({ email })
        if (userFound) {
            return res.send({ status: 'error', error: 'Ya existe el user' })
        }
        const newUser = {
            first_name,
            last_name,
            email,
            password: createHash(password)
        }
        const result = await userservice.create(newUser)
        const token = createToken({ id: result._id, role: result.role, email: result.email })
        res.send({
            status: 'success',
            payload: {
                first_name: result.first_name,
                last_name: result.last_name,
                email: result.email,
                role: result.role,
                _id: result._id
            },
            token
        })
    })

    .post('/login', async (req, res) => {
        const email = req.body.email || req.query.email;
        const password = req.body.password || req.query.password;
        if (email === '' || password === '') {
            return res.status(401).send({ status: 'error', error: 'data_missing' });
        }
        const user = await userservice.getBy({ email })
        if (!user) {
            return res.status(401).send({ status: 'error', error: 'user_not_found' });
        }

        if (!isValidPassword(password, user.password)) {
            return res.status(401).send({ status: 'error', error: 'user_not_found' });
        }        
        req.session.user = {
            id: user._id,
            first_name: user.first_name,
            last_name: user.last_name,
            role: user.role,
            email: user.email
        };
        console.log("Creando sesion de usuario ", user);

        const token = createToken({ id: user._id, first_name: user.first_name, last_name: user.last_name, role: user.role, email: user.email })
        res.json({
            status: 'success',
            payload: {
                id: user._id,
                first_name: user.first_name,
                last_name: user.last_name,
                role: user.role,
                email: user.email
            },
            token
        })
    })



    .get('/current', authenticationToken, (req, res) => {
        res.send(req.session.user);
    })
    


    .get('/logout', (req, res) => {
        req.session.destroy(err => {
            if (err) return res.send({ status: 'error', message: 'Error al cerrar la sesión' })
        })
        res.redirect('/login');
    })

    .get('/', (req, res) => {
        if (req.session.counter) {
            req.session.counter++;
            res.send({ message: 'Ha ingresado al E-Commerce X', counter: req.session.counter });
        } else {
            req.session.counter = 1;
            res.send({ message: 'Bienvenido al E-Commerce', counter: 1 });
        }
    })


module.exports = router
