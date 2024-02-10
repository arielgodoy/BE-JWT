const { Router } = require("express");
const authentication = require("../../middlewares/auth.middleware.js");
const { isValidPassword, createHash } = require("../../utils/hashPassword.js");
const passport = require("passport");
const { createToken, authenticationToken } = require('./../../utils/jwt.js')
const userservice = require('../../dao/usersDaoMongo.js')


const router = Router();
router
    .get('/github', passport.authenticate('github', { scope: ['user:email'] }))

    .get('/githubcallback', passport.authenticate('github', { failureRedirect: '/login' }), (req, res) => {
        req.session.user = req.user;
        res.redirect('/products');
    })

    


    
    .post('/register', async (req, res)=>{
    const { first_name, last_name, email , password } = req.body
   
    if (first_name ==='' || password === "" || email === '' ) {
        return res.send('faltan completar campos obligatorios')
    }
    
    const userFound = await userservice.get({email})
    if (userFound) {
        return res.send({status: 'error', error: 'Ya existe el user'})
    }
    const newUser = {
        first_name,
        last_name,
        email,
        password: createHash(password)
    }
    const result = await userservice.create(newUser)
    const token = createToken({id: result._id})
    res.send({
        status: 'success',
        payload: {
            first_name: result.first_name,
            last_name: result.last_name,
            email: result.email,
            _id: result._id
        },
        token
    })
})

    .post('/login', async (req, res)=>{
    const {email , password } = req.body
   
    if (email === '' || password === '') {
        return res.send('todos los campos son obligatoris')
    }
    
    const user = await userservice.get({email})
    if (!user) {
        return res.send('email o contraseña equivocado')
    }

    if (!isValidPassword(password, { password: user.password })) {
            return res.send('email o contraseña equivocado')        
    }

    const token = createToken({id: user._id, role: user.role })
    res.json({
        status: 'success',
        payload: {
            id: user._id,
            first_name: user.first_name,
            last_name: user.last_name,
        },
        token
    })
})




    .get('/current', authentication, (req, res) => {
        res.send(req.session.user)
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
