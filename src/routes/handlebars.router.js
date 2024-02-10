//import { Router } from 'express';
const express = require('express');
const router = express.Router();
const CartManager = require('../managers/CartManagerMongo.js');
const cartManager = new CartManager(); // Instantiate CartManager

router
.get("/products", (req, res) => {
    console.log('Renderizando .. /products..');
    console.log(req.session.user);
    let username = 'Invitado';
    let email = 'Invitado';
    let admin = false;
    if (req.session.user) {
        if (req.session.user.first_name) {
            username = req.session.user.first_name;
        }

        if (req.session.user.email) {
            email = req.session.user.email;
        }
        admin = req.session.user.role === 'admin';
    }

    res.render("home", {
        title: "Listado de productos",
        programa: "home",
        username: username,
        email: email,
        admin: admin
    })
})


.get("/add", (req, res) => {
    console.log('Renderizando .. /add..');    
    res.render("addproduct", {
        title: "ingreso de productos por API-WINSOCK",
        programa: "addproduct"
    });
})


.get("/realTimeProducts", (req, res) => {
    console.log('Renderizando .. /realTimeProducts..');    
    res.render("realTimeProducts", {
        title: "Real time Refresh WINSOCK",
        programa: "realTimeProducts"
    });
})

.get("/carts", async (req, res) => {
    console.log('Renderizando .. /listacarritos..');    

    try {
        const carts = await cartManager.getCarts();

        res.render("listacarritos", {
            title: "Listado de Carritos",
            programa: "Listacarritos",
            cartData: carts,  // Pasa los datos de los carritos a la vista
        });
    } catch (error) {
        console.error('Error al obtener carritos:', error);
        res.status(500).send('Error interno del servidor');
    }
})
.get("/login", async (req, res) => {   
    console.log('Renderizando .. /login..');    
    res.render("login", {
        title: "Login",
        programa: "login"
    });
})

.get("/register", async (req, res) => {   
    console.log('Renderizando .. /register..');    
    res.render("register", {
        title: "register",
        programa: "register"
    });
})

//export { router as default }; 
module.exports = router;

