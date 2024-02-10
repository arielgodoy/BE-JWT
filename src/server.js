const express = require('express');
const path = require('path');
const { Server } = require('socket.io');
const fetch = require('node-fetch');
const productRouter = require('./routes/products.router.js');
const cartRouter = require('./routes/carts.router.js');
const userRouter = require('./routes/users.router.js');
const hbsrouter = require('./routes/handlebars.router.js');
const sessionsRouter = require('./routes/apis/sessions.router.js');
const { connectDb } = require('./config/mongo.js');
const passport = require('passport');
const { initializePassport } = require('./config/passport.config.js');
// passport

// importacion de cookie-parser para manejar cookies en las solicitudes http
const cookieParser= require('cookie-parser');
const session = require('express-session');
//session file store para login en localstorage
const SessionFileStore = require('session-file-store')(session);
//connect mongo para login en el servidor
const MongoStore = require('connect-mongo');





const ProductManager = require('./managers/ProductManagerMongo.js');
const productManager = new ProductManager();

// console.log('antes de conectar');
connectDb();
// console.log('después de conectar');

const app = express();
const port = 8080;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '/public')));


initializePassport()
app.use(session({
  secret: 'mipalabrasecreta',
}))
app.use(passport.initialize())
app.use(passport.session())





// Configuración de Handlebars
const exphbs = require('express-handlebars');
const handlebars = exphbs.create({
  helpers: {
    jsonStringify: function(context) {
      return JSON.stringify(context);
    }    
  },
    // Desactivar la comprobación de acceso al prototipo (NO recomendado para producción)
  // Esto permitirá el acceso a propiedades del prototipo
  runtimeOptions: {
    allowProtoPropertiesByDefault: true,
    allowProtoMethodsByDefault: true,
  },
});


app.engine('handlebars', handlebars.engine);
app.set('view engine', 'handlebars');
app.set('views', path.resolve(__dirname, 'views'));

// Routers End Points BE
app.use('/api/products', productRouter);
app.use('/api/carts', cartRouter);
app.use('/api/users', userRouter);
app.use('/api/sessions', sessionsRouter);


// Routers FE
app.use('/', hbsrouter);

const httpServer = app.listen(port, (err) => {
  if (err) throw err;
  console.log(`Server running on ${port}`);
});

// Winsocket
const io = new Server(httpServer);
io.on('connection', socket => {
  console.log('Nueva conexión entrante por WS');
  socket.on('addproduct', formData => {
    const status = productManager.addProduct(
      formData.title,
      formData.description,
      formData.price,
      formData.thumbnail,
      formData.code,
      formData.stock,
      formData.status,
      formData.category
    );
    socket.emit('resultado.addproduct', status);
    socket.broadcast.emit('productosactualizados', status);
  });
  socket.on('getproducts', async () => {
    console.log('entro a getproducts de WS');
    try {
      const response = await fetch('http://localhost:8080/api/products/');
      if (!response.ok) {
        console.error('Error al obtener productos desde la API:', response.statusText);
        return;
      }
      try {
        const products = await response.json() || [];
        socket.emit('resultado.getproducts', products);
      } catch (error) {
        console.error('Error al convertir la respuesta a JSON:', error);
      }
    } catch (error) {
      console.error('Error al obtener productos:', error);
      socket.emit('resultado.getproducts', { error: 'Error al obtener productos' });
    }
  });

  socket.on('eliminaProducto', id => {
    console.log('Eliminando Producto ID = ' + id);
    let resultado = productManager.deleteProduct(id);
    socket.broadcast.emit('productosactualizados', resultado);
  });
});

// Middleware de manejo de errores
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Error de server');
});
