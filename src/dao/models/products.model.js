const { model, Schema } = require('mongoose');

// Define el esquema del producto
const productSchema = new Schema({
  title: String,
  description: String,
  code: String,
  price: Number,
  thumbnail: String,
  stock: Number,
  status: String,
  category: String,
});

// Crea el modelo de Producto
const Product = model('Product', productSchema);

module.exports = {Product};
