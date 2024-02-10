const mongoose = require('mongoose');

const uri = 'mongodb+srv://arielgodoy:Ag13135401@clustermongodb.k5c43jz.mongodb.net/?retryWrites=true&w=majority';

async function connectDb() {
  try {
    await mongoose.connect(uri);

    console.log('Conexión a MongoDB establecida correctamente');
    return mongoose.connection;
  } catch (error) {
    console.error('Error de conexión a MongoDB:', error);
    throw error;
  }
}

module.exports = { connectDb };
