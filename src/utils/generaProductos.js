const fs = require('fs');

const generateRandomProducts = () => {
  const products = [];

  for (let i = 1; i <= 500; i++) {
    const product = {
      title: `Nuevo nombre de producto${i}`,
      description: 'Nueva descripción',
      code: `NEWCODE${i}`,
      price: 29.99,
      thumbnail: 'nueva_imagen.jpg',
      stock: 75,
      status: true,
      category: `Categoria${Math.floor(Math.random() * 50) + 1}`,
    };

    products.push(product);
  }

  return products;
};

const jsonData = generateRandomProducts();

fs.writeFileSync('productos.json', JSON.stringify(jsonData, null, 2), 'utf-8');
console.log('JSON generado exitosamente.');
