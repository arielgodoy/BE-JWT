const { Product } = require('../dao/models/products.model.js');

class ProductManager {
  constructor() {
    
  }
  async addProduct(title, description, price, thumbnail, code, stock, status, category) {
    try {
      const existingProduct = await Product.findOne({ code });
      if (existingProduct) {
        return { success: false, message: `El código del producto ya existe, Code=${code}` };
      }

      const product = new Product({
        title,
        description,
        code,
        price,
        thumbnail,
        stock,
        status,
        category,
      });

      await product.save();      
      return { success: true, message: 'Producto agregado con éxito.', productId: product._id.toString() };
    } catch (error) {
      console.error('Error al agregar producto:', error);
      return { success: false, message: 'Error al agregar el producto.' };
    }
  }

  async deleteProduct(id) {
    try {
      const result = await Product.deleteOne({ _id: id });
      if (result.deletedCount > 0) {
        return { success: true, message: `Producto con code ${id} eliminado con éxito.` };
      } else {
        return { success: false, message: `No se encontró un producto con ID ${id}.` };
      }
    } catch (error) {
      console.error('Error al eliminar producto:', error);
      return { success: false, message: 'Error al eliminar el producto.' };
    }
  }

  async updateProduct(id, updatedProduct) {
    try {
      const result = await Product.updateOne({ _id: id }, { $set: updatedProduct });
      if (result.modifiedCount > 0) {
        return { success: true, message: `Producto con ID ${id} actualizado con éxito.` };
      } else {
        return { success: false, message: `No se encontró un producto con ID ${id}.` };
      }
    } catch (error) {
      console.error('Error al actualizar producto:', error);
      return { success: false, message: 'Error al actualizar el producto.' };
    }
  }

  async getProducts({ limit = null, page = 1, pageSize = 10, sort = null, category = null, availability = null }) {
    try {
        // console.log('METODO getProducts');
        // console.log('limit=' + limit);
        // console.log('Page=' + page);
        // console.log('pageSize=' + pageSize);
        // console.log('sort=' + sort);
        // console.log('category=' + category);
        // console.log('availability=' + availability);

        let query = Product.find();

        // Apply category filter if provided
        if (category) {
            query = query.where('category').equals(category);
        }

        // Apply availability filter if provided
        if (availability !== null) {
            query = query.where('availability').equals(availability);
        }

        // Apply sorting if provided
        if (sort === 'asc' || sort === 'desc') {
            const sortDirection = sort === 'asc' ? 1 : -1;
            query = query.sort({ price: sortDirection });
        }

        // Apply the limit if provided
        if (limit !== null && limit !== undefined) {
          query = query.limit(limit);
          console.log("aplicando límite", limit);
        }


        // Execute the query (without skip and limit for counting total)
        const products = await query.exec();

        // Calculate the start index for pagination
        const startIndex = Math.max((page - 1) * pageSize, 0);

        // Slice the array to get the desired page
        const paginatedProducts = products.slice(startIndex, startIndex + pageSize);

        // Return an object with products and totalItems
        //console.log("productos encontrados", products.length)
        return Promise.resolve({ products: paginatedProducts, totalItems: products.length });
    } catch (error) {
        console.error('Error al obtener productos:', error);
        return Promise.resolve({ products: [], totalItems: 0 });
    }
}



  


async getProductById(id) {
  console.log('ID recibido:', id);
  try {
      const product = await Product.findOne({ "_id": id });
      console.log('Producto encontrado:', product);
      return { product, error: null };
  } catch (error) {
      console.error('Error al verificar producto por código:', error);
      return { product: null, error };
  }
}


}

module.exports = ProductManager;
