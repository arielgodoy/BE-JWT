const { model, Schema, ObjectId } = require('mongoose');
const { Product } = require('../dao/models/products.model.js');


const cartSchema = new Schema({
    products: [
        {
            productId: { type: Schema.Types.ObjectId, ref: 'Product' },
            quantity: Number,
        },
    ],
});

const CartModel = model('Cart', cartSchema);

class CartManager {
    async getCarts() {
        try {
            const carts = await CartModel.find().populate('products.productId');
            return carts;
        } catch (error) {
            console.error('Error reading carts from MongoDB:', error);
            return [];
        }
    }

    async getCartById(cid) {
        try {
            const cart = await CartModel.findOne({ _id: cid }).populate('products.productId');
            if (!cart) {
                return 'No se encuentra el carrito';
            }
            return cart;
        } catch (error) {
            console.error('Error getting cart by ID from MongoDB:', error);
            return 'Error obteniendo carrito por ID';
        }
    }

    async createCart(newCart) {
        try {
            const createdCart = await CartModel.create(newCart);
            return createdCart;
        } catch (error) {
            console.error('Error creating cart in MongoDB:', error);
            return 'Error creando carrito';
        }
    }
    //agrega prpducto al carrito, valida si producto existe y si existe suma cantidad!
    async updateCart(cid, updatedProducts) {
        console.log("Agrega producto al carrito, valida si el producto existe y si existe, suma cantidad.");
        try {
            const cart = await CartModel.findOne({ _id: cid });
    
            if (!cart) {
                return 'No se encuentra el carrito';
            }
    
            // Verificar si updatedProducts es un array
            if (!Array.isArray(updatedProducts)) {
                return 'La lista de productos actualizados no es válida.';
            }
    
            // Verificar la existencia de los productos antes de actualizar el carrito
            for (const updatedProduct of updatedProducts) {
                //console.log("verifgica exista producto a insertar",updatedProduct.productId)
                const productExists = await Product.findOne({ _id: updatedProduct.productId });
    
                if (!productExists) {
                    return `No se puede actualizar el carrito. Producto con ID ${updatedProduct.productId} no encontrado.`;
                }
            }
    
            // Actualizar productos en el carrito
            for (const updatedProduct of updatedProducts) {
                const existingProductIndex = cart.products.findIndex(
                    (product) => product.productId.toString() === updatedProduct.productId
                );
    
                if (existingProductIndex !== -1) {
                    // Si el producto ya existe en el carrito, suma las cantidades
                    cart.products[existingProductIndex].quantity += updatedProduct.quantity;
                } else {
                    // Si el producto no existe, agrégalo al carrito
                    console.log("Añadiendo producto al carrito", updatedProduct.productId);
                    cart.products.push({
                        productId: updatedProduct.productId,
                        quantity: updatedProduct.quantity,
                    });
                }
            }
    
            const updatedCart = await cart.save();
            return updatedCart;
        } catch (error) {
            console.error('Error updating cart in MongoDB:', error);
            return 'Error actualizando carrito';
        }
    }
    
    
    
 
    

    

    async removeProductFromCart(cid, pid) {
        try {
            const cart = await CartModel.findOne({ _id: cid });
            if (!cart) {
                return 'No se encuentra el carrito';
            }
            cart.products = cart.products.filter((product) => product.productId.toString() !== pid);    
            const updatedCart = await cart.save();
            return updatedCart;
        } catch (error) {
            console.error('Error eliminando producto del carrito MongoDB:', error);
            return 'Error eliminando producto del carrito';
        }
    }
    



    async updateProductQuantity(cid, pid, quantity) {
        try {
            const cart = await CartModel.findOne({ _id: cid });
            if (!cart) {
                return 'No se encuentra el carrito';
            }
    
            const productIndex = cart.products.findIndex((product) => product.productId.toString() === pid);
    
            if (productIndex !== -1) {
                cart.products[productIndex].quantity = quantity;
            }
    
            const updatedCart = await cart.save();
            return updatedCart;
        } catch (error) {
            console.error('Error updating product quantity in cart in MongoDB:', error);
            return 'Error actualizando cantidad del producto en el carrito';
        }
    }




    async deleteCart(cid) {
        try {
            const result = await CartModel.deleteOne({ _id: cid });
            if (result.deletedCount === 0) {
                return 'No se encuentra el carrito';
            }
            return 'Carrito eliminado con éxito';
        } catch (error) {
            console.error('Error deleting cart in MongoDB:', error);
            return 'Error eliminando carrito';
        }
    }

    async emptyCart(cid) {
        try {
            const cart = await CartModel.findOne({ _id: cid });
    
            if (!cart) {
                return 'No se encuentra el carrito';
            }
    
            // Vaciar el array de productos del carrito
            cart.products = [];
    
            const updatedCart = await cart.save();
            return updatedCart;
        } catch (error) {
            console.error('Error vaciando el carrito en MongoDB:', error);
            return 'Error vaciando el carrito';
        }
    }
    
}

module.exports = CartManager;
