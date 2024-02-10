const express = require('express');
const ProductManager = require('../managers/ProductManagerMongo.js');
const { productsModel } = require('../dao/models/products.model.js')
const productManager = new ProductManager();
const router = express.Router();

router
router
.get('/', async (req, res) => {
    try {
        //const limit = parseInt(req.query.limit) || null;
        const limit = !isNaN(parseInt(req.query.limit)) ? parseInt(req.query.limit) : null;
        const page = parseInt(req.query.page) || 1;
        const pageSize = parseInt(req.query.pageSize) || 100;
        const sort = req.query.sort || null;
        const category = req.query.category || null;
        const availability = req.query.availability || null;        
        const result = await productManager.getProducts({
            limit,
            page,
            pageSize,
            sort,
            category,
            availability,
        });

        const totalPages = Math.ceil(result.totalItems / pageSize);
        const hasPrevPage = page > 1;
        const hasNextPage = page < totalPages;

        const response = {
            status: 'success',
            payload: result.products,
            totalPages: totalPages,
            prevPage: hasPrevPage ? page - 1 : null,
            nextPage: hasNextPage ? page + 1 : null,
            page: page,
            hasPrevPage: hasPrevPage,
            hasNextPage: hasNextPage,
            prevLink: hasPrevPage ? `${req.originalUrl}?page=${page - 1}&pageSize=${pageSize}` : null,
            nextLink: hasNextPage ? `${req.originalUrl}?page=${page + 1}&pageSize=${pageSize}` : null,
        };

        res.json(result.products);
    } catch (error) {
        console.error(error);
        res.status(500).json({ status: 'error', message: 'Error interno del servidor' });
    }
})

.get('/:pid', async (req, res) => {
    const id = req.params.pid;

    console.log("codigo :", id);
    try {
        const result = await productManager.getProductById(id);

        if (result.product) {
            res.json(result.product);
        } else {
            res.status(404).send('Producto no encontrado');
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Error interno del servidor');
    }
})

.post('/', async (req, res) => {
    try {       
        const { title, description, price, thumbnail, code, stock, status, category } = req.body;
        const result = await productManager.addProduct(title, description, price, thumbnail, code, stock, status, category);
        if (result.success) {
            res.json({ message: result.message, productId: result.productId });
        } else {
            res.status(400).json({ error: result.message });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
})
.put('/:id', async (req, res) => {
    const productId = req.params.id;

    const updatedProductData = req.body;
    const result = await productManager.updateProduct(productId, updatedProductData);

    if (result.success) {
        res.json({ message: `Producto con ID ${productId} actualizado con éxito.`, updatedProduct: result.updatedProduct });
    } else {
        res.status(400).json({ error: result.message });
    }
})





  
.delete('/:id', (req, res) => {
    const productId = req.params.id;

    // Devolvemos la respuesta desde el método deleteProduct de ProductManager 
    const result = productManager.deleteProduct(productId);

    if (result.success) {
        res.json({ message: `Producto con ID ${productId} eliminado con éxito.` });
    } else {
        res.status(400).json({ error: result.message });
    }
})




    


//export default router;
module.exports = router;  

