//console.log('Bienvenidos al ingreso por Websocket');
const socket = io();
const limit = '';
const dataTable = $('#productTable').DataTable();
//funcion que actualiza la data en pantalla

const obtenerProductos = async () => {
  try {
    // "Pedimos la data al server por WS"
    //console.log("Pedimos la data al server por WS")
    socket.emit('getproducts', limit);
    // Esperamos la data de manera asíncrona
    const dataFromServer = await new Promise(resolve => {
      socket.on('resultado.getproducts', data => resolve(data));      
    });       
    const products = dataFromServer;   
    // Limpiamos la tabla antes de agregar productos
    dataTable.clear().draw();
    // Inyectamos la data a la tabla
    products.forEach(product => {      
      dataTable.row.add([
        product._id || '',
        product.title || '',
        product.description || '',
        product.code || '',
        product.price || '',
        product.status || '',
        product.stock || '',
        product.category || '',
        product.thumbnail || '',
        '<button class="btn btn-danger eliminar-btn">Eliminar</button>'
      ]).draw();
    });
  } catch (error) {
    console.error('Error en obtenerProductos:', error);
  }
};

// llamamos la funcion de datos la 1era vez
obtenerProductos();

// quedamos a la espera de algun broacast de actualizacion en el json (post,put o delete)
socket.on('productosactualizados', data => {
  obtenerProductos();
});
