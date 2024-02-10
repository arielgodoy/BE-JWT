console.log('Bienvenidos al ingreso por Websocket');
const socket = io();
const limit = '';
const dataTable = $('#productTable').DataTable();

console.log("Título de la página:", programa);
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
    
    //console.log("data=", dataFromServer);
    const products = dataFromServer;   

    // Limpiamos la tabla
    dataTable.clear().draw();

    //const isAdmin = false; // Replace with the actual admin status of the user
    //console.log({{admin}});
    //const isAdmin = {{admin}}; 
    //isAdmin=False;
    products.forEach(product => {
      const deleteButton = isAdmin
        ? '<button class="btn btn-danger eliminar-btn">Eliminar</button>'
        : '<button class="btn btn-danger eliminar-btn" disabled>Unauthorized</button>';
    
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
        deleteButton
      ]).draw();
    });
    


  } catch (error) {
    console.error('Error en obtenerProductos:', error);
  }
};

// Resto del código...
obtenerProductos();


$(document).ready(function () {
  var dataTable = $('#productTable').DataTable();

  // reaccionamos al clieck de eliminar por fila
  $('#productTable').on('click', '.eliminar-btn', function () {    
    let data = dataTable.row($(this).parents('tr')).data();
    // quitamos del jason pos winsocket
    remove(data[0]);
    // quitamos la fila para no renderizar
    dataTable.row($(this).parents('tr')).remove().draw();
  });
});

function remove(productData) {
  const handleResult = function (status) {
    const messageText = status.message;
    $('#result').text(messageText);
  };
  socket.emit('eliminaProducto', productData, handleResult);
}
