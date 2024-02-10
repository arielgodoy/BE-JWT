const { Schema, model } = require('mongoose');

const usersCollection = 'Usuarios';

const UsersSchema = Schema({
    first_name: {
        type: String,
        required: true,
    },
    last_name: String,
    email: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    role: {
        type: String,
        enum: ['admin', 'user'],
        default: 'user',
    },
});

const usersModel = model(usersCollection, UsersSchema);

module.exports = {
    usersModel
};

// // Example of using async/await with .create
// const createUser = async () => {
//     const userObject = {
//         first_name: 'ariel',
//         last_name: 'godoy',
//         email: 'arielgodoy@gmail.com',
//         password: 'hashedPassword', // You should hash the password before saving it
//         role: 'user',
//     };

//     try {
//         const user = await usersModel.create(userObject);
//         console.log('User created:', user);
//     } catch (error) {
//         console.error(error);
//     }
// };

// Call the function
//createUser();
