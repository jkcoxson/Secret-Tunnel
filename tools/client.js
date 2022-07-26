// Connects to the server at localhost:3000.

const net = require('net');
const port = 3000;
const host = 'localhost';

const client = net.createConnection({ port, host }, () => {
    client.write('Hello from client!');
});