// Include Nodejs' net module.
const Net = require('net');
// The port on which the server is listening.
const port = 12345;

// Use net.createServer() in your code. This is just for illustration purpose.
// Create a new TCP server.
const server = new Net.Server();
// The server listens to a socket for a client to make a connection request.
// Think of a socket as an end point.
server.listen(port, "0.0.0.0", function () {
    console.log(`Server listening for connection requests on socket 0.0.0.0:${port}`);
});

// When a client requests a connection with the server, the server creates a new
// socket dedicated to that client.
server.on('connection', function (socket) {
    console.log('A new connection has been established.');
});