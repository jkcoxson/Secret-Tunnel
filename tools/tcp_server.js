// Creates a TCP server that listens on port 3000.

const net = require('net');
const port = 3000;

const server = net.createServer(socket => {
    socket.on('data', data => {
        console.log(data.toString());
    });
});


server.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});

server.on('connection', socket => {
    console.log('That do be a connection!');
    socket.on('data', data => {
        console.log(data.toString());
        socket.write('Hello World!');
    })
});
