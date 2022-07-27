// Jackson Coxson

const dgram = require('dgram');
const server = dgram.createSocket('udp4');

const port = 3000;

// Print message when a client connects
server.on('listening', () => {
    console.log(`Server listening on port ${port}`);
});

// Print when a message is received
server.on('message', (msg, rinfo) => {
    console.log(`${rinfo.address}:${rinfo.port} - ${msg}`);
});