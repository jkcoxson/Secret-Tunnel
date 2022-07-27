// Jackson Coxson

const dgram = require('dgram');
const client = dgram.createSocket('udp4');

const port = 3000;
const host = '10.7.0.1';

// Send message to server
client.send('Hello from client!', port, host, (err, bytes) => {
    if (err) throw err;
    console.log(`UDP message sent to ${host}:${port}`);
    client.close();
});