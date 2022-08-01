// Jackson Coxson
// Proof of concept for Secret Tunnel

use std::net::SocketAddrV4;

mod event;
mod handle;
mod packets;
mod wireguard;

// I don't want this to be async to try and get as much performance as possible
// We are limited by how fast we can yeet packets back and forth
fn main() {
    println!("Starting server");

    let wg = wireguard::Wireguard::new(SocketAddrV4::new(
        std::net::Ipv4Addr::new(0, 0, 0, 0),
        51820,
    ));

    // Wait until the user presses enter
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    println!("{}", input);

    let handle = wg.tcp_connect(3000).unwrap();

    handle
        .send("The cake is a freaking lie".as_bytes().to_vec())
        .unwrap();

    loop {
        println!("{:?}", handle.recv().unwrap());
    }
}
