// Jackson Coxson
// Proof of concept for Secret Tunnel

use std::net::SocketAddrV4;

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

    loop {
        // sleep
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
