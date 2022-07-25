// Jackson Coxson
// Proof of concept for Secret Tunnel

use std::net::SocketAddrV4;

mod packets;
mod wireguard;

// I don't want this to be async to try and get as much performance as possible
// We are limited by how fast we can yeet packets back and forth
fn main() {
    println!("Starting server");

    // temp check
    let c = packets::ipv4_checksum(&[
        0x45, 0x00, 0x00, 0x54, 0x24, 0x0A, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0A, 0x08, 0x00,
        0x01, 0x0A, 0x07, 0x00, 0x0A,
    ]);
    println!("{:02X}", c);

    let wg = wireguard::Wireguard::new(SocketAddrV4::new(
        std::net::Ipv4Addr::new(0, 0, 0, 0),
        51820,
    ));

    loop {
        // sleep
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
