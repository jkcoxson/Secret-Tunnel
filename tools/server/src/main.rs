// Jackson Coxson

use secret_tunnel::wireguard::Wireguard;

#[tokio::main]
async fn main() {
    let mut server = Wireguard::new("0.0.0.0:51820").await;
    loop {
        println!("Packet: {:02X?}", server.recv().await);
    }
}
