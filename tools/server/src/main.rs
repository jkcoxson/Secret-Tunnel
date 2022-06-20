// Jackson Coxson

use secret_tunnel::{router::RouterProtocol, wireguard::Wireguard};

#[tokio::main]
async fn main() {
    let mut server = Wireguard::new("0.0.0.0:51820").await;
    let mut rec = server
        .router
        .bind(RouterProtocol::UDP, "1.1.1.1", 53)
        .await
        .unwrap();
    loop {
        let msg = rec.recv().await;
        println!("{:?}", msg);
    }
}
