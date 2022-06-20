// Jackson Coxson

use secret_tunnel::wireguard::Wireguard;

#[tokio::main]
async fn main() {
    let mut server = Wireguard::new("0.0.0.0:51820").await;
    let mut rec = server.router.bind("Tcp", "10.7.0.1", 12345).await.unwrap();
    loop {
        let msg = rec.recv().await;
        println!("{:?}", msg);
    }
}
