// Jackson Coxson

use secret_tunnel::{router::RouterProtocol, wireguard::Wireguard};

#[tokio::main]
async fn main() {
    let mut server = Wireguard::new("0.0.0.0:51820").await;
    let mut rec = match server
        .router
        .bind(RouterProtocol::TCP, "10.7.0.1", 12345)
        .await
    {
        Ok(r) => r,
        Err(_) => {
            println!("Port already in use");
            std::process::exit(1);
        }
    };

    loop {
        let msg = rec.recv().await;
        println!("{:?}", msg);
    }
}
