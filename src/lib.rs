// Authored by Jackson Coxson

pub mod wireguard;

#[cfg(test)]
mod tests {
    use crate::wireguard;

    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }

    #[tokio::test]
    async fn wireguard_server() {
        let mut server = wireguard::Wireguard::new("0.0.0.0:51820").await;
        loop {
            println!("Packet: {:02X?}", server.recv().await);
        }
    }
}
