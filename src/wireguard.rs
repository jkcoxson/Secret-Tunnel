// Authored by Jackson Coxson
// Holds stuff for maintaining a Wireguard connection

use std::{str::FromStr, sync::Arc};

use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use tokio::{
    net::UdpSocket,
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
};

pub struct Wireguard {
    // This will be filled once the first packet comes in from Wireguard
    rec: UnboundedReceiver<Vec<u8>>,
    send: UnboundedSender<Vec<u8>>,
}

impl Wireguard {
    /// Create a Wireguard listener
    pub async fn new(bind: impl Into<String>) -> Self {
        let bind = bind.into();
        let socket = UdpSocket::bind(bind.clone())
            .await
            .expect("Failed to bind, bad address?");
        let (out_tx, out_rx) = tokio::sync::mpsc::unbounded_channel();
        let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel();

        // Start a task to handle Wireguard
        tokio::spawn(async move {
            wg_thread(in_tx, out_rx, socket).await;
        });
        Self {
            rec: in_rx,
            send: out_tx,
        }
    }

    /// Recieves a raw IP packet from Wireguard
    pub async fn recv(&mut self) -> Vec<u8> {
        self.rec.recv().await.unwrap()
    }

    /// Sends a raw IP packet to Wireguard
    async fn send(&self, raw: &[u8]) {
        self.send.send(raw.to_vec()).unwrap();
    }
}

async fn wg_thread(
    sender: UnboundedSender<Vec<u8>>,
    mut receiver: UnboundedReceiver<Vec<u8>>,
    socket: UdpSocket,
) {
    println!("Starting Wireguard server...");

    // Read in all the keys
    let server_private = include_str!("../wireguard_keys/server_privatekey")[..44].to_string();
    let client_public = include_str!("../wireguard_keys/client_publickey")[..44].to_string();

    let server_private = X25519SecretKey::from_str(&server_private.to_string()).unwrap();
    let client_public = X25519PublicKey::from_str(&client_public.to_string()).unwrap();
    println!("Keys read in");

    let tun = boringtun::noise::Tunn::new(
        Arc::new(server_private),
        Arc::new(client_public),
        None,
        None,
        0,
        None,
    )
    .unwrap();

    // Get the first target
    let mut target = None;

    loop {
        // Get that message
        let mut buf = [0; 1024];
        tokio::select! {
            s = socket.recv_from(&mut buf) => {
                let s = s.unwrap();
                let raw_buf = buf[..s.0].to_vec();

                // Parse it with boringtun
                let mut unencrypted_buf = [0; 65536];
                let p = tun.decapsulate(Some(s.1.ip()), &raw_buf, &mut unencrypted_buf);

                match p {
                    boringtun::noise::TunnResult::Done => {
                        // literally nobody knows what to do with this
                    }
                    boringtun::noise::TunnResult::Err(_) => {
                        println!("Oh no");
                        println!("Anyways...");
                    }
                    boringtun::noise::TunnResult::WriteToNetwork(b) => {
                        socket.send_to(b, s.1).await.unwrap();
                        loop {
                            let p = tun.decapsulate(Some(s.1.ip()), &[], &mut unencrypted_buf);
                            match p {
                                boringtun::noise::TunnResult::WriteToNetwork(b) => {
                                    socket.send_to(b, s.1).await.unwrap();
                                }
                                _ => break,
                            }
                        }
                    }
                    boringtun::noise::TunnResult::WriteToTunnelV4(b, _addr) => {
                        let parsed = packet::ip::v4::Packet::unchecked(&b);
                        target = Some(parsed.source());
                        sender.send(b.to_vec()).unwrap();
                    }
                    boringtun::noise::TunnResult::WriteToTunnelV6(_b, _addr) => {
                        panic!("IPv6 not supported");
                    }
                }
            }
            s = receiver.recv() => {
                // Send it to the tunnel
                let mut buf = [0; 65536];
                tun.encapsulate(&s.unwrap(), &mut buf);
                socket.send_to(&buf, target.unwrap().to_string()).await.unwrap();
            }
        }
    }
}
