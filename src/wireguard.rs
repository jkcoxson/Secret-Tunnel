// Authored by Jackson Coxson
// Holds stuff for maintaining a Wireguard connection

use std::{
    str::FromStr,
    sync::{
        mpsc::{Receiver, Sender},
        Arc, Mutex,
    },
};

use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use smoltcp::phy::{Device, RxToken, TxToken};
use tokio::{
    net::UdpSocket,
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
};

pub struct Wireguard {
    // This will be filled once the first packet comes in from Wireguard
    pub(crate) sender: UnboundedSender<Vec<u8>>,
    pub(crate) token_senders: Arc<Mutex<Vec<Sender<Vec<u8>>>>>,
}

pub struct WireguardTx {
    sender: UnboundedSender<Vec<u8>>,
}

pub struct WireguardRx {
    receiver: Receiver<Vec<u8>>,
}

impl Wireguard {
    /// Create a Wireguard listener
    pub async fn new(bind: impl Into<String>) -> Self {
        let bind = bind.into();
        let socket = UdpSocket::bind(bind.clone())
            .await
            .expect("Failed to bind, bad address?");
        let (incoming_tx, incoming_rx) = tokio::sync::mpsc::unbounded_channel();
        // Start a task to handle Wireguard
        let token_senders = Arc::new(Mutex::new(Vec::new()));
        let token_clone = Arc::clone(&token_senders);
        tokio::spawn(async move {
            wg_thread(incoming_rx, token_clone, socket).await;
        });
        Self {
            token_senders,
            sender: incoming_tx,
        }
    }
}

async fn wg_thread(
    mut receiver: UnboundedReceiver<Vec<u8>>,
    token_senders: Arc<Mutex<Vec<Sender<Vec<u8>>>>>,
    socket: UdpSocket,
) {
    println!("Starting Wireguard server...");

    // Read in all the keys
    let server_private = include_str!("../wireguard_keys/server_privatekey")[..44].to_string();
    let client_public = include_str!("../wireguard_keys/client_publickey")[..44].to_string();

    let server_private = X25519SecretKey::from_str(&server_private.to_string()).unwrap();
    let client_public = X25519PublicKey::from_str(&client_public.to_string()).unwrap();

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
                    boringtun::noise::TunnResult::WriteToTunnelV4(b, addr) => {
                        if target.is_none() {
                            target = Some(addr)
                        }

                        // Parse the bytes as an IP packet
                        match smoltcp::wire::Ipv4Packet::new_checked(&b)  {
                            Ok(_) => {
                                // Write to all the tokens
                                let mut tokens = token_senders.lock().unwrap();
                                let mut i = 0;
                                while i < tokens.len() {
                                    match tokens[i].send(b.to_vec()) {
                                        Ok(_) => {}
                                        Err(_) => {
                                            println!("Token {} failed", i);
                                        }
                                    }
                                    tokens.remove(i);
                                    i += 1;
                                }
                            }
                            Err(e) => {
                                println!("Malformed packet: {}", e);
                            }
                        }
                    }
                    boringtun::noise::TunnResult::WriteToTunnelV6(_b, _addr) => {
                        panic!("IPv6 not supported");
                    }
                }
            }
            s = receiver.recv() => {
                // Send it to the tunnel
                if s.is_none() {
                    continue;
                }
                let mut buf = [0; 65536];
                tun.encapsulate(&s.unwrap(), &mut buf);
                socket.send_to(&buf, target.unwrap().to_string()).await.unwrap();
            }
        }
    }
}

impl Device<'_> for Wireguard {
    type RxToken = WireguardRx;

    type TxToken = WireguardTx;

    fn receive(&mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        println!("Preparing to receive");

        // The problem here is that we can only send a token *if* there is data to receive

        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        self.token_senders.lock().unwrap().push(tx);
        Some((
            WireguardRx { receiver: rx },
            WireguardTx {
                sender: self.sender.clone(),
            },
        ))
    }

    fn transmit(&mut self) -> Option<Self::TxToken> {
        println!("Preparing to transmit");
        Some(WireguardTx {
            sender: self.sender.clone(),
        })
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        println!("Getting capabilities");
        let x = smoltcp::phy::DeviceCapabilities::default();
        x
    }
}

impl RxToken for WireguardRx {
    fn consume<R, F>(self, _timestamp: smoltcp::time::Instant, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        println!("Consuming RxToken");
        let mut bytes = self.receiver.recv().unwrap();
        f(&mut bytes)
    }
}

impl TxToken for WireguardTx {
    fn consume<R, F>(
        self,
        _timestamp: smoltcp::time::Instant,
        len: usize,
        f: F,
    ) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        println!("Consuming TxToken");
        // Create a buffer with the correct length
        let mut buf = vec![0; len];
        let res = match f(&mut buf) {
            Ok(r) => r,
            Err(e) => {
                println!("Error: {}", e);
                return Err(e);
            }
        };

        // Send it
        self.sender.send(buf).unwrap();

        Ok(res)
    }
}
