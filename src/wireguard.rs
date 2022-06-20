// Authored by Jackson Coxson
// Holds stuff for maintaining a Wireguard connection

use std::{str::FromStr, sync::Arc};

use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use smoltcp::wire::{IpProtocol, TcpPacket, UdpPacket};
use tokio::{
    net::UdpSocket,
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
};

use crate::router::Router;

pub struct Wireguard {
    // This will be filled once the first packet comes in from Wireguard
    pub router: Router,
    send: UnboundedSender<Vec<u8>>,
}

impl Wireguard {
    /// Create a Wireguard listener
    pub async fn new(bind: impl Into<String>) -> Self {
        let bind = bind.into();
        let socket = UdpSocket::bind(bind.clone())
            .await
            .expect("Failed to bind, bad address?");
        let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel();

        let router = Router::new();

        // Start a task to handle Wireguard
        let router_clone = router.clone();
        tokio::spawn(async move {
            wg_thread(in_rx, socket, router_clone).await;
        });
        Self {
            router,
            send: in_tx,
        }
    }

    /// Sends a raw IP packet to Wireguard
    pub async fn send(&self, raw: &[u8]) {
        self.send.send(raw.to_vec()).unwrap();
    }
}

async fn wg_thread(mut receiver: UnboundedReceiver<Vec<u8>>, socket: UdpSocket, router: Router) {
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
                    boringtun::noise::TunnResult::WriteToTunnelV4(b, addr) => {
                        if target.is_none() {
                            target = Some(addr)
                        }

                        // Parse the bytes as an IP packet
                        match smoltcp::wire::Ipv4Packet::new_checked(&b)  {
                            Ok(p) => {
                                // Route this packet
                                match p.protocol() {
                                    IpProtocol::HopByHop => todo!(),
                                    IpProtocol::Icmp => todo!(),
                                    IpProtocol::Igmp => todo!(),
                                    IpProtocol::Tcp => {
                                        // Route this packet
                                        let tcp_packet = match TcpPacket::new_checked(p.payload()) {
                                            Ok(p) => p,
                                            Err(_) => {
                                                println!("Couldn't parse TCP packet, skipping");
                                                continue;
                                            }
                                        };

                                        let route = match router.find(p.protocol().to_string(), p.dst_addr().to_string(), tcp_packet.dst_port()).await {
                                            Some(r) => r,
                                            None => {
                                                println!("Couldn't find route, dropping packet");
                                                continue;
                                            }
                                        };

                                        // Send the packet
                                        match route.send(p.payload().to_vec()) {
                                            Ok(_) => {}
                                            Err(_) => {
                                                println!("Router endpoint is down, dropping packet");
                                            }
                                        }
                                    }
                                    IpProtocol::Udp => {
                                        // Route this packet
                                        let udp_packet = match UdpPacket::new_checked(p.payload()) {
                                            Ok(p) => p,
                                            Err(_) => {
                                                println!("Couldn't parse UDP packet, skipping");
                                                continue;
                                            }
                                        };

                                        let route = match router.find(p.protocol().to_string(), p.dst_addr().to_string(), udp_packet.dst_port()).await {
                                            Some(r) => r,
                                            None => {
                                                println!("Couldn't find route, dropping packet");
                                                continue;
                                            }
                                        };

                                        // Send the packet
                                        match route.send(p.payload().to_vec()) {
                                            Ok(_) => {}
                                            Err(_) => {
                                                println!("Router endpoint is down, dropping packet");
                                            }
                                        }
                                    }
                                    IpProtocol::Ipv6Route => todo!(),
                                    IpProtocol::Ipv6Frag => todo!(),
                                    IpProtocol::Icmpv6 => todo!(),
                                    IpProtocol::Ipv6NoNxt => todo!(),
                                    IpProtocol::Ipv6Opts => todo!(),
                                    IpProtocol::Unknown(_) => todo!(),
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
                let mut buf = [0; 65536];
                tun.encapsulate(&s.unwrap(), &mut buf);
                socket.send_to(&buf, target.unwrap().to_string()).await.unwrap();
            }
        }
    }
}
