// Authored by Jackson Coxson
// Holds stuff for maintaining a Wireguard connection

use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use std::{net::SocketAddr, str::FromStr, sync::Arc};

use crate::packets;

pub struct Wireguard {}

impl Wireguard {
    /// Create a Wireguard listener
    pub fn new(bind: impl Into<SocketAddr>) -> Self {
        // Bind to the wireguard port
        let socket = std::net::UdpSocket::bind(bind.into()).unwrap();

        // Start the new thread
        std::thread::spawn(move || wg_thread(socket));

        Wireguard {}
    }
}

fn wg_thread(socket: std::net::UdpSocket) {
    println!("Starting Wireguard server...");

    // Read in all the keys
    let server_private = include_str!("../wireguard_keys/server_privatekey")[..44].to_string();
    let client_public = include_str!("../wireguard_keys/client_publickey")[..44].to_string();

    let server_private = X25519SecretKey::from_str(&server_private).unwrap();
    let client_public = X25519PublicKey::from_str(&client_public).unwrap();

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
        let (size, endpoint) = match socket.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e) => {
                println!("Error receiving: {}", e);
                continue;
            }
        };
        let raw_buf = buf[..size].to_vec();

        // Parse it with boringtun
        let mut unencrypted_buf = [0; 65536];
        let p = tun.decapsulate(Some(endpoint.ip()), &raw_buf, &mut unencrypted_buf);

        match p {
            boringtun::noise::TunnResult::Done => {
                // literally nobody knows what to do with this
                println!("Done");
            }
            boringtun::noise::TunnResult::Err(_) => {
                println!("Oh no");
                println!("Anyways...");
            }
            boringtun::noise::TunnResult::WriteToNetwork(b) => {
                println!("Yeeting back to endpoint");
                socket.send_to(b, endpoint).unwrap();
                loop {
                    println!("Continuing endpoint yeet");
                    let p = tun.decapsulate(Some(endpoint.ip()), &[], &mut unencrypted_buf);
                    match p {
                        boringtun::noise::TunnResult::WriteToNetwork(b) => {
                            socket.send_to(b, endpoint).unwrap();
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
                println!("Parsing IP packet");
                println!("Bytes: {:02X?}", b);
                println!("Address: {:?}", addr);
                let ip_packet = etherparse::SlicedPacket::from_ip(b).unwrap();

                // Handle the packet
                match ip_packet.transport.unwrap() {
                    etherparse::TransportSlice::Icmpv4(ping_send) => {
                        println!("Header: {:?}", ping_send.header());
                        let ping_return_packet: Vec<u8> = packets::Icmp {
                            type_: 0,
                            code: 0,
                            identifier: match ping_send.header().icmp_type {
                                etherparse::Icmpv4Type::EchoRequest(header) => header.id,
                                _ => unimplemented!(),
                            },
                            sequence_number: match ping_send.header().icmp_type {
                                etherparse::Icmpv4Type::EchoRequest(header) => header.seq,
                                _ => unimplemented!(),
                            },
                            data: ping_send.payload().to_vec(),
                        }
                        .into();

                        let ip_packet: Vec<u8> = packets::Ipv4 {
                            id: std::process::id() as u16,
                            ttl: 64,
                            protocol: 1,
                            source: match ip_packet.ip.unwrap() {
                                etherparse::InternetSlice::Ipv4(s, _) => s.destination_addr(),
                                etherparse::InternetSlice::Ipv6(_, _) => {
                                    panic!("IPv6 not supported")
                                }
                            },
                            destination: addr,
                            payload: ping_return_packet,
                        }
                        .into();

                        println!("Returning ping packet: {:02X?}", ip_packet);
                        let mut buf = [0; 2048];
                        match tun.encapsulate(&ip_packet, &mut buf) {
                            boringtun::noise::TunnResult::WriteToNetwork(b) => {
                                socket.send_to(b, endpoint).unwrap();
                            }
                            _ => {
                                println!("Unexpected result");
                            }
                        }
                    }
                    etherparse::TransportSlice::Icmpv6(_) => todo!(),
                    etherparse::TransportSlice::Udp(_) => todo!(),
                    etherparse::TransportSlice::Tcp(_) => todo!(),
                    etherparse::TransportSlice::Unknown(_) => todo!(),
                }
            }
            boringtun::noise::TunnResult::WriteToTunnelV6(_b, _addr) => {
                panic!("IPv6 not supported");
            }
        }
    }
}
