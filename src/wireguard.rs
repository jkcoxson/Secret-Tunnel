// Authored by Jackson Coxson
// Holds stuff for maintaining a Wireguard connection

use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use std::collections::HashMap;
use std::{net::SocketAddr, str::FromStr, sync::Arc};

use crate::event;
use crate::handle;
use crate::packets;

pub struct Wireguard {
    sender: crossbeam_channel::Sender<event::Event>,
}

impl Wireguard {
    /// Create a Wireguard listener
    pub fn new(bind: impl Into<SocketAddr>) -> Self {
        // Bind to the wireguard port
        let socket = std::net::UdpSocket::bind(bind.into()).unwrap();

        // Create a channel to send events to
        let (sender, receiver) = crossbeam_channel::unbounded();

        // Start the new thread
        std::thread::spawn(move || wg_thread(socket, receiver));

        Wireguard { sender }
    }

    /// Opens a new TCP connection
    pub fn tcp_connect(&self, port: u16) -> Result<handle::PortHandle, std::io::Error> {
        println!("Connecting to port {}", port);

        // Create a channel to send events to
        let (sender, receiver) = crossbeam_channel::unbounded();

        // Send the event to the thread
        self.sender
            .send(event::Event::NewTcp(port, sender))
            .unwrap();

        // Wait to get the internal port
        println!("Waiting for handle");
        let internal_port = match receiver.recv().unwrap() {
            event::Event::Port(port) => port,
            event::Event::Error(err) => return Err(err),
            _ => unreachable!(),
        };

        println!("Internal port: {}", internal_port);

        // Return the handle
        Ok(handle::PortHandle {
            port: internal_port,
            outgoing: self.sender.clone(),
            incoming: receiver,
        })
    }
}

fn wg_thread(socket: std::net::UdpSocket, receiver: crossbeam_channel::Receiver<event::Event>) {
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

    // Create hashmap for the handles to ports
    let mut handles: HashMap<u16, handle::InternalHandle> = std::collections::HashMap::new();

    // Global IP addresses to be filled in by the first packet
    let mut self_ip = None;
    let mut peer_ip = None;

    socket
        .set_read_timeout(Some(std::time::Duration::from_millis(50)))
        .unwrap();

    loop {
        // Try to get a message from Wireguard
        let mut buf = [0; 1024];
        match socket.recv_from(&mut buf) {
            Ok((size, endpoint)) => {
                // Fill in the peer IP if it's the first packet
                if peer_ip.is_none() {
                    println!("Filling in peer IP");
                    peer_ip = Some(match endpoint {
                        SocketAddr::V4(addr) => addr,
                        _ => panic!("Unexpected IP type"),
                    });
                }

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
                        // Parse the bytes as an IP packet
                        println!("Parsing IP packet");
                        println!("Bytes: {:02X?}", b);
                        println!("Address: {:?}", addr);
                        // Fill in the self IP if it's the first packet
                        if self_ip.is_none() {
                            println!("Filling in self IP");
                            self_ip = Some(addr);
                        }
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
                                        _ => panic!(),
                                    },
                                    sequence_number: match ping_send.header().icmp_type {
                                        etherparse::Icmpv4Type::EchoRequest(header) => header.seq,
                                        _ => panic!(),
                                    },
                                    data: ping_send.payload().to_vec(),
                                }
                                .into();

                                let ip_packet: Vec<u8> = packets::Ipv4 {
                                    id: std::process::id() as u16,
                                    ttl: 64,
                                    protocol: 1,
                                    source: match ip_packet.ip.unwrap() {
                                        etherparse::InternetSlice::Ipv4(s, _) => {
                                            s.destination_addr()
                                        }
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
                            etherparse::TransportSlice::Icmpv6(_) => unimplemented!(),
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
            Err(e) => match e.kind() {
                std::io::ErrorKind::WouldBlock => continue,
                _ => {
                    println!("Error receiving: {}", e);
                    return;
                }
            },
        };

        // We can't continue without finding ourselves
        if self_ip == None || peer_ip == None {
            continue;
        }

        // Try to get a message from the channel
        match receiver.try_recv() {
            Ok(event) => {
                println!("Got event: {:?}", event);
                match event {
                    event::Event::Transport(_, _) => todo!(),
                    event::Event::NewTcp(external_port, sender) => {
                        println!("Establishing new TCP connection");

                        // Randomly generate a port not in use
                        let mut port;
                        loop {
                            port = rand::random::<u16>();
                            if !handles.contains_key(&port) {
                                break;
                            }
                        }

                        // Create a new handle
                        let handle = handle::TcpInternal {
                            port: external_port,
                            outgoing: sender,
                            seq: 0,
                            ack: 0,
                        };

                        // Create TCP syn packet
                        let tcp_packet = packets::Tcp {
                            source_port: port,
                            destination_port: external_port,
                            sequence_number: 0,
                            ack_number: 0,
                            flags: 0x02,
                            window_size: 0xFFFF,
                            urgent_pointer: 0,
                            data: vec![],
                        };

                        // Create IP packet
                        let ip_packet: Vec<u8> = packets::Ipv4 {
                            id: std::process::id() as u16,
                            ttl: 64,
                            protocol: 6,
                            source: self_ip.unwrap(),
                            destination: *peer_ip.unwrap().ip(),
                            payload: tcp_packet.into(),
                        }
                        .into();

                        println!("Sending TCP packet: {:02X?}", ip_packet);
                        let mut buf = [0; 2048];
                        match tun.encapsulate(&ip_packet, &mut buf) {
                            boringtun::noise::TunnResult::WriteToNetwork(b) => {
                                socket.send_to(b, peer_ip.unwrap()).unwrap();
                            }
                            _ => {
                                println!("Unexpected result");
                            }
                        }

                        handle.outgoing.send(event::Event::Port(port)).unwrap();

                        // Add it to the hashmap
                        handles.insert(port, handle::InternalHandle::Tcp(handle));
                    }
                    event::Event::Error(_) | event::Event::Port(_) => {
                        println!("This should never happen, errors only go out");
                    }
                    event::Event::Stop => {
                        println!("Stopping Wireguard server...");
                        return;
                    }
                }
            }
            Err(crossbeam_channel::TryRecvError::Empty) => {}
            Err(crossbeam_channel::TryRecvError::Disconnected) => {
                panic!("Channel disconnected");
            }
        }
    }
}
