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
        // Create a channel to send events to
        let (sender, receiver) = crossbeam_channel::unbounded();

        // Send the event to the thread
        self.sender
            .send(event::Event::NewTcp(port, sender))
            .unwrap();

        // Wait to get the internal port
        let internal_port = match receiver.recv().unwrap() {
            event::Event::Port(port) => port,
            event::Event::Error(err) => return Err(err),
            _ => unreachable!(),
        };

        // Return the handle
        Ok(handle::PortHandle {
            internal_port,
            external_port: port,
            outgoing: self.sender.clone(),
            incoming: receiver,
        })
    }
}

fn wg_thread(socket: std::net::UdpSocket, receiver: crossbeam_channel::Receiver<event::Event>) {
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
    let mut peer_vpn_ip = None;

    loop {
        // Try to get a message from Wireguard
        let mut buf = [0; 1024];
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(50)))
            .unwrap();
        match socket.recv_from(&mut buf) {
            Ok((size, endpoint)) => {
                // Fill in the peer IP if it's the first packet
                if peer_ip.is_none() {
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

                        let ip_packet = etherparse::SlicedPacket::from_ip(b).unwrap();

                        let incoming_ip = match ip_packet.ip.unwrap() {
                            etherparse::InternetSlice::Ipv4(a, _) => a,
                            etherparse::InternetSlice::Ipv6(_, _) => panic!("IPv6 not supported"),
                        };
                        if peer_vpn_ip.is_none() {
                            println!("Filling in peer VPN IP: {:?}", incoming_ip.source_addr());
                            peer_vpn_ip = Some(incoming_ip.source_addr());
                        }
                        if self_ip.is_none() {
                            println!("Filling in self IP: {:?}", incoming_ip.destination_addr());
                            self_ip = Some(incoming_ip.destination_addr());
                        }

                        // Handle the packet
                        match ip_packet.transport.unwrap() {
                            etherparse::TransportSlice::Icmpv4(ping_send) => {
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
                                    source: incoming_ip.destination_addr(),
                                    destination: addr,
                                    payload: ping_return_packet,
                                }
                                .into();

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
                            etherparse::TransportSlice::Udp(_) => {
                                println!("UDP not implemented");
                            }
                            etherparse::TransportSlice::Tcp(tcp_packet) => {
                                // Determine if the destination is a port we're listening on
                                let destination_port = tcp_packet.destination_port();
                                if handles.contains_key(&destination_port) {
                                    let handle = handles.get_mut(&destination_port).unwrap();
                                    let handle = match handle {
                                        handle::InternalHandle::Tcp(h) => h,
                                        #[allow(unreachable_patterns)]
                                        _ => continue, // wrong protocol
                                    };

                                    // Update the ack and seq numbers
                                    handle.ack = tcp_packet.sequence_number() + 1;
                                    handle.seq = tcp_packet.acknowledgment_number();

                                    // Opening a connection
                                    if tcp_packet.syn() {
                                        // Ack it

                                        let send_tcp = packets::Tcp {
                                            source_port: tcp_packet.destination_port(),
                                            destination_port: handle.port,
                                            sequence_number: handle.seq,
                                            window_size: tcp_packet.window_size(),
                                            urgent_pointer: tcp_packet.urgent_pointer(),
                                            ack_number: handle.ack,
                                            flags: packets::TcpFlags {
                                                fin: false,
                                                syn: false,
                                                rst: false,
                                                psh: false,
                                                ack: true,
                                                urg: false,
                                                ece: false,
                                                cwr: false,
                                            },
                                            pseudo_header: packets::PseudoHeader {
                                                source: self_ip.unwrap(),
                                                destination: peer_vpn_ip.unwrap(),
                                                protocol: 6,
                                                length: 0,
                                            },
                                            data: vec![],
                                        };

                                        let ip_packet: Vec<u8> = packets::Ipv4 {
                                            id: std::process::id() as u16,
                                            ttl: 64,
                                            protocol: 6,
                                            source: self_ip.unwrap(),
                                            destination: peer_vpn_ip.unwrap(),
                                            payload: send_tcp.into(),
                                        }
                                        .into();

                                        let mut buf = [0; 2048];
                                        match tun.encapsulate(&ip_packet, &mut buf) {
                                            boringtun::noise::TunnResult::WriteToNetwork(b) => {
                                                socket.send_to(b, endpoint).unwrap();
                                            }
                                            _ => {
                                                println!("Unexpected result");
                                            }
                                        }

                                        // Send the port to the handle
                                        handle
                                            .outgoing
                                            .send(event::Event::Port(destination_port))
                                            .unwrap();
                                    }

                                    // Closing a connection
                                    if tcp_packet.fin() {
                                        // Ack it
                                        let send_tcp = packets::Tcp {
                                            source_port: tcp_packet.destination_port(),
                                            destination_port: handle.port,
                                            sequence_number: handle.seq,
                                            window_size: tcp_packet.window_size(),
                                            urgent_pointer: tcp_packet.urgent_pointer(),
                                            ack_number: handle.ack,
                                            flags: packets::TcpFlags {
                                                fin: false,
                                                syn: false,
                                                rst: false,
                                                psh: false,
                                                ack: true,
                                                urg: false,
                                                ece: false,
                                                cwr: false,
                                            },
                                            pseudo_header: packets::PseudoHeader {
                                                source: self_ip.unwrap(),
                                                destination: peer_vpn_ip.unwrap(),
                                                protocol: 6,
                                                length: 0,
                                            },
                                            data: vec![],
                                        };

                                        let ip_packet: Vec<u8> = packets::Ipv4 {
                                            id: std::process::id() as u16,
                                            ttl: 64,
                                            protocol: 6,
                                            source: self_ip.unwrap(),
                                            destination: peer_vpn_ip.unwrap(),
                                            payload: send_tcp.into(),
                                        }
                                        .into();

                                        let mut buf = [0; 2048];
                                        match tun.encapsulate(&ip_packet, &mut buf) {
                                            boringtun::noise::TunnResult::WriteToNetwork(b) => {
                                                socket.send_to(b, endpoint).unwrap();
                                            }
                                            _ => {
                                                println!("Unexpected result");
                                            }
                                        }

                                        // Send a fin back to the server
                                        let send_tcp = packets::Tcp {
                                            source_port: tcp_packet.destination_port(),
                                            destination_port: handle.port,
                                            sequence_number: handle.seq,
                                            window_size: tcp_packet.window_size(),
                                            urgent_pointer: tcp_packet.urgent_pointer(),
                                            ack_number: handle.ack,
                                            flags: packets::TcpFlags {
                                                fin: true,
                                                syn: false,
                                                rst: false,
                                                psh: false,
                                                ack: true,
                                                urg: false,
                                                ece: false,
                                                cwr: false,
                                            },
                                            pseudo_header: packets::PseudoHeader {
                                                source: self_ip.unwrap(),
                                                destination: peer_vpn_ip.unwrap(),
                                                protocol: 6,
                                                length: 0,
                                            },
                                            data: vec![],
                                        };

                                        let ip_packet: Vec<u8> = packets::Ipv4 {
                                            id: std::process::id() as u16,
                                            ttl: 64,
                                            protocol: 6,
                                            source: self_ip.unwrap(),
                                            destination: peer_vpn_ip.unwrap(),
                                            payload: send_tcp.into(),
                                        }
                                        .into();

                                        let mut buf = [0; 2048];
                                        match tun.encapsulate(&ip_packet, &mut buf) {
                                            boringtun::noise::TunnResult::WriteToNetwork(b) => {
                                                socket.send_to(b, endpoint).unwrap();
                                            }
                                            _ => {
                                                println!("Unexpected result");
                                            }
                                        }

                                        // Send the close event to the handle
                                        let _ = handle.outgoing.send(event::Event::Closed);
                                    }

                                    // Receiving data
                                    if tcp_packet.psh() {
                                        // Send the data to the handle
                                        handle
                                            .outgoing
                                            .send(event::Event::Transport(
                                                0,
                                                ip_packet.payload.to_vec(),
                                            ))
                                            .unwrap();

                                        // Add the length of the packet to the ack number
                                        handle.ack += (ip_packet.payload.len() - 1) as u32;

                                        // Ack it
                                        let send_tcp = packets::Tcp {
                                            source_port: tcp_packet.destination_port(),
                                            destination_port: handle.port,
                                            sequence_number: handle.seq,
                                            window_size: tcp_packet.window_size(),
                                            urgent_pointer: tcp_packet.urgent_pointer(),
                                            ack_number: handle.ack,
                                            flags: packets::TcpFlags {
                                                fin: false,
                                                syn: false,
                                                rst: false,
                                                psh: false,
                                                ack: true,
                                                urg: false,
                                                ece: false,
                                                cwr: false,
                                            },
                                            pseudo_header: packets::PseudoHeader {
                                                source: self_ip.unwrap(),
                                                destination: peer_vpn_ip.unwrap(),
                                                protocol: 6,
                                                length: 0,
                                            },
                                            data: vec![],
                                        };

                                        let ip_packet: Vec<u8> = packets::Ipv4 {
                                            id: std::process::id() as u16,
                                            ttl: 64,
                                            protocol: 6,
                                            source: self_ip.unwrap(),
                                            destination: peer_vpn_ip.unwrap(),
                                            payload: send_tcp.into(),
                                        }
                                        .into();

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
                                } else {
                                    println!("Unknown port: {}", destination_port);
                                }
                            }
                            etherparse::TransportSlice::Unknown(_) => todo!(),
                        }
                    }
                    boringtun::noise::TunnResult::WriteToTunnelV6(_b, _addr) => {
                        panic!("IPv6 not supported");
                    }
                }
            }
            Err(e) => match e.kind() {
                std::io::ErrorKind::WouldBlock => {}
                _ => {
                    println!("Error receiving: {}", e);
                    return;
                }
            },
        };

        // We can't continue without finding ourselves
        if self_ip == None || peer_ip == None || peer_vpn_ip == None {
            continue;
        }

        // Try to get a message from the channel
        match receiver.try_recv() {
            Ok(event) => {
                match event {
                    event::Event::Transport(internal_port, data) => {
                        // Look up the handle
                        let handle = match handles.get_mut(&internal_port) {
                            Some(handle) => handle,
                            None => {
                                println!("Unknown port: {}", internal_port);
                                continue;
                            }
                        };

                        match handle {
                            handle::InternalHandle::Tcp(handle) => {
                                let tcp_packet = packets::Tcp {
                                    source_port: internal_port,
                                    destination_port: handle.port,
                                    sequence_number: handle.seq,
                                    window_size: 65535,
                                    urgent_pointer: 0,
                                    ack_number: handle.ack,
                                    flags: packets::TcpFlags {
                                        fin: false,
                                        syn: false,
                                        rst: false,
                                        psh: true,
                                        ack: true,
                                        urg: false,
                                        ece: false,
                                        cwr: false,
                                    },
                                    pseudo_header: packets::PseudoHeader {
                                        source: self_ip.unwrap(),
                                        destination: peer_vpn_ip.unwrap(),
                                        protocol: 6,
                                        length: data.len() as u16,
                                    },
                                    data,
                                };

                                let ip_packet: Vec<u8> = packets::Ipv4 {
                                    id: std::process::id() as u16,
                                    ttl: 64,
                                    protocol: 6,
                                    source: self_ip.unwrap(),
                                    destination: peer_vpn_ip.unwrap(),
                                    payload: tcp_packet.into(),
                                }
                                .into();

                                let mut buf = [0; 2048];
                                match tun.encapsulate(&ip_packet, &mut buf) {
                                    boringtun::noise::TunnResult::WriteToNetwork(b) => {
                                        socket.send_to(b, peer_ip.unwrap()).unwrap();
                                    }
                                    _ => {
                                        println!("Unexpected result");
                                    }
                                }
                            }
                        }
                    }
                    event::Event::NewTcp(external_port, sender) => {
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
                            flags: packets::TcpFlags {
                                fin: false,
                                syn: true,
                                rst: false,
                                psh: false,
                                ack: false,
                                urg: false,
                                ece: false,
                                cwr: false,
                            },
                            window_size: 0xFFFF,
                            urgent_pointer: 0,
                            pseudo_header: packets::PseudoHeader {
                                source: self_ip.unwrap(),
                                destination: peer_vpn_ip.unwrap(),
                                protocol: 6,
                                length: 20,
                            },
                            data: vec![],
                        };

                        // Create IP packet
                        let ip_packet: Vec<u8> = packets::Ipv4 {
                            id: std::process::id() as u16,
                            ttl: 64,
                            protocol: 6,
                            source: self_ip.unwrap(),
                            destination: peer_vpn_ip.unwrap(),
                            payload: tcp_packet.into(),
                        }
                        .into();

                        let mut buf = [0; 2048];
                        match tun.encapsulate(&ip_packet, &mut buf) {
                            boringtun::noise::TunnResult::WriteToNetwork(b) => {
                                socket.send_to(b, peer_ip.unwrap()).unwrap();
                            }
                            _ => {
                                println!("Unexpected result");
                            }
                        }

                        // Add it to the hashmap
                        handles.insert(port, handle::InternalHandle::Tcp(handle));
                    }
                    event::Event::Stop => {
                        println!("Stopping Wireguard server...");
                        return;
                    }
                    _ => {
                        println!("This should never happen, errors only go out");
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
