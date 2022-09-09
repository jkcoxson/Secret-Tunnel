// Authored by Jackson Coxson
// Holds stuff for maintaining a Wireguard connection

use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use log::{error, info, warn};
use std::collections::HashMap;
use std::{net::SocketAddr, str::FromStr, sync::Arc};

use packet_builder::payload::PayloadData;
use packet_builder::*;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::Packet;

use crate::event;
use crate::handle::{self, FinStatus};
use crate::packets;

#[derive(Clone)]
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

        // Ready sender
        let (ready_sender, ready) = crossbeam_channel::bounded(0);

        // Start the new thread
        std::thread::spawn(move || wg_thread(socket, receiver, ready_sender));

        // Wait until we're ready to return
        ready.recv().unwrap();
        info!("WireGuard is ready");

        Wireguard { sender }
    }

    pub fn stop(&self) {
        warn!("Stopping self");
        match self.sender.send(event::Event::Stop) {
            Ok(_) => {}
            Err(e) => error!("Failed to send stop to Wireguard: {:?}", e),
        }
    }

    /// Opens a new TCP connection
    pub fn tcp_connect(&self, port: u16) -> Result<handle::PortHandle, std::io::Error> {
        info!("Connecting to port {}", port);

        // Create a channel to send events to
        let (sender, receiver) = crossbeam_channel::unbounded();

        // Send the event to the thread
        self.sender
            .send(event::Event::NewTcp(port, sender))
            .unwrap();

        // Wait to get the internal port
        info!("Waiting to receive internal port");
        let internal_port = match receiver.recv().unwrap() {
            event::Event::Port(port) => port,
            event::Event::Error(err) => return Err(err),
            _ => unreachable!(),
        };
        info!("Got internal port");

        // Return the handle
        Ok(handle::PortHandle {
            internal_port,
            external_port: port,
            outgoing: self.sender.clone(),
            incoming: receiver,
            buffer: vec![],
        })
    }

    /// Tests if the Wireguard thread is running
    pub fn ping(&self, timeout: std::time::Duration) -> bool {
        let (tx, rx) = crossbeam_channel::bounded(1);

        match self.sender.send(event::Event::Ping(tx)) {
            Ok(_) => (),
            Err(_) => return false,
        }

        rx.recv_timeout(timeout).is_ok()
    }
}

fn wg_thread(
    socket: std::net::UdpSocket,
    receiver: crossbeam_channel::Receiver<event::Event>,
    ready_sender: crossbeam_channel::Sender<()>,
) {
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

    let mut ready = false;

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
                        if !ready {
                            ready = true;
                            ready_sender.send(()).unwrap();
                        }
                    }
                    boringtun::noise::TunnResult::Err(_) => {
                        // don't care
                    }
                    boringtun::noise::TunnResult::WriteToNetwork(b) => {
                        socket.send_to(b, endpoint).unwrap();
                        loop {
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
                        info!("Incoming:\n{:02X?}\n", b);

                        // Parse the bytes as an IP packet
                        let ip_packet = etherparse::SlicedPacket::from_ip(b).unwrap();

                        let incoming_ip = match ip_packet.ip.unwrap() {
                            etherparse::InternetSlice::Ipv4(a, _) => a,
                            etherparse::InternetSlice::Ipv6(_, _) => panic!("IPv6 not supported"),
                        };
                        if peer_vpn_ip.is_none() {
                            info!("Filling in peer VPN IP: {:?}", incoming_ip.source_addr());
                            peer_vpn_ip = Some(incoming_ip.source_addr());
                        }
                        if self_ip.is_none() {
                            info!("Filling in self IP: {:?}", incoming_ip.destination_addr());
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
                                        warn!("Unexpected result");
                                    }
                                }
                            }
                            etherparse::TransportSlice::Icmpv6(_) => unimplemented!(),
                            etherparse::TransportSlice::Udp(_) => {
                                error!("UDP not implemented");
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

                                    // Opening a connection
                                    if tcp_packet.syn() {
                                        // Syn is special: it has a phantom data byte so we increase ack by 1
                                        handle.ack = tcp_packet.sequence_number() + 1;
                                        info!("Setting ack to {}", handle.ack);

                                        // Ack it
                                        let mut pkt_buf = [0u8; 1500];
                                        let pkt = packet_builder!(
                                            pkt_buf,
                                            ipv4({set_source => ipv4addr!(self_ip.unwrap().to_string()), set_destination => ipv4addr!(peer_vpn_ip.unwrap().to_string()) }) /
                                            tcp({set_source => tcp_packet.destination_port(), set_destination => handle.port, set_flags => (TcpFlags::ACK), set_sequence => handle.seq, set_acknowledgement => handle.ack}) /
                                            payload({"".to_string().into_bytes()})
                                        );

                                        let mut buf = [0; 2048];
                                        match tun.encapsulate(pkt.packet(), &mut buf) {
                                            boringtun::noise::TunnResult::WriteToNetwork(b) => {
                                                socket.send_to(b, endpoint).unwrap();
                                            }
                                            _ => {
                                                warn!("Unexpected result");
                                            }
                                        }

                                        // Send the port to the handle
                                        handle
                                            .outgoing
                                            .send(event::Event::Port(destination_port))
                                            .unwrap();

                                        continue;
                                    }

                                    // Check the sequence number
                                    if tcp_packet.sequence_number() != handle.ack {
                                        warn!("Unexpected sequence number");
                                        // Ack the old packet to request a retransmission
                                        let mut pkt_buf = [0u8; 1500];
                                        let pkt = packet_builder!(
                                            pkt_buf,
                                            ipv4({set_source => ipv4addr!(self_ip.unwrap().to_string()), set_destination => ipv4addr!(peer_vpn_ip.unwrap().to_string()) }) /
                                            tcp({set_source => tcp_packet.destination_port(), set_destination => handle.port, set_flags => (TcpFlags::ACK), set_sequence => handle.seq, set_acknowledgement => handle.ack}) /
                                            payload({Vec::<u8>::new()})
                                        );

                                        let mut buf = [0; 2048];
                                        match tun.encapsulate(pkt.packet(), &mut buf) {
                                            boringtun::noise::TunnResult::WriteToNetwork(b) => {
                                                socket.send_to(b, endpoint).unwrap();
                                            }
                                            _ => {
                                                warn!("Unexpected result");
                                            }
                                        }
                                        continue;
                                    }

                                    // Check if we got a fin response
                                    if tcp_packet.fin() && handle.fin_state == FinStatus::FirstSent
                                    {
                                        // Ack it
                                        let mut pkt_buf = [0u8; 1500];
                                        let pkt = packet_builder!(
                                            pkt_buf,
                                            ipv4({set_source => ipv4addr!(self_ip.unwrap().to_string()), set_destination => ipv4addr!(peer_vpn_ip.unwrap().to_string()) }) /
                                            tcp({set_source => tcp_packet.destination_port(), set_destination => handle.port, set_flags => (TcpFlags::ACK), set_sequence => handle.seq, set_acknowledgement => handle.ack}) /
                                            payload({"".to_string().into_bytes()})
                                        );

                                        let mut buf = [0; 2048];
                                        match tun.encapsulate(pkt.packet(), &mut buf) {
                                            boringtun::noise::TunnResult::WriteToNetwork(b) => {
                                                socket.send_to(b, endpoint).unwrap();
                                            }
                                            _ => {
                                                warn!("Unexpected result");
                                            }
                                        }

                                        // Close it
                                        match handle.outgoing.send(event::Event::Closed(0)) {
                                            Ok(_) => {}
                                            Err(e) => error!("Unable to send to handle: {e}"),
                                        }

                                        continue;
                                    }

                                    // Receiving data
                                    if tcp_packet.psh() || !ip_packet.payload.is_empty() {
                                        // The next sequence number we expect is the one we just received
                                        // plus the length of the data we received plus one
                                        handle.ack += ip_packet.payload.len() as u32;

                                        // Send the data to the handle
                                        handle
                                            .outgoing
                                            .send(event::Event::Transport(
                                                0,
                                                ip_packet.payload.to_vec(),
                                            ))
                                            .unwrap();

                                        // Ack it
                                        let mut pkt_buf = [0u8; 1500];
                                        let pkt = packet_builder!(
                                            pkt_buf,
                                            ipv4({set_source => ipv4addr!(self_ip.unwrap().to_string()), set_destination => ipv4addr!(peer_vpn_ip.unwrap().to_string()) }) /
                                            tcp({set_source => tcp_packet.destination_port(), set_destination => handle.port, set_flags => (TcpFlags::ACK), set_sequence => handle.seq, set_acknowledgement => handle.ack}) /
                                            payload({"".to_string().into_bytes()})
                                        );

                                        let mut buf = [0; 2048];
                                        match tun.encapsulate(pkt.packet(), &mut buf) {
                                            boringtun::noise::TunnResult::WriteToNetwork(b) => {
                                                socket.send_to(b, endpoint).unwrap();
                                            }
                                            _ => {
                                                warn!("Unexpected result");
                                            }
                                        }
                                    }

                                    // Closing a connection
                                    if tcp_packet.fin() {
                                        match handle.fin_state {
                                            FinStatus::Chill => {
                                                handle.fin_state = FinStatus::FirstReceived;

                                                // Send a fin back to the server
                                                let mut pkt_buf = [0u8; 1500];
                                                let pkt = packet_builder!(
                                                    pkt_buf,
                                                    ipv4({set_source => ipv4addr!(self_ip.unwrap().to_string()), set_destination => ipv4addr!(peer_vpn_ip.unwrap().to_string()) }) /
                                                    tcp({set_source => tcp_packet.destination_port(), set_destination => handle.port, set_flags => (TcpFlags::ACK | TcpFlags::FIN), set_sequence => handle.seq, set_acknowledgement => handle.ack}) /
                                                    payload({"".to_string().into_bytes()})
                                                );

                                                let mut buf = [0; 2048];
                                                match tun.encapsulate(pkt.packet(), &mut buf) {
                                                    boringtun::noise::TunnResult::WriteToNetwork(b) => {
                                                        socket.send_to(b, endpoint).unwrap();
                                                    }
                                                    _ => {
                                                        warn!("Unexpected result");
                                                    }
                                                }

                                                // We'll wait for the ack to our fin to send the close event to the handle
                                            }
                                            FinStatus::FirstReceived => {
                                                // We shouldn't have received another fin request, we already got one
                                                // Just abort
                                                let mut pkt_buf = [0u8; 1500];
                                                let pkt = packet_builder!(
                                                    pkt_buf,
                                                    ipv4({set_source => ipv4addr!(self_ip.unwrap().to_string()), set_destination => ipv4addr!(peer_vpn_ip.unwrap().to_string()) }) /
                                                    tcp({set_source => tcp_packet.destination_port(), set_destination => handle.port, set_flags => (TcpFlags::RST), set_sequence => handle.seq, set_acknowledgement => handle.ack}) /
                                                    payload({"".to_string().into_bytes()})
                                                );

                                                let mut buf = [0; 2048];
                                                match tun.encapsulate(pkt.packet(), &mut buf) {
                                                    boringtun::noise::TunnResult::WriteToNetwork(b) => {
                                                        socket.send_to(b, endpoint).unwrap();
                                                    }
                                                    _ => {
                                                        warn!("Unexpected result");
                                                    }
                                                }

                                                match handle.outgoing.send(event::Event::Closed(0))
                                                {
                                                    Ok(_) => {}
                                                    Err(e) => {
                                                        error!("Unable to send to handle: {e}");
                                                    }
                                                }
                                                continue;
                                            }
                                            FinStatus::FirstSent => {
                                                // Ack it and close
                                                let mut pkt_buf = [0u8; 1500];
                                                let pkt = packet_builder!(
                                                    pkt_buf,
                                                    ipv4({set_source => ipv4addr!(self_ip.unwrap().to_string()), set_destination => ipv4addr!(peer_vpn_ip.unwrap().to_string()) }) /
                                                    tcp({set_source => tcp_packet.destination_port(), set_destination => handle.port, set_flags => (TcpFlags::ACK), set_sequence => handle.seq, set_acknowledgement => handle.ack}) /
                                                    payload({"".to_string().into_bytes()})
                                                );

                                                let mut buf = [0; 2048];
                                                match tun.encapsulate(pkt.packet(), &mut buf) {
                                                    boringtun::noise::TunnResult::WriteToNetwork(b) => {
                                                        socket.send_to(b, endpoint).unwrap();
                                                    }
                                                    _ => {
                                                        warn!("Unexpected result");
                                                    }
                                                }

                                                match handle.outgoing.send(event::Event::Closed(0))
                                                {
                                                    Ok(_) => {}
                                                    Err(e) => {
                                                        error!("Unable to send to handle: {e}");
                                                    }
                                                }
                                                continue;
                                            }
                                        }
                                    }
                                } else {
                                    warn!("Unknown port: {}", destination_port);
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
                std::io::ErrorKind::TimedOut => {}
                _ => {
                    error!("Error receiving: {}", e);
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
                                warn!("Unknown port: {}", internal_port);
                                continue;
                            }
                        };

                        match handle {
                            handle::InternalHandle::Tcp(handle) => {
                                let mut pkt_buf = [0u8; 1500];
                                let pkt = packet_builder!(
                                    pkt_buf,
                                    ipv4({set_source => ipv4addr!(self_ip.unwrap().to_string()), set_destination => ipv4addr!(peer_vpn_ip.unwrap().to_string()) }) /
                                    tcp({set_source => internal_port, set_destination => handle.port, set_flags => (TcpFlags::ACK | TcpFlags::PSH), set_sequence => handle.seq, set_acknowledgement => handle.ack}) /
                                    payload({data.clone()})
                                );

                                handle.seq += data.len() as u32;

                                let mut buf = [0; 2048];
                                match tun.encapsulate(pkt.packet(), &mut buf) {
                                    boringtun::noise::TunnResult::WriteToNetwork(b) => {
                                        socket.send_to(b, peer_ip.unwrap()).unwrap();
                                    }
                                    _ => {
                                        warn!("Unexpected result");
                                    }
                                }
                            }
                        }
                    }
                    event::Event::NewTcp(external_port, sender) => {
                        info!("Creating TCP connection: {}", external_port);
                        // Randomly generate a port not in use
                        let mut port;
                        loop {
                            port = rand::random::<u16>();
                            if !handles.contains_key(&port) {
                                break;
                            }
                        }

                        // Create a new handle
                        let mut handle = handle::TcpInternal {
                            port: external_port,
                            outgoing: sender,
                            seq: rand::random::<u32>(),
                            ack: 0,
                            fin_state: FinStatus::Chill,
                        };

                        // Create TCP syn packet
                        let mut pkt_buf = [0u8; 1500];
                        let pkt = packet_builder!(
                            pkt_buf,
                            ipv4({set_source => ipv4addr!(self_ip.unwrap().to_string()), set_destination => ipv4addr!(peer_vpn_ip.unwrap().to_string()) }) /
                            tcp({set_source => port, set_destination => external_port, set_flags => (TcpFlags::SYN), set_sequence => handle.seq, set_acknowledgement => 0}) /
                            payload({"".to_string().into_bytes()})
                        );

                        let mut buf = [0; 2048];
                        match tun.encapsulate(pkt.packet(), &mut buf) {
                            boringtun::noise::TunnResult::WriteToNetwork(b) => {
                                socket.send_to(b, peer_ip.unwrap()).unwrap();
                            }
                            _ => {
                                warn!("Unexpected result");
                            }
                        }

                        handle.seq += 1;
                        handle.ack += 1;

                        // Add it to the hashmap
                        handles.insert(port, handle::InternalHandle::Tcp(handle));
                    }
                    event::Event::Stop => {
                        warn!("Stopping Wireguard server...");
                        return;
                    }
                    event::Event::Ping(sender) => match sender.send(()) {
                        Ok(_) => {}
                        Err(_) => warn!("Failed to respond to ping"),
                    },
                    event::Event::Closed(internal_port) => {
                        // Send a fin to the target
                        let handle = match handles.get_mut(&internal_port) {
                            Some(h) => h,
                            None => {
                                error!("No internal port found!!");
                                continue;
                            }
                        };

                        match handle {
                            handle::InternalHandle::Tcp(handle) => {
                                let mut pkt_buf = [0u8; 1500];
                                let pkt = packet_builder!(
                                    pkt_buf,
                                    ipv4({set_source => ipv4addr!(self_ip.unwrap().to_string()), set_destination => ipv4addr!(peer_vpn_ip.unwrap().to_string()) }) /
                                    tcp({set_source => handle.port, set_destination => handle.port, set_flags => (TcpFlags::FIN), set_sequence => handle.seq, set_acknowledgement => handle.ack}) /
                                    payload({"".to_string().into_bytes()})
                                );

                                let mut buf = [0; 2048];
                                match tun.encapsulate(pkt.packet(), &mut buf) {
                                    boringtun::noise::TunnResult::WriteToNetwork(b) => {
                                        socket.send_to(b, peer_ip.unwrap()).unwrap();
                                    }
                                    _ => {
                                        warn!("Unexpected result");
                                    }
                                }
                                handle.fin_state = FinStatus::FirstSent;
                            }
                        }
                    }
                    _ => {
                        error!("This should never happen, errors only go out");
                    }
                }
            }
            Err(crossbeam_channel::TryRecvError::Empty) => {}
            Err(crossbeam_channel::TryRecvError::Disconnected) => {
                warn!("Channel disconnected");
            }
        }
    }
}
