// Jackson Coxson

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddrV4},
    str::FromStr,
};

use secret_tunnel::wireguard::Wireguard;
use smoltcp::{
    iface::{InterfaceBuilder, NeighborCache, Routes},
    socket::TcpSocket,
    storage::RingBuffer,
    time::Instant,
    wire::{EthernetAddress, IpCidr, Ipv4Address, Ipv4Cidr},
};

#[tokio::main]
async fn main() {
    let server = Wireguard::new("0.0.0.0:51820").await;

    // This is our mac address
    let hw_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

    // Create a subnet with a mask of 10.7.0.1
    let ip_cidr = Ipv4Cidr::new(smoltcp::wire::Ipv4Address([10, 7, 0, 1]), 24);

    let default_v4_gw = Ipv4Address::new(10, 7, 0, 10);
    let mut routes_storage = [None; 1];
    let mut routes = Routes::new(&mut routes_storage[..]);
    routes.add_default_ipv4_route(default_v4_gw).unwrap();

    let mut interface = InterfaceBuilder::new(server, vec![])
        .hardware_addr(hw_addr.into())
        .neighbor_cache(NeighborCache::new(BTreeMap::new()))
        .ip_addrs(vec![IpCidr::Ipv4(ip_cidr)])
        .routes(routes)
        .finalize();

    println!("{}", interface.ipv4_addr().unwrap().to_string());

    let tx_buffer = RingBuffer::new([0; 128].to_vec());
    let rx_buffer = RingBuffer::new([0; 64].to_vec());
    let socket = TcpSocket::new(rx_buffer, tx_buffer);

    let handle = interface.add_socket(socket);

    let timestamp = Instant::now();
    match interface.poll(timestamp) {
        Ok(_) => {}
        Err(e) => {
            println!("poll error: {}", e);
        }
    }

    let x: (&mut TcpSocket, &mut _) = interface.get_socket_and_context(handle);

    x.0.connect(
        x.1,
        SocketAddrV4::new(Ipv4Addr::from_str("10.7.0.10").unwrap(), 12345),
        54321,
    )
    .unwrap();

    println!("Didn't crash!");

    loop {
        let data =
            x.0.recv(|data| {
                let mut data = data.to_owned();
                if !data.is_empty() {
                    println!("data");
                    data = data.split(|&b| b == b'\n').collect::<Vec<_>>().concat();
                    data.reverse();
                    data.extend(b"\n");
                }
                (data.len(), data)
            })
            .unwrap();
        println!("{:02X?}", data);
    }
}
