// Jackson Coxson
// Packet creation that isn't bad

pub(crate) struct Ipv4 {
    pub(crate) id: u16,
    pub(crate) ttl: u8,
    pub(crate) protocol: u8,
    pub(crate) source: std::net::Ipv4Addr,
    pub(crate) destination: std::net::Ipv4Addr,
    pub(crate) payload: Vec<u8>,
}

impl From<Ipv4> for Vec<u8> {
    fn from(ipv4: Ipv4) -> Vec<u8> {
        // The 45 is *technically* dynamic, but all the packets I've seen have been 45
        // Bitwise operations are hard
        let mut to_return = vec![0x45, 0x00];

        // Total length - left as 0 for now
        to_return.extend_from_slice(&[0x00, 0x00]);
        // Identification
        to_return.extend_from_slice(&ipv4.id.to_be_bytes());
        // Fragment offset
        to_return.extend_from_slice(&[0x00, 0x00]);
        // TTL
        to_return.push(ipv4.ttl);
        // Protocol
        to_return.push(ipv4.protocol);
        // Checksum
        to_return.extend_from_slice(&[0x00, 0x00]);
        // Source
        to_return.extend_from_slice(&ipv4.source.octets());
        // Destination
        to_return.extend_from_slice(&ipv4.destination.octets());

        // Change byte 6 and 7 to the length of the payload
        to_return[2] = (84 >> 8) as u8;
        to_return[3] = (84 & 0xFF) as u8;

        // Calculate the checksum
        let checksum = ipv4_checksum(&to_return);
        to_return[10] = (checksum >> 8) as u8;
        to_return[11] = (checksum & 0xFF) as u8;

        // Payload
        to_return.extend_from_slice(&ipv4.payload);

        to_return
    }
}

pub(crate) struct Icmp {
    pub(crate) type_: u8,
    pub(crate) code: u8,
    pub(crate) identifier: u16,
    pub(crate) sequence_number: u16,
    pub(crate) data: Vec<u8>,
}

impl From<Icmp> for Vec<u8> {
    fn from(icmp: Icmp) -> Vec<u8> {
        let mut to_return = vec![icmp.type_, icmp.code];

        // Checksum - left as 0 to skip validation (because lazy)
        to_return.extend_from_slice(&[0x00, 0x00]);
        // Identifier
        to_return.extend_from_slice(&icmp.identifier.to_be_bytes());
        // Sequence number
        to_return.extend_from_slice(&icmp.sequence_number.to_be_bytes());
        // Data
        to_return.extend_from_slice(&icmp.data);

        // Fix the checksum
        let checksum = checksum(&to_return, 1);
        to_return[2] = (checksum >> 8) as u8;
        to_return[3] = (checksum & 0xFF) as u8;

        to_return
    }
}

pub(crate) struct Tcp {
    pub(crate) source_port: u16,
    pub(crate) destination_port: u16,
    pub(crate) sequence_number: u64,
    pub(crate) ack_number: u64,
    pub(crate) data_offset: u8,
    pub(crate) reserved: u8,
    pub(crate) flags: u8,
    pub(crate) window_size: u16,
    pub(crate) urgent_pointer: u16,
    pub(crate) data: Vec<u8>,
}

pub(crate) struct TcpFlags {
    pub(crate) fin: bool,
    pub(crate) syn: bool,
    pub(crate) rst: bool,
    pub(crate) psh: bool,
    pub(crate) ack: bool,
    pub(crate) urg: bool,
    pub(crate) ece: bool,
    pub(crate) cwr: bool,
}

impl From<TcpFlags> for u8 {
    fn from(flags: TcpFlags) -> u8 {
        let mut to_return = 0;
        if flags.fin {
            to_return |= 1 << 0;
        }
        if flags.syn {
            to_return |= 1 << 1;
        }
        if flags.rst {
            to_return |= 1 << 2;
        }
        if flags.psh {
            to_return |= 1 << 3;
        }
        if flags.ack {
            to_return |= 1 << 4;
        }
        if flags.urg {
            to_return |= 1 << 5;
        }
        if flags.ece {
            to_return |= 1 << 6;
        }
        if flags.cwr {
            to_return |= 1 << 7;
        }
        to_return
    }
}

impl From<Tcp> for Vec<u8> {
    fn from(tcp: Tcp) -> Vec<u8> {
        let mut to_return = vec![];

        // Source port
        to_return.extend_from_slice(&tcp.source_port.to_be_bytes());
        // Destination port
        to_return.extend_from_slice(&tcp.destination_port.to_be_bytes());
        // Sequence number
        to_return.extend_from_slice(&tcp.sequence_number.to_be_bytes());
        // Ack number
        to_return.extend_from_slice(&tcp.ack_number.to_be_bytes());
        // Data offset
        to_return.push(tcp.data_offset);
        // Reserved
        to_return.push(tcp.reserved);
        // Flags
        to_return.extend_from_slice(&tcp.flags.to_be_bytes());
        // Window size
        to_return.extend_from_slice(&tcp.window_size.to_be_bytes());
        // Checksum - left as 0 and filled in later
        to_return.extend_from_slice(&[0x00, 0x00]);
        // Urgent pointer
        to_return.extend_from_slice(&tcp.urgent_pointer.to_be_bytes());
        // Data
        to_return.extend_from_slice(&tcp.data);

        // Calculate the checksum
        let checksum = tcp_checksum(&to_return);
        to_return[16] = (checksum >> 8) as u8;
        to_return[17] = (checksum & 0xFF) as u8;

        to_return
    }
}

/// Sum all words (16 bit chunks) in the given data. The word at word offset
/// `skipword` will be skipped. Each word is treated as big endian.
/// Stolen from https://docs.rs/pnet_packet/0.31.0/src/pnet_packet/util.rs.html with minor modifications
fn sum_be_words(data: &[u8], skipword: usize) -> u32 {
    if data.is_empty() {
        return 0;
    }
    let len = data.len();
    let mut cur_data = data;
    let mut sum = 0u32;
    let mut i = 0;
    while cur_data.len() >= 2 {
        if i != skipword {
            // It's safe to unwrap because we verified there are at least 2 bytes
            sum += u16::from_be_bytes(cur_data[0..2].try_into().unwrap()) as u32;
        }
        cur_data = &cur_data[2..];
        i += 1;
    }

    // If the length is odd, make sure to checksum the final byte
    if i != skipword && len & 1 != 0 {
        sum += (data[len - 1] as u32) << 8;
    }

    sum
}

/// Calculates a checksum. Used by ipv4 and icmp. The two bytes starting at `skipword * 2` will be
/// ignored. Supposed to be the checksum field, which is regarded as zero during calculation.
/// Stolen from https://docs.rs/pnet_packet/0.31.0/src/pnet_packet/util.rs.html
pub fn checksum(data: &[u8], skipword: usize) -> u16 {
    if data.is_empty() {
        return 0;
    }
    let sum = sum_be_words(data, skipword);
    finalize_checksum(sum)
}

fn finalize_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    !sum as u16
}

/// Calculate the checksum for an IPv4 packet.
pub fn ipv4_checksum(buffer: &[u8]) -> u16 {
    use byteorder::{BigEndian, ReadBytesExt};
    use std::io::Cursor;

    let mut result = 0xffffu32;
    let mut buffer = Cursor::new(buffer);

    while let Ok(value) = buffer.read_u16::<BigEndian>() {
        // Skip checksum field.
        if buffer.position() == 12 {
            continue;
        }

        result += value as u32;

        if result > 0xffff {
            result -= 0xffff;
        }
    }

    !result as u16
}

fn tcp_checksum(buffer: &[u8]) -> u16 {
    use byteorder::{BigEndian, ReadBytesExt};
    use std::io::Cursor;

    let mut result = 0xffffu32;
    let mut buffer = Cursor::new(buffer);

    while let Ok(value) = buffer.read_u16::<BigEndian>() {
        result += value as u32;

        if result > 0xffff {
            result -= 0xffff;
        }
    }

    !result as u16
}
