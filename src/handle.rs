// Jackson Coxson

use crate::event::Event;

pub struct PortHandle {
    // The internal port
    pub port: u16,
    pub outgoing: crossbeam_channel::Sender<Event>,
    pub incoming: crossbeam_channel::Receiver<Event>,
}

pub enum InternalHandle {
    Tcp(TcpInternal),
}

pub struct TcpInternal {
    /// The target port
    pub port: u16,
    /// The channel to send events to
    pub outgoing: crossbeam_channel::Sender<Event>,
    /// Sequence number for the next packet
    pub seq: u64,
    /// Ack number for the next packet
    pub ack: u64,
}
