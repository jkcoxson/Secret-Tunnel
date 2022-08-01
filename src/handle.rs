// Jackson Coxson

use crossbeam_channel::{RecvError, SendError, TryRecvError};

use crate::event::Event;

pub struct PortHandle {
    pub internal_port: u16,
    pub external_port: u16,
    pub outgoing: crossbeam_channel::Sender<Event>,
    pub incoming: crossbeam_channel::Receiver<Event>,
}

impl PortHandle {
    pub fn recv(&self) -> Result<Event, RecvError> {
        self.incoming.recv()
    }
    pub fn try_recv(&self) -> Result<Event, TryRecvError> {
        self.incoming.try_recv()
    }
    pub fn send(&self, payload: Vec<u8>) -> Result<(), SendError<Event>> {
        self.outgoing
            .send(Event::Transport(self.internal_port, payload))
    }
    pub fn close(&self) {
        self.outgoing.send(Event::Closed).unwrap();
    }
}

pub(crate) enum InternalHandle {
    Tcp(TcpInternal),
}

pub(crate) struct TcpInternal {
    /// The target port
    pub(crate) port: u16,
    /// The channel to send events to
    pub(crate) outgoing: crossbeam_channel::Sender<Event>,
    /// Sequence number for the next packet
    pub(crate) seq: u32,
    /// Ack number for the next packet
    pub(crate) ack: u32,
}
