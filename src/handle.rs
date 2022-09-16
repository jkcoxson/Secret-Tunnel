// Jackson Coxson

use std::fmt::Debug;

use crossbeam_channel::{RecvError, SendError, TryRecvError};

use crate::event::Event;

#[derive(Clone)]
pub struct PortHandle {
    pub internal_port: u16,
    pub external_port: u16,
    pub outgoing: crossbeam_channel::Sender<Event>,
    pub incoming: crossbeam_channel::Receiver<Event>,

    /// Used for FFI
    pub buffer: Vec<u8>,
}

impl PortHandle {
    pub fn recv(&self) -> Result<Event, RecvError> {
        self.incoming.recv()
    }
    pub fn try_recv(&self) -> Result<Event, TryRecvError> {
        self.incoming.try_recv()
    }
    pub fn send(&self, payload: Vec<u8>) -> Result<(), SendError<Event>> {
        // info!("Sending: {:?}", payload);
        self.outgoing
            .send(Event::Transport(self.internal_port, payload))
    }
    pub fn close(&self) {
        self.outgoing
            .send(Event::Closed(self.internal_port))
            .unwrap();
    }
}

impl Debug for PortHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortHandle")
            .field("internal_port", &self.internal_port)
            .field("external_port", &self.external_port)
            .field("outgoing", &self.outgoing)
            .field("incoming", &self.incoming)
            .finish()
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
    /// The state that a finish is in
    pub(crate) fin_state: FinStatus,
}

#[derive(PartialEq, Eq)]
pub(crate) enum FinStatus {
    FirstSent,
    FirstReceived,
    Chill,
}
