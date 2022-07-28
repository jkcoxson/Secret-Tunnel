// Jackson Coxson

#[derive(Debug)]
pub enum Event {
    /// Transport the packet to the outside world.
    /// Internal port and packet
    Transport(u16, Vec<u8>),
    /// Create a new TCP connection.
    /// External port and channel sender.
    NewTcp(u16, crossbeam_channel::Sender<Event>),
    /// An error occurred
    Error(std::io::Error),
    /// Port return
    Port(u16),
    /// Connection closed
    Closed,
    /// Stop all threads
    Stop,
}
