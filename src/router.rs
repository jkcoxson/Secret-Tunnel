// Authored by Jackson Coxson

use rand::Rng;
use std::sync::Arc;
use tokio::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    Mutex,
};

pub struct Router {
    routes: Arc<Mutex<Vec<Route>>>,
}

pub struct Route {
    /// The protocol to filter on
    protocol: String,

    /// The port to filter on
    port: u16,

    /// The address to filter on
    address: String,

    /// The sender to send packets that match the filter
    sender: UnboundedSender<Vec<u8>>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            routes: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn bind(
        &mut self,
        protocol: RouterProtocol,
        address: impl Into<String>,
        port: u16,
    ) -> Result<UnboundedReceiver<Vec<u8>>, ()> {
        let protocol = protocol.into();
        let address = address.into();

        // Check if this route already exists
        if self.find(&protocol, &address, port).await.is_some() {
            return Err(());
        }

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        let route = Route {
            protocol,
            port,
            address: address.into(),
            sender: tx,
        };

        self.routes.lock().await.push(route);

        Ok(rx)
    }

    pub async fn find(
        &self,
        protocol: impl Into<String>,
        address: impl Into<String>,
        port: u16,
    ) -> Option<UnboundedSender<Vec<u8>>> {
        let protocol = protocol.into();
        let address = address.into();

        println!("Finding a route for {}:{} on {}", address, port, protocol);

        let lock = self.routes.lock().await;

        for route in &*lock {
            if route.protocol == protocol && route.port == port && route.address == address {
                return Some(route.sender.clone());
            }
        }

        None
    }

    /// Gets a random port that is not in use
    pub async fn random_port(&self) -> u16 {
        let mut rng = rand::thread_rng();
        let mut port = rng.gen_range(1024..65535);

        let used_ports = self.get_used_ports().await;

        while used_ports.contains(&port) {
            port = rng.gen_range(1024..65535);
        }

        port
    }

    async fn get_used_ports(&self) -> Vec<u16> {
        let mut ports = Vec::new();
        let lock = self.routes.lock().await;

        for route in &*lock {
            ports.push(route.port);
        }

        ports
    }
}

pub enum RouterProtocol {
    UDP,
    TCP,
}

impl From<RouterProtocol> for String {
    fn from(protocol: RouterProtocol) -> Self {
        match protocol {
            RouterProtocol::UDP => "UDP".to_string(),
            RouterProtocol::TCP => "TCP".to_string(),
        }
    }
}

impl Clone for Router {
    fn clone(&self) -> Self {
        Router {
            routes: self.routes.clone(),
        }
    }
}
