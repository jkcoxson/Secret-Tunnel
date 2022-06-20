// Authored by Jackson Coxson

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
        protocol: impl Into<String>,
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

        let lock = self.routes.lock().await;

        for route in &*lock {
            if route.protocol == protocol && route.port == port && route.address == address {
                return Some(route.sender.clone());
            }
        }

        None
    }
}

impl Clone for Router {
    fn clone(&self) -> Self {
        Router {
            routes: self.routes.clone(),
        }
    }
}
