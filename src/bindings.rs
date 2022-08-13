// Jackson Coxson

use std::{
    ffi::CStr,
    net::SocketAddrV4,
    os::raw::{c_char, c_uint, c_void},
    sync::{Arc, Mutex},
};

use lazy_static::lazy_static;

use crate::{handle::PortHandle, wireguard::Wireguard};

lazy_static! {
    // Used for C code that can't hold the Wireguard struct.
    static ref WG: Arc<Mutex<Option<crate::wireguard::Wireguard>>> = Arc::new(Mutex::new(None));
}

#[no_mangle]
/// Creates a new Wireguard instance. This is blocking until a successful handshake!!
/// # Arguments
/// * `address` - The address to listen on. Usually `127.0.0.1:51820`.
/// # Returns
/// A pointer to the struct on success, or `NULL` on failure.
pub extern "C" fn new_wireguard(address: *const c_char) -> *mut c_void {
    // Check the address
    if address.is_null() {
        return std::ptr::null_mut();
    }
    let address = unsafe { CStr::from_ptr(address as *mut _) };
    let address = match address.to_str() {
        Ok(address) => address,
        Err(_) => return std::ptr::null_mut(),
    };
    let address = match address.parse::<SocketAddrV4>() {
        Ok(address) => address,
        Err(_) => return std::ptr::null_mut(),
    };

    Box::into_raw(Box::new(Wireguard::new(address))) as *mut c_void
}

#[no_mangle]
/// Destroys a Wireguard instance, freeing the memory on the stack
/// # Arguments
/// * `handle` - The handle to the Wireguard instance.
/// # Safety
/// Don't be stupid
pub unsafe extern "C" fn free_wireguard(handle: *mut Wireguard) {
    if handle.is_null() {
        if let Ok(mut wg) = WG.lock() {
            *wg = None;
        }
    } else {
        Box::from_raw(handle);
    }
}

#[no_mangle]
/// Connect to a TCP server running on the client. Blocks until successful handshake.
/// # Arguments
/// * 'wireguard' - The pointer to the Wireguard struct. Pass `NULL` to lookup or create a static instance.
/// * 'address' - The address to connect to. Usually `
/// # Returns
/// A pointer to the handle on success, or `NULL` on failure.
/// # Safety
/// Don't be stupid
pub unsafe extern "C" fn connect_tcp(wireguard: *mut Wireguard, port: u16) -> *mut c_void {
    // Check the wireguard pointer
    let wireguard = if wireguard.is_null() {
        // See if we have a static pointer
        match WG.lock() {
            Ok(mut wg) => match wg.clone().as_mut() {
                Some(wg) => Box::new(wg.clone()),
                None => {
                    // Create a new one
                    let created_wg = Wireguard::new(SocketAddrV4::new(
                        std::net::Ipv4Addr::new(0, 0, 0, 0),
                        51820,
                    ));

                    // Store it
                    *wg = Some(created_wg.clone());

                    Box::new(created_wg)
                }
            },
            Err(_) => return std::ptr::null_mut(),
        }
    } else {
        Box::from_raw(wireguard)
    };

    let handle = match wireguard.tcp_connect(port) {
        Ok(handle) => handle,
        Err(_) => return std::ptr::null_mut(),
    };

    Box::into_raw(Box::new(handle)) as *mut c_void
}

#[no_mangle]
/// Sends data to the client through the handle.
/// # Arguments
/// * 'handle' - The pointer to the handle.
/// * 'data' - The data to send.
/// * 'size' - The size of the data.
/// # Returns
/// 0 on success, or 1 on failure.
/// # Safety
/// Don't be stupid
pub unsafe extern "C" fn tcp_handle_send(
    handle: *mut PortHandle,
    data: *const u8,
    size: usize,
) -> c_uint {
    // Check the handle
    if handle.is_null() {
        return 0;
    }

    println!("Unpacking handle");
    let handle = Box::from_raw(handle as *mut PortHandle);

    // Check the data
    if data.is_null() {
        return 0;
    }

    println!("Unpacking data");
    let data = std::slice::from_raw_parts(data, size);

    println!("Converting to vec");
    let data = data.to_vec();
    println!("{:?}", data);

    // Send the data
    println!("Sending data");
    let res = match handle.send(data) {
        Ok(_) => 0,
        Err(_) => 1,
    };

    println!("Dropping");

    res
}

#[no_mangle]
/// Receives data from the client through the handle.
/// # Arguments
/// * 'handle' - The pointer to the handle.
/// * 'data' - The buffer to receive the data into.
/// # Returns
/// The number of bytes received on success, or 0 on failure.
/// # Safety
/// Don't be stupid
pub unsafe extern "C" fn tcp_handle_recv(handle: *mut PortHandle, to_fill: *mut u8) -> c_uint {
    // Check the handle
    if handle.is_null() {
        return 0;
    }
    let handle = Box::from_raw(handle as *mut PortHandle);

    match handle.recv() {
        Ok(event) => {
            match event {
                crate::event::Event::Transport(_, data) => {
                    let mut fill_pls = Vec::from_raw_parts(to_fill, data.len(), data.len());
                    fill_pls.extend_from_slice(&data);
                    data.len() as c_uint
                }
                _ => 0,
            }
        }
        Err(_) => 0,
    }
}

#[no_mangle]
/// Test function for bindings.
pub extern "C" fn test() {
    println!("Hello from Rust!");
}
