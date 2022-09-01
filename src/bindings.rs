// Jackson Coxson

use std::{
    ffi::CStr,
    net::SocketAddrV4,
    os::raw::{c_char, c_uint, c_void},
    sync::{Arc, Mutex},
};

use lazy_static::lazy_static;
use libc::c_int;
use log::{info, warn};

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
    warn!("FREEING WIREGUARD");
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
                    simple_logger::init_with_level(log::Level::Info).unwrap();
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

    std::mem::forget(wireguard);

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
    pointer: *const u8,
    size: usize,
) -> c_uint {
    // Check the handle
    if handle.is_null() {
        return 0;
    }

    let handle = Box::from_raw(handle as *mut PortHandle);

    // Check the data
    if pointer.is_null() {
        return 0;
    }

    let slice_data = std::slice::from_raw_parts(pointer, size);

    let data = slice_data.to_vec();

    // Send the data
    let res = match handle.send(data) {
        Ok(_) => 0,
        Err(_) => 1,
    };

    std::mem::forget(handle);

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
pub unsafe extern "C" fn tcp_handle_recv(
    handle: *mut PortHandle,
    pointer: *mut c_char,
    len: u32,
) -> c_int {
    // Check the handle
    if handle.is_null() {
        return -1;
    }
    let mut handle = Box::from_raw(handle as *mut PortHandle);

    info!("Attempting to receive {} bytes", len);
    let mut to_return = vec![];

    // Check if we have unused data in the buffer
    while !handle.buffer.is_empty() {
        to_return.push(handle.buffer.remove(0));
        if to_return.len() == len as usize {
            break;
        }
    }

    // Determine if we need any more bytes
    loop {
        if to_return.len() != len as usize {
            match handle.recv() {
                Ok(event) => match event {
                    crate::event::Event::Transport(_, data) => {
                        for i in data {
                            if to_return.len() != len as usize {
                                to_return.push(i)
                            } else {
                                handle.buffer.push(i);
                            }
                        }
                    }
                    _ => {
                        return -1;
                    }
                },
                Err(_) => {
                    return -1;
                }
            }
        } else {
            break;
        }
    }

    let mut fill_pls = c_vec::CVec::new(pointer, len as usize);
    for i in 0..to_return.len() {
        fill_pls[i] = to_return[i] as c_char
    }

    std::mem::forget(fill_pls);
    std::mem::forget(handle);
    len as c_int
}

#[no_mangle]
/// Test function for bindings.
pub extern "C" fn test() {
    println!("Hello from Rust!");
}

/// Initialize the logger
/// # Arguments
/// *level*
///
/// 1 => Error,
///
/// 2 => :Warn,
///
/// 3 => Info,
///
/// 4 => Debug,
///
/// 5 => Trace,
/// # Returns
/// 0 on success, -1 on failure
pub extern "C" fn init_logger(level: libc::c_uint) -> libc::c_int {
    match simple_logger::init_with_level(match level {
        1 => log::Level::Error,
        2 => log::Level::Warn,
        3 => log::Level::Info,
        4 => log::Level::Debug,
        5 => log::Level::Trace,
        _ => return -1,
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
