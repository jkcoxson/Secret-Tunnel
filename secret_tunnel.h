// Jackson Coxson

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


typedef struct PortHandle PortHandle;

typedef struct Wireguard Wireguard;

/**
 * Connect to a TCP server running on the client. Blocks until successful handshake.
 * # Arguments
 * * 'wireguard' - The pointer to the Wireguard struct. Pass `NULL` to lookup or create a static instance.
 * * 'address' - The address to connect to. Usually `
 * # Returns
 * A pointer to the handle on success, or `NULL` on failure.
 * # Safety
 * Don't be stupid
 */
void *connect_tcp(struct Wireguard *wireguard, uint16_t port);

/**
 * Destroys a Wireguard instance, freeing the memory on the stack
 * # Arguments
 * * `handle` - The handle to the Wireguard instance.
 * # Safety
 * Don't be stupid
 */
void free_wireguard(struct Wireguard *handle);

/**
 * Initialize the logger
 * # Arguments
 * *level*
 *
 * 1 => Error,
 *
 * 2 => :Warn,
 *
 * 3 => Info,
 *
 * 4 => Debug,
 *
 * 5 => Trace,
 * # Returns
 * 0 on success, -1 on failure
 */
int init_logger(unsigned int level);

/**
 * Initializes a static Wireguard instance that is stored globally. Blocks until a Wireguard handshake is made.
 * # Arguments
 * * `address` - The address to listen on. Usually `127.0.0.1:51820`.
 * # Returns
 * 0 on success
 */
int init_static_wireguard(const char *address);

/**
 * Debugs an app from an app ID
 * # Safety
 * Don't be stupid
 */
int minimuxer_debug_app(char *app_id);

/**
 * Creates a new Wireguard instance. This is blocking until a successful handshake!!
 * # Arguments
 * * `address` - The address to listen on. Usually `127.0.0.1:51820`.
 * # Returns
 * A pointer to the struct on success, or `NULL` on failure.
 */
void *new_wireguard(const char *address);

/**
 * Starts the muxer and heartbeat client
 * # Arguments
 * Pairing file as a list of chars terminated by null
 * # Safety
 * Don't be stupid
 */
int start_usbmuxd(char *pairing_file);

/**
 * Sets the current environment variable for libusbmuxd to localhost
 */
void target_minimuxer_address(void);

/**
 * Receives data from the client through the handle.
 * # Arguments
 * * 'handle' - The pointer to the handle.
 * * 'data' - The buffer to receive the data into.
 * # Returns
 * The number of bytes received on success, or 0 on failure.
 * # Safety
 * Don't be stupid
 */
int tcp_handle_recv(struct PortHandle *handle, char *pointer, uint32_t len);

/**
 * Sends data to the client through the handle.
 * # Arguments
 * * 'handle' - The pointer to the handle.
 * * 'data' - The data to send.
 * * 'size' - The size of the data.
 * # Returns
 * 0 on success, or 1 on failure.
 * # Safety
 * Don't be stupid
 */
unsigned int tcp_handle_send(struct PortHandle *handle, const uint8_t *pointer, size_t size);

/**
 * Test function for bindings.
 */
void test(void);
