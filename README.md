# SECRET TUNNEL!
```
...Yeah, and I forget the next couple of lines, but then it goes...
Secret tunnel!
Secret tunnel!
Through the mountain! 
Secret, secret, secret, secret tunnel!"
```

In all seriousness, this library is meant to create loopback connections to lockdownd.
It tricks lockdownd into thinking it's not a loopback connection using Wireguard.

# Basic Functional Overview
1. Listens on a port for incoming Wireguard connections
2. Handshakes with Wireguard
3. Create and send fake IP/TCP packets to Wireguard
4. Adapt [libimobiledevice](https://github.com/jkcoxson/libimobiledevice) to use the fake IP/TCP packets
5. Profit

**Completeness: 5/5**

# TCP Stack
The TCP stack is a barebones implementation of a TCP/IP stack. It makes many assumptions about the reliability of the underlying transport layer, and makes little effort to handle any errors.
- [x] Packets are generated and checksummed
- [ ] Maximum segment size is negotiated.
- [ ] Window scaling is negotiated.
- [x] Multiple packets are transmitted without waiting for an acknowledgement.
- [ ] Reassembly of out-of-order segments is supported, with no more than 4 or 32 gaps in sequence space.
- [ ] Keep-alive packets may be sent at a configurable interval.
- [ ] Retransmission timeout
- [ ] Time-wait timeout
- [ ] Delayed acknowledgements are supported, with configurable delay.
- [ ] Nagle's algorithm is implemented. 

# How to use
Don't

ETA: July of 2069
