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
4. Adapt libimobiledevice to use the fake IP/TCP packets
5. Profit
**Completeness: 2/5**

# How to use
Don't

ETA: July of 2069
