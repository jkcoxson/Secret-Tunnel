cargo build
cp secret_tunnel.h /usr/local/include/
cp target/debug/libsecret_tunnel.a /usr/local/lib/
cp target/debug/libsecret_tunnel.dylib /usr/local/lib/
cp secret_tunnel.pc /usr/local/lib/pkgconfig/