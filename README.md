# p0f_api

This crate provides Rust interface for communicating with [p0f](http://lcamtuf.coredump.cx/p0f3/) unix socket query API,
for use with `std::net::IpAddr`, `std::net::Ipv4Addr` and `std::net::Ipv6Addr`.  
Since it uses Rust `std::os::unix::net::UnixStream` it won't work on systems that do not support it.

It has been developed with p0f version 3.09b.

## How to use it?

### Cargo.toml:
```toml
[dependencies]
p0f_api = "~0.1.2"
```

### Code:
Please see `examples/query.rs`.
