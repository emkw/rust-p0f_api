extern crate p0f_api;

use std::net::IpAddr;
use std::str::FromStr;

use p0f_api::P0f;

pub fn main() {
	// Program arguments: [ip addr] [p0f socket path]
	let ip = std::env::args().nth(1).unwrap_or("127.0.0.1".into());
	let path = std::env::args().nth(2).unwrap_or("p0f.sock".into());

	// Try to connect to p0f socket.
	let mut p0f = P0f::new_connect(&path).expect(&format!(r#"Could not connect to p0f socket "{}""#, &path));
	// Try to parse IP address.
	let addr = IpAddr::from_str(&ip).expect(&format!(r#"Invalid IP address: "{}"#, ip));

	// Send query to p0f API.
	let resp = p0f.query(&addr);

	if let Ok(resp) = resp {
		// We have a correct response.

		if let Some(resp) = resp {
			// Address is known by p0f.
			println!("Ok: {:?} -> {:#?}.", addr, resp);
		} else {
			// Address is not known by p0f.
			println!("p0f returned no match.");
		}
	} else if let Err(resp_err) = resp {
		// We had en error communicating with API.
		println!("Response error: {:#?}.", resp_err);
	}

	// Ipv4Addr query variant.
	p0f.query_v4( &std::net::Ipv4Addr::new(127, 0, 0, 1) ).unwrap();
	p0f.query_v4( &[127, 0, 0, 1].into() ).unwrap();
	p0f.query_v4( &0x7f000001.into() ).unwrap();

	// Ipv6Addr query variant.
	p0f.query_v6( &std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1) ).unwrap();
	p0f.query_v6( &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1].into() ).unwrap();
}
