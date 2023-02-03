pub mod raw;

use std::borrow::ToOwned;
use std::io::{self,Read,Write};
use std::mem;
use std::net::{IpAddr,Ipv4Addr,Ipv6Addr};
use std::os::unix::net::UnixStream;
use std::path::{Path,PathBuf};
use std::time::Duration;

/// p0f API interface.
pub struct P0f {
	socket: Option<UnixStream>,
	path: PathBuf,
}

impl P0f {
	/// Return new p0f api struct with p0f API socket path,
	/// with uninitialized connection.
	pub fn new<P: AsRef<Path>>(path: P) -> Self {
		P0f {
			socket: None,
			path: path.as_ref().to_owned(),
		}
	}

	/// Return new p0f api struct with p0f API socket path.
	/// Returns error if connection to socket fails.
	pub fn new_connect<P: AsRef<Path>>(path: P) -> io::Result<Self> {
		let socket = try!(UnixStream::connect(path.as_ref()));

		Ok(P0f {
			socket: Some(socket),
			.. Self::new(path)
		})
	}

	/// Connect to p0f API socket.
	pub fn connect(&mut self) -> io::Result<()> {
		let socket = try!(UnixStream::connect(self.path.as_path()));
		self.socket = Some(socket);

		Ok(())
	}

	/// Query p0f API for IP address `addr`.
	///
	/// `P0F_STATUS_OK` maps to Ok(Some(P0fResponse)).
	///
	/// `P0F_STATUS_NOMATCH` maps to Ok(None).
	pub fn query(&mut self, addr: &IpAddr) -> io::Result<Option<P0fResponse>> {
		if self.socket.is_none() {
			try!(self.connect());
		}

		if let Some(ref mut socket) = self.socket {
			let mut addr_buff: [u8; 16] = [0; 16];
			let addr_type = match *addr {
				IpAddr::V4(ref addr_v4) => {
					let addr_data = addr_v4.octets();
					addr_buff[0..addr_data.len()].clone_from_slice(&addr_data);

					raw::P0F_ADDR_IPV4
				},
				IpAddr::V6(ref addr_v6) => {
					let addr_data = addr_v6.segments();
					for (i, segment) in addr_data.iter().enumerate() {
						let buff_idx = 2 * i;
						addr_buff[buff_idx]   = (*segment >> 8) as u8;
						addr_buff[buff_idx+1] =  *segment as u8;
					}
					raw::P0F_ADDR_IPV6
				},
			};

			let query = raw::p0f_api_query {
				magic: raw::P0F_QUERY_MAGIC,
				addr_type: addr_type,
				addr: addr_buff,
			};
			// Waiting for const fn size_of...
			let query_data: [u8; raw::SIZEOF_QUERY] = unsafe { mem::transmute(query) };
			try!(socket.write_all(&query_data));

			let mut resp_data: [u8; raw::SIZEOF_RESPONSE] = [0; raw::SIZEOF_RESPONSE];
			try!(socket.read_exact(&mut resp_data));
			let resp: raw::p0f_api_response = unsafe { mem::transmute(resp_data) };

			if resp.magic != raw::P0F_RESP_MAGIC {
				return Err(io::Error::new(
					io::ErrorKind::InvalidData,
					format!(
						"p0f: invalid magic number received: 0x{:x}. Should be: 0x{:x}.",
						{resp.magic},
						raw::P0F_RESP_MAGIC
					)
				));
			}

			match resp.status {
				raw::P0F_STATUS_BADQUERY =>
					return Err(io::Error::new(
						io::ErrorKind::InvalidInput,
						"p0f: Bad Query. [Please report this to p0f_api crate author].",
					)),
				raw::P0F_STATUS_NOMATCH =>
					return Ok(None),
				raw::P0F_STATUS_OK =>
					return Ok(Some(P0fResponse::from_raw_response(&resp))),
				_ =>
					return Err(io::Error::new(
						io::ErrorKind::InvalidData,
						format!(
							"p0f: Unknown status received: 0x{:x}. [Please report this to p0f_api crate author].",
							{resp.status}
						)
					))
			}
			
		}

		Err(io::Error::new(io::ErrorKind::NotConnected, "p0f: Not connected to p0f socket."))
	}

	/// Query by `Ipv4Addr`.
	pub fn query_v4(&mut self, addr: &Ipv4Addr) -> io::Result<Option<P0fResponse>> {
		self.query(&IpAddr::V4(*addr))
	}

	/// Query by `Ipv6Addr`.
	pub fn query_v6(&mut self, addr: &Ipv6Addr) -> io::Result<Option<P0fResponse>> {
		self.query(&IpAddr::V6(*addr))
	}
}

#[derive(Clone,Debug)]
/// Rustified p0f api response.
pub struct P0fResponse {
	/// First seen - seconds from UNIX_EPOCH.
	pub first_seen: i64,
	/// Last seen - seconds from UNIX_EPOCH.
	pub last_seen: i64,
	/// Total connections seen.
	pub total_conn: u32,

	/// Last uptime.
	pub uptime: Duration,
	/// Uptime modulo (days).
	pub uptime_mod_days: u32,

	/// NAT / LB last detected - seconds from UNIX_EPOCH.
	pub last_nat: i64,
	/// OS chg last detected - seconds from UNIX_EPOCH.
	pub last_chg: i64,

	/// System distance.
	pub distance: i16,

	/// Host is lying about U-A / Server.
	///
	/// NOTE: If User-Agent is not present at all, this value stays at 0.
	///
	/// * `1` means OS difference (possibly due to proxying).
	/// * `2` means an outright mismatch.
	pub bad_sw: u8,
	/// Match quality.
	pub os_match_q: u8,

	///  Name of detected OS.
	pub os_name: String,
	/// Flavor of detected OS.
	pub os_flavor: String,

	/// Name of detected HTTP app.
	pub http_name: String,
	/// Flavor of detected HTTP app.
	pub http_flavor: String,

	/// Link type.
	pub link_type: String,

	/// Language.
	pub language: String,
}

impl P0fResponse {
	/// Conversion from `raw::p0f_api_response`.
	fn from_raw_response(resp: &raw::p0f_api_response) -> Self {
		debug_assert_eq!({resp.magic}, raw::P0F_RESP_MAGIC);
		debug_assert_eq!({resp.status}, raw::P0F_STATUS_OK);

		P0fResponse {
			first_seen: resp.first_seen as i64,
			last_seen: resp.last_seen as i64,
			total_conn: resp.total_conn,
			uptime: Duration::from_secs(60 * resp.uptime_min as u64),
			uptime_mod_days: resp.up_mod_days,
			last_nat: resp.last_nat as i64,
			last_chg: resp.last_chg as i64,
			distance: resp.distance,
			bad_sw: resp.bad_sw,
			os_match_q: resp.os_match_q,
			os_name: string_from_sz_slice(&resp.os_name),
			os_flavor: string_from_sz_slice(&resp.os_flavor),
			http_name: string_from_sz_slice(&resp.http_name),
			http_flavor: string_from_sz_slice(&resp.http_flavor),
			link_type: string_from_sz_slice(&resp.link_type),
			language: string_from_sz_slice(&resp.language),
		}
	}

	/// Returns `true` if Match quality has `P0F_MATCH_FUZZY` flag set
	/// (e.g., TTL or DF difference).
	#[inline]
	pub fn os_match_fuzzy(&self) -> bool {
		self.os_match_q & raw::P0F_MATCH_FUZZY != 0
	}

	/// Returns `true` if Match quality has `P0F_MATCH_GENERIC` flag set
	/// (generic signature).
	#[inline]
	pub fn os_match_generic(&self) -> bool {
		self.os_match_q & raw::P0F_MATCH_GENERIC != 0
	}

	/// Returns `true` if there is an OS difference (`bad_sw` >= 1).
	///
	/// NOTE: This will ever return `true` only if p0f encountered some http software headers.
	#[inline]
	pub fn os_difference(&self) -> bool {
		self.bad_sw >= 1
	}

	/// Returns `true` if there's an OS difference (`bad_sw` >= 2).
	///
	/// NOTE: This will ever return `true` only if p0f encountered some http software headers.
	#[inline]
	pub fn os_mismatch(&self) -> bool {
		self.bad_sw >= 2
	}
}

fn string_from_sz_slice(src: &[u8]) -> String {
	let last = src.iter().position(|&x| x == 0).unwrap_or(src.len()-1);

	String::from_utf8_lossy(&src[0..last]).into_owned()
}
