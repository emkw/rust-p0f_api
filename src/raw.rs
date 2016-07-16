pub const P0F_STR_MAX:       usize = 31;
pub const P0F_STR_SIZE:      usize = P0F_STR_MAX + 1;

pub const P0F_QUERY_MAGIC:     u32 = 0x50304601;
pub const P0F_RESP_MAGIC:      u32 = 0x50304602;

pub const P0F_STATUS_BADQUERY: u32 = 0x00;
pub const P0F_STATUS_OK:       u32 = 0x10;
pub const P0F_STATUS_NOMATCH:  u32 = 0x20;

pub const P0F_ADDR_IPV4:        u8 = 0x04;
pub const P0F_ADDR_IPV6:        u8 = 0x06;

pub const P0F_MATCH_FUZZY:      u8 = 0x01;
pub const P0F_MATCH_GENERIC:    u8 = 0x02;

pub const SIZEOF_QUERY:      usize = 21;
pub const SIZEOF_RESPONSE:   usize = 232;

#[repr(C,packed)]
#[derive(Copy,Clone,Debug)]
/// Raw struct accepted by p0f
pub struct p0f_api_query {
	/// Must be P0F_QUERY_MAGIC
	pub magic: u32,
	/// P0F_ADDR_*
	pub addr_type: u8,
	/// IP address (big endian left align)
	pub addr: [u8; 16],
}

#[repr(C,packed)]
#[derive(Copy,Clone,Debug)]
/// Raw struct returned by p0f
pub struct p0f_api_response {
	/// Must be P0F_RESP_MAGIC
	pub magic: u32,
	/// P0F_STATUS_*
	pub status: u32,

	/// First seen (unix time)
	pub first_seen: u32,
	/// Last seen (unix time)
	pub last_seen: u32,
	/// Total connections seen
	pub total_conn: u32,

	/// Last uptime (minutes)
	pub uptime_min: u32,
	/// Uptime modulo (days)
	pub up_mod_days: u32,

	/// NAT / LB last detected (unix time)
	pub last_nat: u32,
	/// OS chg last detected (unix time)
	pub last_chg: u32,

	/// System distance
	pub distance: i16,

	/// Host is lying about U-A / Server
	pub bad_sw: u8,
	/// Match quality
	pub os_match_q: u8,

	///  Name of detected OS
	pub os_name: [u8; P0F_STR_SIZE],
	/// Flavor of detected OS
	pub os_flavor: [u8; P0F_STR_SIZE],

	/// Name of detected HTTP app
	pub http_name: [u8; P0F_STR_SIZE],
	/// Flavor of detected HTTP app
	pub http_flavor: [u8; P0F_STR_SIZE],

	/// Link type
	pub link_type: [u8; P0F_STR_SIZE],

	/// Language
	pub language: [u8; P0F_STR_SIZE],
}

#[cfg(test)]
mod test {
	use std::mem;

	#[test]
	fn test_query_size() {
		assert_eq!(super::SIZEOF_QUERY, mem::size_of::<super::p0f_api_query>());
	}

	#[test]
	fn test_response_size() {
		assert_eq!(super::SIZEOF_RESPONSE, mem::size_of::<super::p0f_api_response>());
	}
}
