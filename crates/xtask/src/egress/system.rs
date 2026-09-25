//! System-selected PTR lookup on Linux/macOS; this adapter does not enumerate a PTR RRset.
//! All automated verification uses FixtureResolver; the FFI boundary is inspected, never run.

use ::egress::{DnsLookupError, DnsResolver};
use std::net::{IpAddr, ToSocketAddrs};

/// Opt-in production adapter used only when the CLI has no DNS fixture argument.
pub(super) struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsLookupError> {
        reverse(ip)
    }

    fn addresses(&self, fqdn: &str) -> Result<Vec<IpAddr>, DnsLookupError> {
        (absolute_query(fqdn).as_str(), 0)
            .to_socket_addrs()
            .map(|all| all.map(|address| address.ip()).collect())
            .map_err(|_| DnsLookupError::Unavailable)
    }
}

// A trailing dot makes the name absolute, disabling search-list completion into another zone.
fn absolute_query(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
enum Address {
    V4(libc::sockaddr_in),
    V6(libc::sockaddr_in6),
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Address {
    fn new(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => Self::V4(libc::sockaddr_in {
                #[cfg(target_os = "macos")]
                sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(ip.octets()),
                },
                sin_zero: [0; 8],
            }),
            IpAddr::V6(ip) => Self::V6(libc::sockaddr_in6 {
                #[cfg(target_os = "macos")]
                sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: ip.octets(),
                },
                sin6_scope_id: 0,
            }),
        }
    }

    fn raw(&self) -> (*const libc::sockaddr, libc::socklen_t) {
        match self {
            Self::V4(address) => (
                std::ptr::from_ref(address).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ),
            Self::V6(address) => (
                std::ptr::from_ref(address).cast(),
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            ),
        }
    }
}

/// Obtains the system's selected reverse name without numeric fallback.
///
/// # Safety
/// The typed local owns initialized sockaddr layout, family and exact size for the entire call.
/// Its address is stable while borrowed. The mutable host buffer advertises exactly its capacity;
/// the service pointer is null with zero length. NI_NAMEREQD refuses numeric fallback. Searching
/// for NUL and copying bytes use bounded safe slices, so decoding cannot overread either buffer.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn reverse(ip: IpAddr) -> Result<Vec<String>, DnsLookupError> {
    const NI_MAXHOST: usize = libc::NI_MAXHOST as usize;
    let mut host = [0 as libc::c_char; NI_MAXHOST];
    let address = Address::new(ip);
    let (pointer, length) = address.raw();
    // Both borrowed allocations outlive this call and the lengths match their actual storage.
    let result = unsafe {
        libc::getnameinfo(
            pointer,
            length,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };
    if result != 0 {
        return Err(DnsLookupError::Unavailable);
    }
    let end = host
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(DnsLookupError::Unavailable)?;
    let bytes = host[..end]
        .iter()
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    let name = String::from_utf8(bytes).map_err(|_| DnsLookupError::Unavailable)?;
    if name.is_empty() {
        return Err(DnsLookupError::Unavailable);
    }
    Ok(vec![name])
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn reverse(_ip: IpAddr) -> Result<Vec<String>, DnsLookupError> {
    Err(DnsLookupError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::absolute_query;

    #[test]
    fn forward_query_is_absolute() {
        let absolute = "crawler.egress.example.net.";
        assert!(
            absolute_query("crawler.egress.example.net") == absolute,
            "forward query must append the root label"
        );
        assert!(
            absolute_query(absolute) == absolute,
            "absolute forward query changed"
        );
        let source = include_str!("system.rs");
        let body = source
            .split_once("    fn addresses(")
            .unwrap()
            .1
            .split_once("\n    }")
            .unwrap()
            .0;
        let compact = |text: &str| {
            text.chars()
                .filter(|c| !c.is_ascii_whitespace())
                .collect::<String>()
        };
        let expected = "(absolute_query(fqdn).as_str(), 0).to_socket_addrs()";
        assert_eq!(compact(body).matches(&compact(expected)).count(), 1);
    }
}
