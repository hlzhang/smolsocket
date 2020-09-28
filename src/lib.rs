#[cfg_attr(test, macro_use)]
extern crate log;

use core::{convert::TryFrom, fmt};

use byteorder::{BigEndian, ByteOrder};
#[cfg(feature = "rt_tokio")]
use futures::prelude::*;
#[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
use smoltcp::wire::{IpAddress, IpEndpoint};
#[cfg(feature = "proto-ipv4")]
use smoltcp::wire::Ipv4Address;
#[cfg(feature = "proto-ipv6")]
use smoltcp::wire::Ipv6Address;
#[cfg(feature = "rt_tokio")]
use tokio_util::{codec::*, udp::*};

#[cfg(feature = "proto-ipv4")]
pub use crate::ipv4::{ipv4_addr, ipv4_addr_from_bytes, SocketAddrV4};
#[cfg(feature = "proto-ipv6")]
pub use crate::ipv6::{ipv6_addr, ipv6_addr_from_bytes, SocketAddrV6};
#[cfg(feature = "std")]
pub use crate::std::*;

type Result<T> = core::result::Result<T, Error>;

#[cfg(feature = "rt_tokio")]
pub type TokioUdpPacket = (bytes::Bytes, ::std::net::SocketAddr);
#[cfg(feature = "rt_tokio")]
pub type TokioUdpBytesSink = stream::SplitSink<UdpFramed<BytesCodec>, TokioUdpPacket>;
#[cfg(feature = "rt_tokio")]
pub type TokioUdpBytesStream = stream::SplitStream<UdpFramed<BytesCodec>>;

pub const LEN_V4: usize = 6;
pub const LEN_V6: usize = 18;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    AddrParseError,
    UnspecifiedIp,
}

impl ::std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::AddrParseError => write!(f, "invalid IP address bytes"),
            Error::UnspecifiedIp => write!(f, "UnspecifiedIp"),
        }
    }
}

/// merge two u8s into u16
pub fn port_from_bytes(high: u8, low: u8) -> u16 {
    u16::from(high) << 8 | u16::from(low)
}

pub fn port_to_bytes(port: u16) -> [u8; 2] {
    let mut buf = [0; 2];
    BigEndian::write_u16(&mut buf, port);
    buf
}

#[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub enum SocketAddr {
    /// An IPv4 socket address.
    #[cfg(feature = "proto-ipv4")]
    V4(SocketAddrV4),
    /// An IPv6 socket address.
    #[cfg(feature = "proto-ipv6")]
    V6(SocketAddrV6),
}

#[allow(clippy::len_without_is_empty)]
#[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
impl SocketAddr {
    pub fn new(ip: IpAddress, port: u16) -> Result<Self> {
        match ip {
            #[cfg(feature = "proto-ipv4")]
            IpAddress::Ipv4(ip) => Ok(SocketAddr::new_v4(ip, port)),
            #[cfg(feature = "proto-ipv6")]
            IpAddress::Ipv6(ip) => Ok(SocketAddr::V6(SocketAddrV6::new(ip, port))),
            IpAddress::Unspecified => Err(Error::UnspecifiedIp),
            _ => unreachable!(),
        }
    }

    #[cfg(feature = "proto-ipv4")]
    pub fn new_v4(ip: Ipv4Address, port: u16) -> Self {
        SocketAddr::V4(SocketAddrV4::new(ip, port))
    }

    #[cfg(feature = "proto-ipv4")]
    pub fn new_v4_all_zeros() -> Self {
        SocketAddr::new_ip4_port(0, 0, 0, 0, 0)
    }

    #[cfg(feature = "proto-ipv4")]
    pub fn v4_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() == LEN_V4 {
            let ip_addr = ipv4_addr_from_bytes(&bytes[0..LEN_V4 - 2])?;
            let port_bytes = &bytes[LEN_V4 - 2..LEN_V4];
            let port = port_from_bytes(port_bytes[0], port_bytes[1]);
            Ok(SocketAddr::new_v4(ip_addr, port))
        } else {
            Err(Error::AddrParseError)
        }
    }

    #[cfg(feature = "proto-ipv4")]
    pub fn new_ip4_port(a0: u8, a1: u8, a2: u8, a3: u8, port: u16) -> Self {
        SocketAddr::V4(SocketAddrV4::new_ip4_port(a0, a1, a2, a3, port))
    }

    #[cfg(feature = "proto-ipv6")]
    pub fn new_v6(ip: Ipv6Address, port: u16) -> Self {
        SocketAddr::V6(SocketAddrV6::new(ip, port))
    }

    #[cfg(feature = "proto-ipv6")]
    pub fn new_v6_all_zeros() -> Self {
        SocketAddr::new_ip6_port(0, 0, 0, 0, 0, 0, 0, 0, 0)
    }

    #[cfg(feature = "proto-ipv6")]
    pub fn v6_from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() == LEN_V6 {
            let ip_addr = ipv6_addr_from_bytes(&bytes[0..LEN_V6 - 2])?;
            let port_bytes = &bytes[LEN_V6 - 2..LEN_V6];
            let port = port_from_bytes(port_bytes[0], port_bytes[1]);
            Ok(SocketAddr::new_v6(ip_addr, port))
        } else {
            Err(Error::AddrParseError)
        }
    }

    #[cfg(feature = "proto-ipv6")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_ip6_port(
        a0: u16,
        a1: u16,
        a2: u16,
        a3: u16,
        a4: u16,
        a5: u16,
        a6: u16,
        a7: u16,
        port: u16,
    ) -> Self {
        SocketAddr::V6(SocketAddrV6::new_ip6_port(
            a0, a1, a2, a3, a4, a5, a6, a7, port,
        ))
    }

    pub fn len(&self) -> usize {
        match self {
            #[cfg(feature = "proto-ipv4")]
            SocketAddr::V4(addr) => addr.len(),
            #[cfg(feature = "proto-ipv6")]
            SocketAddr::V6(addr) => addr.len(),
        }
    }

    pub fn ip(&self) -> IpAddress {
        match self {
            #[cfg(feature = "proto-ipv4")]
            SocketAddr::V4(addr) => IpAddress::Ipv4(addr.addr),
            #[cfg(feature = "proto-ipv6")]
            SocketAddr::V6(addr) => IpAddress::Ipv6(addr.addr),
        }
    }

    pub fn ip_octets(&self) -> Vec<u8> {
        match self {
            #[cfg(feature = "proto-ipv4")]
            SocketAddr::V4(addr) => addr.addr.0.to_vec(),
            #[cfg(feature = "proto-ipv6")]
            SocketAddr::V6(addr) => addr.addr.0.to_vec(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            #[cfg(feature = "proto-ipv4")]
            SocketAddr::V4(addr) => addr.port,
            #[cfg(feature = "proto-ipv6")]
            SocketAddr::V6(addr) => addr.port,
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            #[cfg(feature = "proto-ipv4")]
            SocketAddr::V4(addr) => addr.to_vec(),
            #[cfg(feature = "proto-ipv6")]
            SocketAddr::V6(addr) => addr.to_vec(),
        }
    }

    pub fn emmit(&self, bytes: &mut [u8]) {
        match self {
            #[cfg(feature = "proto-ipv4")]
            SocketAddr::V4(addr) => addr.emmit(bytes),
            #[cfg(feature = "proto-ipv6")]
            SocketAddr::V6(addr) => addr.emmit(bytes),
        }
    }

    #[cfg(feature = "rt_tokio")]
    pub async fn bind_udp(&self) -> ::std::io::Result<(Self, tokio::net::UdpSocket)> {
        let addr: ::std::net::SocketAddr = self.into();
        let udp_socket = tokio::net::UdpSocket::bind(addr).await?;
        let local_addr = udp_socket.local_addr()?.into();
        Ok((local_addr, udp_socket))
    }

    #[cfg(feature = "rt_tokio")]
    pub async fn bind_tcp(&self) -> ::std::io::Result<(Self, tokio::net::TcpListener)> {
        let addr: ::std::net::SocketAddr = self.into();
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?.into();
        Ok((local_addr, listener))
    }

    #[cfg(feature = "rt_tokio")]
    pub async fn connect_tcp(&self) -> ::std::io::Result<(Self, tokio::net::TcpStream)> {
        let addr: ::std::net::SocketAddr = self.into();
        let ts = tokio::net::TcpStream::connect(addr).await?;
        let local_addr = ts.local_addr()?.into();
        Ok((local_addr, ts))
    }

    #[cfg(feature = "rt_tokio")]
    pub async fn to_udp_framed(&self) -> ::std::io::Result<(Self, UdpFramed<BytesCodec>)> {
        let (local_addr, udp_socket) = self.bind_udp().await?;
        Ok((local_addr, UdpFramed::new(udp_socket, BytesCodec::new())))
    }

    #[cfg(feature = "rt_tokio")]
    pub async fn to_udp_split(&self) -> ::std::io::Result<(Self, TokioUdpBytesSink, TokioUdpBytesStream)> {
        let (local_addr, framed) = self.to_udp_framed().await?;
        let (sink, stream) = framed.split();
        Ok((local_addr, sink, stream))
    }
}

#[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
impl From<SocketAddr> for IpEndpoint {
    fn from(val: SocketAddr) -> Self {
        match val {
            #[cfg(feature = "proto-ipv4")]
            SocketAddr::V4(val) => IpEndpoint::new(IpAddress::Ipv4(val.addr), val.port),
            #[cfg(feature = "proto-ipv6")]
            SocketAddr::V6(val) => IpEndpoint::new(IpAddress::Ipv6(val.addr), val.port),
        }
    }
}

#[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
impl TryFrom<&[u8]> for SocketAddr {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        match value.len() {
            #[cfg(feature = "proto-ipv4")]
            6 => SocketAddr::v4_from_bytes(value),
            #[cfg(feature = "proto-ipv6")]
            18 => SocketAddr::v6_from_bytes(value),
            _ => Err(Error::AddrParseError),
        }
    }
}

#[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
impl fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            #[cfg(feature = "proto-ipv4")]
            SocketAddr::V4(ref a) => a.fmt(f),
            #[cfg(feature = "proto-ipv6")]
            SocketAddr::V6(ref a) => a.fmt(f),
        }
    }
}

#[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
impl fmt::Debug for SocketAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

#[cfg(feature = "proto-ipv4")]
mod ipv4 {
    use core::fmt;

    use smoltcp::wire::Ipv4Address;

    use super::{Error, LEN_V4, port_to_bytes, Result};

    pub fn ipv4_addr_from_bytes(bytes: &[u8]) -> Result<Ipv4Address> {
        if bytes.len() == 4 {
            Ok(Ipv4Address::from_bytes(bytes))
        } else {
            Err(Error::AddrParseError)
        }
    }

    pub fn ipv4_addr(a0: u8, a1: u8, a2: u8, a3: u8) -> Ipv4Address {
        ipv4_addr_from_bytes(&[a0, a1, a2, a3]).expect("should be valid")
    }

    #[derive(Copy, Clone, Eq, Hash, PartialEq)]
    pub struct SocketAddrV4 {
        pub addr: Ipv4Address,
        pub port: u16,
    }

    #[allow(clippy::len_without_is_empty)]
    #[allow(clippy::trivially_copy_pass_by_ref)]
    impl SocketAddrV4 {
        pub fn new(addr: Ipv4Address, port: u16) -> Self {
            SocketAddrV4 { addr, port }
        }

        pub fn new_ip4_port(a0: u8, a1: u8, a2: u8, a3: u8, port: u16) -> Self {
            SocketAddrV4 {
                addr: Ipv4Address::new(a0, a1, a2, a3),
                port,
            }
        }

        pub fn len(&self) -> usize {
            LEN_V4
        }

        pub fn to_vec(&self) -> Vec<u8> {
            let mut result = Vec::with_capacity(self.len());
            result.extend_from_slice(&self.addr.0);
            result.extend_from_slice(&port_to_bytes(self.port));
            result
        }

        pub fn emmit(&self, bytes: &mut [u8]) {
            bytes[0..4].copy_from_slice(&self.addr.0);
            bytes[4..6].copy_from_slice(&port_to_bytes(self.port));
        }
    }

    impl fmt::Display for SocketAddrV4 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}:{}", self.addr, self.port)
        }
    }

    impl fmt::Debug for SocketAddrV4 {
        fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Display::fmt(self, fmt)
        }
    }
}

#[cfg(feature = "proto-ipv6")]
mod ipv6 {
    use core::fmt;

    use byteorder::{BigEndian, ByteOrder};
    use smoltcp::wire::Ipv6Address;

    use super::{Error, LEN_V6, port_to_bytes, Result};

    #[cfg(feature = "proto-ipv6")]
    pub fn ipv6_addr_from_bytes(bytes: &[u8]) -> Result<Ipv6Address> {
        if bytes.len() == 16 {
            Ok(Ipv6Address::from_bytes(bytes))
        } else {
            Err(Error::AddrParseError)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn ipv6_addr(
        a0: u16,
        a1: u16,
        a2: u16,
        a3: u16,
        a4: u16,
        a5: u16,
        a6: u16,
        a7: u16,
    ) -> Ipv6Address {
        let ip_address: [u16; 8] = [a0, a1, a2, a3, a4, a5, a6, a7];
        let mut ip_address_bytes = [0u8; 16];
        {
            let p = &mut ip_address_bytes[..];
            for (idx, quartet) in ip_address.iter().enumerate() {
                let idx = idx * 2;
                BigEndian::write_u16(&mut p[idx..idx + 2], *quartet);
            }
        }
        ipv6_addr_from_bytes(&ip_address_bytes).expect("should be valid")
    }

    #[derive(Copy, Clone, Eq, Hash, PartialEq)]
    pub struct SocketAddrV6 {
        pub addr: Ipv6Address,
        pub port: u16,
    }

    #[allow(clippy::len_without_is_empty)]
    #[allow(clippy::trivially_copy_pass_by_ref)]
    impl SocketAddrV6 {
        pub fn new(addr: Ipv6Address, port: u16) -> Self {
            SocketAddrV6 { addr, port }
        }

        #[allow(clippy::too_many_arguments)]
        pub fn new_ip6_port(
            a0: u16,
            a1: u16,
            a2: u16,
            a3: u16,
            a4: u16,
            a5: u16,
            a6: u16,
            a7: u16,
            port: u16,
        ) -> Self {
            SocketAddrV6 {
                addr: Ipv6Address::new(a0, a1, a2, a3, a4, a5, a6, a7),
                port,
            }
        }

        pub fn len(&self) -> usize {
            LEN_V6
        }

        pub fn to_vec(&self) -> Vec<u8> {
            let mut result = Vec::with_capacity(self.len());
            result.extend_from_slice(&self.addr.0);
            result.extend_from_slice(&port_to_bytes(self.port));
            result
        }

        pub fn emmit(&self, bytes: &mut [u8]) {
            bytes[0..16].copy_from_slice(&self.addr.0);
            bytes[16..18].copy_from_slice(&port_to_bytes(self.port));
        }
    }

    impl fmt::Display for SocketAddrV6 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "[{}]:{}", self.addr, self.port)
        }
    }

    impl fmt::Debug for SocketAddrV6 {
        fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Display::fmt(self, fmt)
        }
    }
}

#[cfg(feature = "std")]
mod std {
    #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
    use ::std::net::{IpAddr, SocketAddr as StdSocketAddr};
    #[cfg(feature = "proto-ipv4")]
    use ::std::net::{Ipv4Addr, SocketAddrV4 as StdSocketAddrV4};
    #[cfg(feature = "proto-ipv6")]
    use ::std::net::{Ipv6Addr, SocketAddrV6 as StdSocketAddrV6};

    #[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
    use smoltcp::wire::{IpAddress, IpEndpoint};
    #[cfg(feature = "proto-ipv4")]
    use smoltcp::wire::Ipv4Address;
    #[cfg(feature = "proto-ipv6")]
    use smoltcp::wire::Ipv6Address;

    use super::{Error, Result};
    #[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
    use super::SocketAddr;
    #[cfg(feature = "proto-ipv4")]
    use super::SocketAddrV4;
    #[cfg(feature = "proto-ipv6")]
    use super::SocketAddrV6;

    #[cfg(feature = "proto-ipv4")]
    pub trait IntoStdIpv4Addr: Sized {
        fn into_std(self) -> Ipv4Addr;
    }

    #[cfg(feature = "proto-ipv4")]
    impl IntoStdIpv4Addr for Ipv4Address {
        fn into_std(self) -> Ipv4Addr {
            self.0.into()
        }
    }

    #[cfg(feature = "proto-ipv6")]
    pub trait IntoStdIpv6Addr: Sized {
        fn into_std(self) -> Ipv6Addr;
    }

    #[cfg(feature = "proto-ipv6")]
    impl IntoStdIpv6Addr for Ipv6Address {
        fn into_std(self) -> Ipv6Addr {
            self.0.into()
        }
    }

    #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
    pub trait IntoStdIpAddr: Sized {
        fn into_std(self) -> Result<IpAddr>;
    }

    #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
    impl IntoStdIpAddr for IpAddress {
        fn into_std(self) -> Result<IpAddr> {
            match self {
                IpAddress::Ipv4(ip) => Ok(ip.0.into()),
                IpAddress::Ipv6(ip) => Ok(ip.0.into()),
                IpAddress::Unspecified => Err(Error::UnspecifiedIp),
                _ => unreachable!(),
            }
        }
    }

    #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
    pub trait IntoStdSocketAddr: Sized {
        fn into_std(self) -> Result<StdSocketAddr>;
    }

    #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
    impl IntoStdSocketAddr for IpEndpoint {
        fn into_std(self) -> Result<StdSocketAddr> {
            let addr: IpAddr = self.addr.into_std()?;
            Ok(StdSocketAddr::new(addr, self.port))
        }
    }

    #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
    impl From<SocketAddr> for StdSocketAddr {
        fn from(val: SocketAddr) -> Self {
            match val {
                SocketAddr::V4(val) => {
                    StdSocketAddr::V4(StdSocketAddrV4::new(val.addr.0.into(), val.port))
                }
                SocketAddr::V6(val) => {
                    StdSocketAddr::V6(StdSocketAddrV6::new(val.addr.0.into(), val.port, 0, 0))
                }
            }
        }
    }

    #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
    impl From<&SocketAddr> for StdSocketAddr {
        fn from(val: &SocketAddr) -> Self {
            match val {
                SocketAddr::V4(val) => {
                    StdSocketAddr::V4(StdSocketAddrV4::new(val.addr.0.into(), val.port))
                }
                SocketAddr::V6(val) => {
                    StdSocketAddr::V6(StdSocketAddrV6::new(val.addr.0.into(), val.port, 0, 0))
                }
            }
        }
    }

    #[cfg(all(feature = "proto-ipv4", feature = "proto-ipv6"))]
    impl From<StdSocketAddr> for SocketAddr {
        fn from(val: StdSocketAddr) -> Self {
            match val {
                StdSocketAddr::V4(val) => SocketAddr::V4(SocketAddrV4 {
                    addr: Ipv4Address::from(*val.ip()),
                    port: val.port(),
                }),
                StdSocketAddr::V6(val) => SocketAddr::V6(SocketAddrV6 {
                    addr: Ipv6Address::from(*val.ip()),
                    port: val.port(),
                }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ::std::env;
    #[cfg(all(feature = "std", feature = "proto-ipv4", feature = "proto-ipv6"))]
    use ::std::net::IpAddr;
    #[cfg(all(feature = "std", feature = "proto-ipv4"))]
    use ::std::net::Ipv4Addr;
    #[cfg(all(feature = "std", feature = "proto-ipv6"))]
    use ::std::net::Ipv6Addr;
    #[cfg(all(feature = "std", feature = "proto-ipv4", feature = "proto-ipv6"))]
    use ::std::net::SocketAddr as StdSocketAddr;

    use super::*;

    #[cfg(feature = "proto-ipv4")]
    #[test]
    fn ipv4_socket_addr() {
        if env::var("RUST_LOG").is_err() {
            env::set_var("RUST_LOG", "debug");
        }
        let _ = pretty_env_logger::try_init_timed();

        let ip_address_bytes = [127, 0, 0, 1];
        let ip_address: Ipv4Address = ipv4_addr(127, 0, 0, 1);
        info!("ip4 ip_address: {}", ip_address);
        info!("ip4 ip_address debug: {:?}", ip_address);
        assert_eq!(ip_address.as_bytes(), &ip_address_bytes);

        let socket_addr = SocketAddrV4::new_ip4_port(127, 0, 0, 1, 8080);
        info!("ip4 socket_addr: {}", socket_addr);
        info!("ip4 socket_addr debug: {:?}", socket_addr);
        assert_eq!(socket_addr.len(), LEN_V4);
        assert_eq!(socket_addr.addr.as_bytes(), &ip_address_bytes);
        assert_eq!(
            socket_addr.addr.as_bytes(),
            &socket_addr.to_vec().as_slice()[0..4]
        );
        assert_eq!(socket_addr.port, 8080);

        let mut bytes = vec![0 as u8; 6];
        socket_addr.emmit(&mut bytes);
        assert_eq!(socket_addr.addr.as_bytes(), &bytes[0..4]);
        assert_eq!(port_from_bytes(bytes[4], bytes[5]), 8080);

        assert_eq!(SocketAddr::try_from(bytes.as_slice()), Ok(SocketAddr::V4(socket_addr)));
    }

    #[cfg(feature = "proto-ipv6")]
    #[test]
    fn ipv6_socket_addr() {
        if env::var("RUST_LOG").is_err() {
            env::set_var("RUST_LOG", "debug");
        }
        let _ = pretty_env_logger::try_init_timed();

        let ip_address_bytes: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        info!("ip6 ip_address_bytes: {:x?}", ip_address_bytes);

        let ip_address: Ipv6Address = ipv6_addr(0, 0, 0, 0, 0, 0, 0, 1);
        info!("ip6 ip_address: {}", ip_address);
        info!("ip6 ip_address debug: {:?}", ip_address);
        assert_eq!(ip_address.as_bytes(), &ip_address_bytes);

        let socket_addr = SocketAddrV6::new_ip6_port(0, 0, 0, 0, 0, 0, 0, 1, 8080);
        info!("ip6 socket_addr: {}", socket_addr);
        info!("ip6 socket_addr debug: {:?}", socket_addr);
        assert_eq!(socket_addr.len(), LEN_V6);
        assert_eq!(socket_addr.addr.as_bytes(), &ip_address_bytes);
        assert_eq!(
            socket_addr.addr.as_bytes(),
            &socket_addr.to_vec().as_slice()[0..16]
        );
        assert_eq!(socket_addr.port, 8080);

        let mut bytes = vec![0 as u8; 18];
        socket_addr.emmit(&mut bytes);
        assert_eq!(socket_addr.addr.as_bytes(), &bytes[0..16]);
        assert_eq!(port_from_bytes(bytes[16], bytes[17]), 8080);

        assert_eq!(SocketAddr::try_from(bytes.as_slice()), Ok(SocketAddr::V6(socket_addr)));
    }

    #[cfg(all(feature = "std", feature = "proto-ipv4", feature = "proto-ipv6"))]
    #[test]
    fn ipv4_to_std() {
        if env::var("RUST_LOG").is_err() {
            env::set_var("RUST_LOG", "debug");
        }
        let _ = pretty_env_logger::try_init_timed();

        let ip_address_bytes = [127, 0, 0, 1];
        let ip_address: Ipv4Address = ipv4_addr(127, 0, 0, 1);
        let std_ip_address: Ipv4Addr = ip_address.into_std();
        assert_eq!(std_ip_address.octets().as_ref(), ip_address_bytes);
        let std_ip_address: Result<IpAddr> = IpAddress::Ipv4(ip_address).into_std();
        assert_eq!(std_ip_address, Ok(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));

        let socket_addr_v4 = SocketAddrV4::new(ip_address, 80);
        assert_eq!(socket_addr_v4.len(), LEN_V4);
        let socket_addr = SocketAddr::V4(socket_addr_v4);
        assert_eq!(
            Ok(socket_addr),
            SocketAddr::new(IpAddress::Ipv4(ip_address), 80)
        );
        assert_eq!(
            Err(Error::UnspecifiedIp),
            SocketAddr::new(IpAddress::Unspecified, 80)
        );
        assert_eq!(socket_addr, SocketAddr::new_v4(ip_address, 80));
        assert_eq!(socket_addr, SocketAddr::new_ip4_port(127, 0, 0, 1, 80));
        assert_eq!(socket_addr.len(), LEN_V4);
        assert_eq!(socket_addr.ip().as_bytes(), ip_address_bytes);
        assert_eq!(socket_addr.ip_octets(), ip_address_bytes);
        let socket_addr_vec = socket_addr.to_vec();
        assert_eq!(socket_addr_vec[0..4], ip_address_bytes);
        assert_eq!(port_from_bytes(socket_addr_vec[4], socket_addr_vec[5]), 80);
        info!("ip4 socket_addr: {}", socket_addr);
        info!("ip4 socket_addr debug: {:?}", socket_addr);

        let std_socket_addr: StdSocketAddr = socket_addr.into();
        assert!(std_socket_addr.ip().is_loopback());
        assert_eq!(std_socket_addr.ip().to_string(), "127.0.0.1".to_string());
        assert_eq!(std_socket_addr.port(), socket_addr_v4.port);
        assert_eq!(std_socket_addr.port(), socket_addr.port());
    }

    #[cfg(all(feature = "std", feature = "proto-ipv4", feature = "proto-ipv6"))]
    #[test]
    fn ipv6_to_std() {
        if env::var("RUST_LOG").is_err() {
            env::set_var("RUST_LOG", "debug");
        }
        let _ = pretty_env_logger::try_init_timed();

        let ip_address_bytes: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let ip_address: Ipv6Address = ipv6_addr(0, 0, 0, 0, 0, 0, 0, 1);
        let std_ip_address: Ipv6Addr = ip_address.into_std();
        assert_eq!(std_ip_address.octets().as_ref(), ip_address_bytes);
        let std_ip_address: Result<IpAddr> = IpAddress::Ipv6(ip_address).into_std();
        assert_eq!(
            std_ip_address,
            Ok(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
        );

        let socket_addr_v6 = SocketAddrV6::new(ip_address, 80);
        assert_eq!(socket_addr_v6.len(), LEN_V6);
        let socket_addr = SocketAddr::V6(socket_addr_v6);
        assert_eq!(
            Ok(socket_addr),
            SocketAddr::new(IpAddress::Ipv6(ip_address), 80)
        );
        assert_eq!(
            Err(Error::UnspecifiedIp),
            SocketAddr::new(IpAddress::Unspecified, 80)
        );
        assert_eq!(socket_addr, SocketAddr::new_v6(ip_address, 80));
        assert_eq!(
            socket_addr,
            SocketAddr::new_ip6_port(0, 0, 0, 0, 0, 0, 0, 1, 80)
        );
        assert_eq!(socket_addr.len(), LEN_V6);
        assert_eq!(socket_addr.ip().as_bytes(), ip_address_bytes);
        assert_eq!(socket_addr.ip_octets(), ip_address_bytes);
        let socket_addr_vec = socket_addr.to_vec();
        assert_eq!(socket_addr_vec[0..16], ip_address_bytes);
        assert_eq!(
            port_from_bytes(socket_addr_vec[16], socket_addr_vec[17]),
            80
        );
        info!("ip6 socket_addr: {}", socket_addr);
        info!("ip6 socket_addr debug: {:?}", socket_addr);

        let std_socket_addr: StdSocketAddr = socket_addr.into();
        assert!(std_socket_addr.ip().is_loopback());
        assert_eq!(std_socket_addr.ip().to_string(), "::1".to_string());
        assert_eq!(std_socket_addr.port(), socket_addr_v6.port);
        assert_eq!(std_socket_addr.port(), socket_addr.port());
    }
}
