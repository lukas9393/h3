use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut};

use super::proto::varint::{BufExt, BufMutExt, UnexpectedEnd};

#[derive(Debug, PartialEq)]
pub enum Error {
    UnsupportedCapsule(u64), // Known Capsule that should generate an error
}

pub enum Capsule {
    AddressAssign(AddressAssign),
    AddressRequest(AddressRequest),
    RouteAdvertisement(RouteAdvertisement),
}

macro_rules! capsule_types {
{$($name:ident = $val:expr,)*} => {
    impl CapsuleType {
        $(pub const $name: CapsuleType = CapsuleType($val);)*
    }
}
}

capsule_types! {
    ADDRESS_ASSIGN = 0x0,
    ADDRESS_REQUEST = 0x1,
    ROUTE_ADVERTISEMENT = 0x2,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct CapsuleType(u64);

impl CapsuleType {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self, UnexpectedEnd> {
        Ok(CapsuleType(buf.get_var()?))
    }
    pub fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.write_var(self.0);
    }
}

pub(crate) trait CapsuleHeader {
    const TYPE: CapsuleType;
    fn len(&self) -> usize;
    fn encode_header<T: BufMut>(&self, buf: &mut T) {
        Self::TYPE.encode(buf);
        buf.write_var(self.len() as u64);
    }
}

#[derive(Debug, PartialEq)]
pub struct AddressAssign {
    pub ip_address: IpAddr,
    pub ip_prefix_length: u8,
}

impl CapsuleHeader for AddressAssign {
    const TYPE: CapsuleType = CapsuleType::ADDRESS_ASSIGN;
    fn len(&self) -> usize {
        2 + match self.ip_address {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 16,
        }
    }
}

impl AddressAssign {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self, UnexpectedEnd> {
        let ip_version = buf.get_u8();
        let ip_address = match ip_version {
            4 => {
                let mut addr = [0; 4];
                buf.copy_to_slice(&mut addr);
                IpAddr::from(Ipv4Addr::from(addr))
            }
            6 => {
                let mut addr = [0; 16];
                buf.copy_to_slice(&mut addr);
                IpAddr::from(Ipv6Addr::from(addr))
            }
            _ => todo!(),
        };
        Ok(AddressAssign {
            ip_address,
            ip_prefix_length: buf.get_u8(),
        })
    }

    fn encode<B: BufMut>(&self, buf: &mut B) {
        self.encode_header(buf);

        match self.ip_address {
            IpAddr::V4(addr) => {
                buf.put_u8(4);
                buf.put_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                buf.put_u8(6);
                buf.put_slice(&addr.octets());
            }
        }
        buf.put_u8(self.ip_prefix_length);
    }
}

#[derive(Debug, PartialEq)]
pub struct AddressRequest {
    ip_address: IpAddr,
    ip_prefix_length: u8,
}

impl CapsuleHeader for AddressRequest {
    const TYPE: CapsuleType = CapsuleType::ADDRESS_ASSIGN;

    fn len(&self) -> usize {
        2 + match self.ip_address {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 16,
        }
    }
}

impl AddressRequest {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self, UnexpectedEnd> {
        let ip_version = buf.get_u8();
        let ip_address = match ip_version {
            4 => {
                let mut addr = [0; 4];
                buf.copy_to_slice(&mut addr);
                IpAddr::from(Ipv4Addr::from(addr))
            }
            6 => {
                let mut addr = [0; 16];
                buf.copy_to_slice(&mut addr);
                IpAddr::from(Ipv6Addr::from(addr))
            }
            _ => todo!(),
        };
        Ok(AddressRequest {
            ip_address,
            ip_prefix_length: buf.get_u8(),
        })
    }

    fn encode<B: BufMut>(&self, buf: &mut B) {
        self.encode_header(buf);

        match self.ip_address {
            IpAddr::V4(addr) => {
                buf.put_u8(4);
                buf.put_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                buf.put_u8(6);
                buf.put_slice(&addr.octets());
            }
        }
        buf.put_u8(self.ip_prefix_length);
    }
}

#[derive(Debug, PartialEq)]
pub struct RouteAdvertisement {
    ranges: Vec<IpAddressRange>,
}

impl CapsuleHeader for RouteAdvertisement {
    const TYPE: CapsuleType = CapsuleType::ROUTE_ADVERTISEMENT;

    fn len(&self) -> usize {
        self.ranges.iter().fold(0, |len, range| len + range.len())
    }
}

impl RouteAdvertisement {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self, UnexpectedEnd> {
        let mut ranges = Vec::new();
        while buf.has_remaining() {
            ranges.push(IpAddressRange::decode(buf)?);
        }
        Ok(RouteAdvertisement { ranges })
    }

    fn encode<B: BufMut>(&self, buf: &mut B) {
        self.encode_header(buf);

        for range in &self.ranges {
            range.encode(buf);
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct IpAddressRange {
    start_ip_address: IpAddr,
    end_ip_address: IpAddr,
    ip_protocol: u8,
}

impl IpAddressRange {
    fn decode<B: Buf>(buf: &mut B) -> Result<Self, UnexpectedEnd> {
        let ip_version = buf.get_u8();
        let (start_ip_address, end_ip_address) = match ip_version {
            4 => {
                let mut start = [0; 4];
                buf.copy_to_slice(&mut start);
                let mut end = [0; 4];
                buf.copy_to_slice(&mut end);
                (
                    IpAddr::from(Ipv4Addr::from(start)),
                    IpAddr::from(Ipv4Addr::from(end)),
                )
            }
            6 => {
                let mut start = [0; 16];
                buf.copy_to_slice(&mut start);
                let mut end = [0; 16];
                buf.copy_to_slice(&mut end);
                (
                    IpAddr::from(Ipv6Addr::from(start)),
                    IpAddr::from(Ipv6Addr::from(end)),
                )
            }
            _ => todo!(),
        };

        let ip_protocol = buf.get_u8();

        Ok(IpAddressRange {
            start_ip_address,
            end_ip_address,
            ip_protocol,
        })
    }

    fn encode<B: BufMut>(&self, buf: &mut B) {
        match (self.start_ip_address, self.end_ip_address) {
            (IpAddr::V4(start), IpAddr::V4(end)) => {
                buf.put_u8(4);
                buf.put_slice(&start.octets());
                buf.put_slice(&end.octets());
            }
            (IpAddr::V6(start), IpAddr::V6(end)) => {
                buf.put_u8(6);
                buf.put_slice(&start.octets());
                buf.put_slice(&end.octets());
            }
            _ => todo!(),
        }

        buf.put_u8(self.ip_protocol);
    }

    fn len(&self) -> usize {
        match (self.start_ip_address, self.end_ip_address) {
            (IpAddr::V4(_), IpAddr::V4(_)) => 8,
            (IpAddr::V6(_), IpAddr::V6(_)) => 32,
            _ => todo!(),
        }
    }
}

impl Capsule {
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Capsule, UnexpectedEnd> {
        let ty = CapsuleType::decode(buf)?;
        let capsule = match ty {
            CapsuleType::ADDRESS_ASSIGN => {
                let address_assign = AddressAssign::decode(buf)?;
                Capsule::AddressAssign(address_assign)
            }
            CapsuleType::ADDRESS_REQUEST => {
                let address_request = AddressRequest::decode(buf)?;
                Capsule::AddressRequest(address_request)
            }

            CapsuleType::ROUTE_ADVERTISEMENT => {
                let route_advertisement = RouteAdvertisement::decode(buf)?;
                Capsule::RouteAdvertisement(route_advertisement)
            }
            // _ => Err(Error::UnsupportedCapsule(ty.0)),
            _ => todo!(),
        };
        Ok(capsule)
    }

    pub fn encode<T: BufMut>(&self, buf: &mut T) {
        match self {
            Capsule::AddressAssign(t) => t.encode(buf),
            Capsule::AddressRequest(t) => t.encode(buf),
            Capsule::RouteAdvertisement(t) => t.encode(buf),
        };
    }
}
