use libc;

use std::ffi::CString;
use std::fmt::Display;

const TUN: &str = "/dev/net/tun";
const TUNSETIFF: u64 = 0x400454ca;

#[repr(C)]
struct Ifreq {
    ifrn_name: [libc::c_char; libc::IFNAMSIZ],
    ifru_flags: libc::c_int,
}

pub fn new() -> Result<i32, Box<dyn std::error::Error>> {
    let s = CString::new(TUN)?;
    let fd = unsafe { libc::open(s.as_ptr(), libc::O_RDWR) };

    if fd < 0 {
        return Err(Box::new(Error(format!("failed open {}", TUN))));
    }

    let mut ifr = Ifreq {
        ifrn_name: [0; libc::IFNAMSIZ],
        ifru_flags: 0,
    };
    ifr.ifru_flags = libc::IFF_TUN | libc::IFF_NO_PI;

    if unsafe { libc::ioctl(fd, TUNSETIFF.try_into()?, &mut ifr) } < 0 {
        return Err(Box::new(Error(format!("failed create device"))));
    }
    Ok(fd)
}

#[derive(Debug)]
pub struct Error(String);

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {}
