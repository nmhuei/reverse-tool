use crate::error::LinuxError;
use socket2::{Domain, Protocol, Socket, Type};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

pub struct PathProber;

impl PathProber {
    pub fn check_carrier(iface: &str) -> bool {
        let path = format!("/sys/class/net/{}/carrier", iface);
        if let Ok(content) = fs::read_to_string(path) {
            content.trim() == "1"
        } else {
            // If carrier doesn't exist (e.g. virtual interfaces), check operstate
            let oper_path = format!("/sys/class/net/{}/operstate", iface);
            if let Ok(oper) = fs::read_to_string(oper_path) {
                let s = oper.trim();
                s == "up" || s == "unknown"
            } else {
                false
            }
        }
    }

    /// Probe reachability of an IP bound exclusively to `iface` using SO_BINDTODEVICE
    pub fn probe_tcp(
        iface: &str,
        target_ip: IpAddr,
        port: u16,
        timeout: Duration,
    ) -> Result<bool, LinuxError> {
        let domain = match target_ip {
            IpAddr::V4(_) => Domain::IPV4,
            IpAddr::V6(_) => Domain::IPV6,
        };

        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

        // Bind socket strictly to the target network interface using SO_BINDTODEVICE
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            if let Ok(c_iface) = std::ffi::CString::new(iface) {
                let ret = unsafe {
                    libc::setsockopt(
                        socket.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_BINDTODEVICE,
                        c_iface.as_ptr() as *const libc::c_void,
                        c_iface.as_bytes_with_nul().len() as libc::socklen_t,
                    )
                };
                if ret != 0 {
                    tracing::debug!("SO_BINDTODEVICE on {} failed", iface);
                }
            }
        }

        socket.set_nonblocking(true)?;

        let target_addr: SocketAddr = (target_ip, port).into();
        let sock_addr = target_addr.into();

        match socket.connect(&sock_addr) {
            Ok(()) => Ok(true),
            Err(err) => {
                // In progress is expected for non-blocking connect
                if err.raw_os_error() == Some(libc::EINPROGRESS) {
                    // Poll with timeout
                    let mut pfd = libc::pollfd {
                        fd: std::os::fd::AsRawFd::as_raw_fd(&socket),
                        events: libc::POLLOUT,
                        revents: 0,
                    };

                    let res = unsafe { libc::poll(&mut pfd, 1, timeout.as_millis() as i32) };
                    if res > 0 && (pfd.revents & libc::POLLOUT) != 0 {
                        // Check socket error
                        let mut error: libc::c_int = 0;
                        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
                        unsafe {
                            libc::getsockopt(
                                std::os::fd::AsRawFd::as_raw_fd(&socket),
                                libc::SOL_SOCKET,
                                libc::SO_ERROR,
                                &mut error as *mut _ as *mut libc::c_void,
                                &mut len,
                            );
                        }
                        Ok(error == 0)
                    } else {
                        Ok(false)
                    }
                } else {
                    Ok(false)
                }
            }
        }
    }

    /// Overall health check for an interface: carrier check + optional probe
    pub fn probe_interface(
        iface: &str,
        target_probe: Option<(IpAddr, u16)>,
    ) -> Result<bool, LinuxError> {
        if !Self::check_carrier(iface) {
            return Ok(false);
        }

        if let Some((ip, port)) = target_probe {
            Self::probe_tcp(iface, ip, port, Duration::from_millis(500))
        } else {
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_loopback_carrier() {
        assert!(PathProber::check_carrier("lo"));
    }
}
