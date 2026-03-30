//! Network syscalls for the Linux compatibility layer.
//!
//! Socket operations are proxied through the ATOS mailbox system to netd.
//! Pipes use a mailbox pair. Eventfd uses keyspace-backed counters.
//! io_uring returns -ENOSYS (runtimes fall back to epoll).

use super::constants::*;
use super::state::{self, FdEntry, FdKind};

// ── socket ─────────────────────────────────────────────────────────────────

/// socket(int domain, int type, int protocol)
///
/// Allocates an fd with FdKind::Socket. The mailbox_id is set to the agent's
/// own mailbox for now; actual netd proxy routing happens on connect().
pub fn sys_socket(agent_id: u16, _domain: i32, _sock_type: i32, _protocol: i32) -> i64 {
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -ENOSYS,
    };

    let fd = match st.alloc_fd() {
        Some(f) => f,
        None => return -EMFILE,
    };

    st.fd_table[fd] = Some(FdEntry {
        kind: FdKind::Socket,
        keyspace_key: 0,
        mailbox_id: agent_id, // will be updated on connect
        offset: 0,
        flags: 0,
        active: true,
    });

    fd as i64
}

// ── connect ────────────────────────────────────────────────────────────────

/// connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
///
/// Stores the target address metadata in the fd entry.
/// In a full implementation this would send a connect request to netd via mailbox.
pub fn sys_connect(agent_id: u16, sockfd: i32, _addr_ptr: u64, _addrlen: u64) -> i64 {
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -ENOSYS,
    };

    match st.get_fd(sockfd) {
        Some(entry) if entry.kind == FdKind::Socket => {}
        Some(_) => return -ENOTSOCK,
        None => return -EBADF,
    }

    // TODO: parse sockaddr, send connect request to netd via mailbox.
    // For now, return success (connection is "established" logically).
    0
}

// ── accept ─────────────────────────────────────────────────────────────────

/// accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
pub fn sys_accept(agent_id: u16, sockfd: i32, _addr_ptr: u64, _addrlen_ptr: u64) -> i64 {
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -ENOSYS,
    };

    match st.get_fd(sockfd) {
        Some(entry) if entry.kind == FdKind::Socket => {}
        Some(_) => return -ENOTSOCK,
        None => return -EBADF,
    }

    // Allocate a new fd for the accepted connection
    let new_fd = match st.alloc_fd() {
        Some(f) => f,
        None => return -EMFILE,
    };

    st.fd_table[new_fd] = Some(FdEntry {
        kind: FdKind::Socket,
        keyspace_key: 0,
        mailbox_id: agent_id,
        offset: 0,
        flags: 0,
        active: true,
    });

    new_fd as i64
}

// ── sendto ─────────────────────────────────────────────────────────────────

/// sendto(int sockfd, const void *buf, size_t len, int flags,
///        const struct sockaddr *dest_addr, socklen_t addrlen)
pub fn sys_sendto(agent_id: u16, sockfd: i32, _buf_ptr: u64, len: u64,
                  _flags: u64, _dest_addr: u64) -> i64 {
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -ENOSYS,
    };

    match st.get_fd(sockfd) {
        Some(entry) if entry.kind == FdKind::Socket => {}
        Some(_) => return -ENOTSOCK,
        None => return -EBADF,
    }

    // TODO: proxy data through mailbox to netd.
    // For now, report all bytes as sent.
    len as i64
}

// ── recvfrom ───────────────────────────────────────────────────────────────

/// recvfrom(int sockfd, void *buf, size_t len, int flags,
///          struct sockaddr *src_addr, socklen_t *addrlen)
pub fn sys_recvfrom(agent_id: u16, sockfd: i32, _buf_ptr: u64, _len: u64,
                    _flags: u64, _src_addr: u64) -> i64 {
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -ENOSYS,
    };

    match st.get_fd(sockfd) {
        Some(entry) if entry.kind == FdKind::Socket => {}
        Some(_) => return -ENOTSOCK,
        None => return -EBADF,
    }

    // No data available yet (non-blocking semantics)
    -EAGAIN
}

// ── sendmsg / recvmsg ──────────────────────────────────────────────────────

/// sendmsg(int sockfd, const struct msghdr *msg, int flags)
pub fn sys_sendmsg(agent_id: u16, sockfd: i32, _msg_ptr: u64, _flags: u64) -> i64 {
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -ENOSYS,
    };

    match st.get_fd(sockfd) {
        Some(entry) if entry.kind == FdKind::Socket => {}
        Some(_) => return -ENOTSOCK,
        None => return -EBADF,
    }

    // TODO: proxy through netd mailbox
    0
}

/// recvmsg(int sockfd, struct msghdr *msg, int flags)
pub fn sys_recvmsg(agent_id: u16, sockfd: i32, _msg_ptr: u64, _flags: u64) -> i64 {
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -ENOSYS,
    };

    match st.get_fd(sockfd) {
        Some(entry) if entry.kind == FdKind::Socket => {}
        Some(_) => return -ENOTSOCK,
        None => return -EBADF,
    }

    -EAGAIN
}

// ── shutdown ───────────────────────────────────────────────────────────────

/// shutdown(int sockfd, int how)
pub fn sys_shutdown(agent_id: u16, sockfd: i32, _how: i32) -> i64 {
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -ENOSYS,
    };

    match st.get_fd(sockfd) {
        Some(entry) if entry.kind == FdKind::Socket => {}
        Some(_) => return -ENOTSOCK,
        None => return -EBADF,
    }

    0
}

// ── bind ───────────────────────────────────────────────────────────────────

/// bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
pub fn sys_bind(agent_id: u16, sockfd: i32, _addr_ptr: u64, _addrlen: u64) -> i64 {
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -ENOSYS,
    };

    match st.get_fd(sockfd) {
        Some(entry) if entry.kind == FdKind::Socket => {}
        Some(_) => return -ENOTSOCK,
        None => return -EBADF,
    }

    0
}

// ── listen ─────────────────────────────────────────────────────────────────

/// listen(int sockfd, int backlog)
pub fn sys_listen(agent_id: u16, sockfd: i32, _backlog: i32) -> i64 {
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -ENOSYS,
    };

    match st.get_fd(sockfd) {
        Some(entry) if entry.kind == FdKind::Socket => {}
        Some(_) => return -ENOTSOCK,
        None => return -EBADF,
    }

    0
}

// ── getsockname ────────────────────────────────────────────────────────────

/// getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
///
/// Returns a zeroed sockaddr_in (AF_INET, port 0, addr 0.0.0.0).
pub fn sys_getsockname(agent_id: u16, sockfd: i32, addr_ptr: u64, addrlen_ptr: u64) -> i64 {
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -ENOSYS,
    };

    match st.get_fd(sockfd) {
        Some(entry) if entry.kind == FdKind::Socket => {}
        Some(_) => return -ENOTSOCK,
        None => return -EBADF,
    }

    if addr_ptr == 0 || addrlen_ptr == 0 {
        return -EFAULT;
    }

    // Write a minimal sockaddr_in: AF_INET (2), port 0, addr 0.0.0.0
    // struct sockaddr_in is 16 bytes
    unsafe {
        let p = addr_ptr as *mut u8;
        core::ptr::write_bytes(p, 0, 16);
        // sa_family = AF_INET = 2 (u16 at offset 0)
        let af_inet: u16 = 2;
        core::ptr::copy_nonoverlapping(
            &af_inet as *const u16 as *const u8, p, 2,
        );
        // Write addrlen = 16
        let addrlen: u32 = 16;
        core::ptr::copy_nonoverlapping(
            &addrlen as *const u32 as *const u8,
            addrlen_ptr as *mut u8,
            4,
        );
    }

    0
}

// ── getpeername ─────────────────────────────────────────────────────────────

/// getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
pub fn sys_getpeername(agent_id: u16, sockfd: i32, addr_ptr: u64, addrlen_ptr: u64) -> i64 {
    // Same implementation as getsockname for now
    sys_getsockname(agent_id, sockfd, addr_ptr, addrlen_ptr)
}

// ── socketpair ─────────────────────────────────────────────────────────────

/// socketpair(int domain, int type, int protocol, int sv[2])
pub fn sys_socketpair(agent_id: u16, _domain: u64, _sock_type: u64, _protocol: u64, sv_ptr: u64) -> i64 {
    if sv_ptr == 0 {
        return -EFAULT;
    }

    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -ENOSYS,
    };

    let fd0 = match st.alloc_fd() {
        Some(f) => f,
        None => return -EMFILE,
    };
    st.fd_table[fd0] = Some(FdEntry {
        kind: FdKind::Socket,
        keyspace_key: 0,
        mailbox_id: agent_id,
        offset: 0,
        flags: 0,
        active: true,
    });

    let fd1 = match st.alloc_fd() {
        Some(f) => f,
        None => {
            st.fd_table[fd0] = None;
            return -EMFILE;
        }
    };
    st.fd_table[fd1] = Some(FdEntry {
        kind: FdKind::Socket,
        keyspace_key: 0,
        mailbox_id: agent_id,
        offset: 0,
        flags: 0,
        active: true,
    });

    unsafe {
        let p = sv_ptr as *mut i32;
        core::ptr::write(p, fd0 as i32);
        core::ptr::write(p.add(1), fd1 as i32);
    }

    0
}

// ── setsockopt / getsockopt ────────────────────────────────────────────────

/// setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
pub fn sys_setsockopt(agent_id: u16, sockfd: i32, _level: u64, _optname: u64,
                      _optval_ptr: u64, _optlen: u64) -> i64 {
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -ENOSYS,
    };

    match st.get_fd(sockfd) {
        Some(entry) if entry.kind == FdKind::Socket => {}
        Some(_) => return -ENOTSOCK,
        None => return -EBADF,
    }

    // Accept all socket options silently
    0
}

/// getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
///
/// Returns zeroed/default values.
pub fn sys_getsockopt(agent_id: u16, sockfd: i32, _level: u64, _optname: u64,
                      optval_ptr: u64, optlen_ptr: u64) -> i64 {
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -ENOSYS,
    };

    match st.get_fd(sockfd) {
        Some(entry) if entry.kind == FdKind::Socket => {}
        Some(_) => return -ENOTSOCK,
        None => return -EBADF,
    }

    if optval_ptr != 0 && optlen_ptr != 0 {
        // Read the optlen, write zeroed data
        unsafe {
            let len_ptr = optlen_ptr as *mut u32;
            let len = core::ptr::read(len_ptr) as usize;
            if len > 0 && len <= 128 {
                core::ptr::write_bytes(optval_ptr as *mut u8, 0, len);
            }
        }
    }

    0
}

// ── pipe2 ──────────────────────────────────────────────────────────────────

/// pipe2(int pipefd[2], int flags)
///
/// Creates two fds backed by a mailbox pair: writing to pipefd[1] sends to
/// the mailbox, reading from pipefd[0] receives from it.
pub fn sys_pipe2(agent_id: u16, pipefd_ptr: u64, flags: i32) -> i64 {
    if pipefd_ptr == 0 {
        return -EFAULT;
    }

    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -ENOSYS,
    };

    // Allocate read end
    let read_fd = match st.alloc_fd() {
        Some(f) => f,
        None => return -EMFILE,
    };
    st.fd_table[read_fd] = Some(FdEntry {
        kind: FdKind::Pipe,
        keyspace_key: 0,
        mailbox_id: agent_id,
        offset: 0,
        flags: flags as u32,
        active: true,
    });

    // Allocate write end
    let write_fd = match st.alloc_fd() {
        Some(f) => f,
        None => {
            st.fd_table[read_fd] = None;
            return -EMFILE;
        }
    };
    st.fd_table[write_fd] = Some(FdEntry {
        kind: FdKind::Pipe,
        keyspace_key: 0,
        mailbox_id: agent_id,
        offset: 0,
        flags: flags as u32,
        active: true,
    });

    unsafe {
        let p = pipefd_ptr as *mut i32;
        core::ptr::write(p, read_fd as i32);
        core::ptr::write(p.add(1), write_fd as i32);
    }

    0
}

// ── eventfd2 ───────────────────────────────────────────────────────────────

/// eventfd2(unsigned int initval, int flags)
///
/// Creates an fd backed by a u64 counter. The initial value is stored
/// in the keyspace_key field of the fd entry.
pub fn sys_eventfd2(agent_id: u16, initval: u32, flags: i32) -> i64 {
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -ENOSYS,
    };

    let fd = match st.alloc_fd() {
        Some(f) => f,
        None => return -EMFILE,
    };

    st.fd_table[fd] = Some(FdEntry {
        kind: FdKind::EventFd,
        keyspace_key: initval as u64, // counter value stored here
        mailbox_id: 0,
        offset: 0,
        flags: flags as u32,
        active: true,
    });

    fd as i64
}

// ── io_uring stubs ─────────────────────────────────────────────────────────

/// io_uring_setup(u32 entries, struct io_uring_params *p) -> -ENOSYS
///
/// Not supported. Node.js and other runtimes fall back to epoll.
#[allow(dead_code)]
pub fn sys_io_uring_setup(_agent_id: u16, _entries: u32, _params_ptr: u64) -> i64 {
    -ENOSYS
}

/// io_uring_enter(unsigned int fd, u32 to_submit, u32 min_complete,
///                u32 flags, sigset_t *sig) -> -ENOSYS
#[allow(dead_code)]
pub fn sys_io_uring_enter(_agent_id: u16, _fd: u32, _to_submit: u32,
                          _min_complete: u32, _flags: u32, _sig: u64) -> i64 {
    -ENOSYS
}
