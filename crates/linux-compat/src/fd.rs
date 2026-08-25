//! File descriptors and open file descriptions.
//!
//! Linux semantics: `dup` clones the descriptor but shares the open file
//! description (offset and status flags), so descriptions live behind
//! `Rc<RefCell<..>>`.

use std::{cell::RefCell, rc::Rc};

use crate::{abi, vfs::Dev};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdStream {
    In,
    Out,
    Err,
}

#[derive(Debug)]
pub enum Backing {
    /// Host-visible standard stream. Stdin reads EOF; out/err append to the
    /// machine's output buffer.
    Std(StdStream),
    /// Regular VFS file.
    File { node: usize },
    /// Directory opened for reading entries; `cookie` is the getdents64
    /// position.
    Dir { node: usize, cookie: u64 },
    /// Character device.
    Dev(Dev),
}

#[derive(Debug)]
pub struct Description {
    pub backing: Backing,
    pub offset: u64,
    /// Status flags from open(2): access mode, O_APPEND, O_NONBLOCK.
    pub flags: u64,
}

impl Description {
    pub fn readable(&self) -> bool {
        self.flags & abi::O_ACCMODE != abi::O_WRONLY
    }

    pub fn writable(&self) -> bool {
        self.flags & abi::O_ACCMODE != abi::O_RDONLY
    }
}

pub type Ofd = Rc<RefCell<Description>>;

#[derive(Clone)]
pub struct FdEntry {
    pub desc: Ofd,
    pub cloexec: bool,
}

pub struct FdTable {
    entries: Vec<Option<FdEntry>>,
}

const FD_LIMIT: usize = 1024;

impl FdTable {
    pub fn new() -> Self {
        let std = |stream| {
            Some(FdEntry {
                desc: Rc::new(RefCell::new(Description {
                    backing: Backing::Std(stream),
                    offset: 0,
                    flags: match stream {
                        StdStream::In => abi::O_RDONLY,
                        _ => abi::O_WRONLY,
                    },
                })),
                cloexec: false,
            })
        };
        Self {
            entries: vec![std(StdStream::In), std(StdStream::Out), std(StdStream::Err)],
        }
    }

    pub fn get(&self, fd: u64) -> Result<&FdEntry, u64> {
        self.entries
            .get(fd as usize)
            .and_then(|e| e.as_ref())
            .ok_or(abi::EBADF)
    }

    pub fn get_mut(&mut self, fd: u64) -> Result<&mut FdEntry, u64> {
        self.entries
            .get_mut(fd as usize)
            .and_then(|e| e.as_mut())
            .ok_or(abi::EBADF)
    }

    /// Installs `entry` at the lowest free slot at or above `min`.
    pub fn insert_from(&mut self, min: usize, entry: FdEntry) -> Result<u64, u64> {
        if min >= FD_LIMIT {
            return Err(abi::EINVAL);
        }
        while self.entries.len() < min {
            self.entries.push(None);
        }
        for (fd, slot) in self.entries.iter_mut().enumerate().skip(min) {
            if slot.is_none() {
                *slot = Some(entry);
                return Ok(fd as u64);
            }
        }
        if self.entries.len() >= FD_LIMIT {
            return Err(abi::EMFILE);
        }
        self.entries.push(Some(entry));
        Ok((self.entries.len() - 1) as u64)
    }

    pub fn insert(&mut self, entry: FdEntry) -> Result<u64, u64> {
        self.insert_from(0, entry)
    }

    /// Installs `entry` exactly at `fd`, closing anything already there.
    pub fn insert_at(&mut self, fd: u64, entry: FdEntry) -> Result<u64, u64> {
        let fd = fd as usize;
        if fd >= FD_LIMIT {
            return Err(abi::EBADF);
        }
        while self.entries.len() <= fd {
            self.entries.push(None);
        }
        self.entries[fd] = Some(entry);
        Ok(fd as u64)
    }

    pub fn close(&mut self, fd: u64) -> Result<(), u64> {
        let slot = self.entries.get_mut(fd as usize).ok_or(abi::EBADF)?;
        if slot.take().is_none() {
            return Err(abi::EBADF);
        }
        Ok(())
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}
