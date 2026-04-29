#![cfg_attr(not(unix), allow(dead_code))]

#[cfg(not(unix))]
compile_error!("Heap Oracle currently supports the Rust monitor on Unix targets only");

use std::ffi::CString;
use std::fmt;
use std::mem::size_of;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

pub const MAGIC: u32 = 0x484f5243;
pub const VERSION: u32 = 1;
pub const STACK_DEPTH: usize = 8;
pub const RING_CAPACITY: usize = 4096;

// O_CREAT differs between Linux (0o100 = 64) and macOS (0x0200 = 512).
#[cfg(target_os = "macos")]
const O_CREAT: c_int = 0x0200;
#[cfg(not(target_os = "macos"))]
const O_CREAT: c_int = 0o100;
const O_RDWR: c_int = 0o2;
const PROT_READ: c_int = 0x1;
const PROT_WRITE: c_int = 0x2;
const MAP_SHARED: c_int = 0x01;
const S_IRUSR: u32 = 0o400;
const S_IWUSR: u32 = 0o200;

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
	Invalid = 0,
	Alloc = 1,
	Free = 2,
	Realloc = 3,
	Memalign = 4,
	Calloc = 5,
}

impl EventKind {
	pub fn from_raw(raw: u16) -> Self {
		match raw {
			1 => Self::Alloc,
			2 => Self::Free,
			3 => Self::Realloc,
			4 => Self::Memalign,
			5 => Self::Calloc,
			_ => Self::Invalid,
		}
	}

	pub fn as_str(self) -> &'static str {
		match self {
			Self::Invalid => "invalid",
			Self::Alloc => "malloc",
			Self::Free => "free",
			Self::Realloc => "realloc",
			Self::Memalign => "memalign",
			Self::Calloc => "calloc",
		}
	}
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct HeapEvent {
	pub kind: u16,
	pub flags: u16,
	pub pid: u32,
	pub tid: u32,
	pub stack_len: u32,
	pub timestamp_ns: u64,
	pub addr: u64,
	pub aux_addr: u64,
	pub size: u64,
	pub aux_size: u64,
	pub callstack: [u64; STACK_DEPTH],
}

impl HeapEvent {
	pub fn kind(self) -> EventKind {
		EventKind::from_raw(self.kind)
	}

	pub fn stack(self) -> [u64; STACK_DEPTH] {
		self.callstack
	}
}

impl fmt::Debug for HeapEvent {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("HeapEvent")
			.field("kind", &self.kind())
			.field("pid", &self.pid)
			.field("tid", &self.tid)
			.field("timestamp_ns", &self.timestamp_ns)
			.field("addr", &format_args!("{:#x}", self.addr))
			.field("aux_addr", &format_args!("{:#x}", self.aux_addr))
			.field("size", &self.size)
			.field("aux_size", &self.aux_size)
			.finish()
	}
}

#[repr(C)]
pub struct RingHeader {
	pub magic: u32,
	pub version: u32,
	pub capacity: u32,
	pub event_size: u32,
	pub head: AtomicU64,
	pub tail: AtomicU64,
	pub dropped: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RingStats {
	pub head: u64,
	pub tail: u64,
	pub dropped: u64,
}

impl RingStats {
	pub fn pending(self) -> u64 {
		self.head.saturating_sub(self.tail)
	}
}

pub struct SharedRing {
	mapping: *mut u8,
	mapping_len: usize,
	header: *mut RingHeader,
	events: *mut HeapEvent,
	name: CString,
	owner: bool,
}

unsafe impl Send for SharedRing {}

impl SharedRing {
	pub fn create(name: &str) -> Result<Self, String> {
		Self::map(name, true)
	}

	pub fn name(&self) -> &str {
		self.name.to_str().unwrap_or("/heap-oracle-invalid")
	}

	pub fn read_batch(&mut self, limit: usize, out: &mut Vec<HeapEvent>) -> usize {
		let header = unsafe { &*self.header };
		let head = header.head.load(Ordering::Acquire);
		let mut tail = header.tail.load(Ordering::Relaxed);

		out.clear();
		while tail != head && out.len() < limit {
			let slot = (tail % RING_CAPACITY as u64) as usize;
			let event = unsafe { ptr::read(self.events.add(slot)) };
			out.push(event);
			tail += 1;
		}

		header.tail.store(tail, Ordering::Release);
		out.len()
	}

	pub fn stats(&self) -> RingStats {
		let header = unsafe { &*self.header };

		RingStats {
			head: header.head.load(Ordering::Acquire),
			tail: header.tail.load(Ordering::Acquire),
			dropped: header.dropped.load(Ordering::Acquire),
		}
	}

	fn map(name: &str, create: bool) -> Result<Self, String> {
		let normalized = normalize_shm_name(name);
		let c_name = CString::new(normalized.clone())
			.map_err(|_| format!("shared memory name contains NUL byte: {name:?}"))?;
		let total_len = ring_len(RING_CAPACITY);

		unsafe {
			let flags = if create { O_CREAT | O_RDWR } else { O_RDWR };
			let fd = shm_open(c_name.as_ptr(), flags, S_IRUSR | S_IWUSR);
			if fd < 0 {
				return Err(last_os_error("shm_open"));
			}

			if create && ftruncate(fd, total_len as i64) < 0 {
				close(fd);
				let _ = shm_unlink(c_name.as_ptr());
				return Err(last_os_error("ftruncate"));
			}

			let mapping = mmap(
				ptr::null_mut(),
				total_len,
				PROT_READ | PROT_WRITE,
				MAP_SHARED,
				fd,
				0,
			);
			close(fd);
			if mapping == map_failed() {
				if create {
					let _ = shm_unlink(c_name.as_ptr());
				}
				return Err(last_os_error("mmap"));
			}

			let header = mapping as *mut RingHeader;
			let events = (mapping as *mut u8).add(size_of::<RingHeader>()) as *mut HeapEvent;

			if create {
				ptr::write_bytes(mapping as *mut u8, 0, total_len);
				ptr::write(
					header,
					RingHeader {
						magic: MAGIC,
						version: VERSION,
						capacity: RING_CAPACITY as u32,
						event_size: size_of::<HeapEvent>() as u32,
						head: AtomicU64::new(0),
						tail: AtomicU64::new(0),
						dropped: AtomicU64::new(0),
					},
				);
			}

			let ring = Self {
				mapping: mapping as *mut u8,
				mapping_len: total_len,
				header,
				events,
				name: c_name,
				owner: create,
			};
			ring.validate()?;
			Ok(ring)
		}
	}

	fn validate(&self) -> Result<(), String> {
		let header = unsafe { &*self.header };

		if header.magic != MAGIC {
			return Err(format!(
				"shared memory magic mismatch: expected {MAGIC:#x}, got {:#x}",
				header.magic,
			));
		}
		if header.version != VERSION {
			return Err(format!(
				"shared memory version mismatch: expected {VERSION}, got {}",
				header.version,
			));
		}
		if header.capacity as usize != RING_CAPACITY {
			return Err(format!(
				"shared memory capacity mismatch: expected {}, got {}",
				RING_CAPACITY,
				header.capacity,
			));
		}
		if header.event_size as usize != size_of::<HeapEvent>() {
			return Err(format!(
				"shared memory event size mismatch: expected {}, got {}",
				size_of::<HeapEvent>(),
				header.event_size,
			));
		}

		Ok(())
	}
}

impl Drop for SharedRing {
	fn drop(&mut self) {
		unsafe {
			let _ = munmap(self.mapping as *mut c_void, self.mapping_len);
			if self.owner {
				let _ = shm_unlink(self.name.as_ptr());
			}
		}
	}
}

fn normalize_shm_name(name: &str) -> String {
	if name.starts_with('/') {
		name.to_owned()
	} else {
		format!("/{name}")
	}
}

fn ring_len(capacity: usize) -> usize {
	size_of::<RingHeader>() + (capacity * size_of::<HeapEvent>())
}

fn last_os_error(op: &str) -> String {
	format!("{op} failed: {}", std::io::Error::last_os_error())
}

fn map_failed() -> *mut c_void {
	(-1isize) as *mut c_void
}

#[link(name = "c")]
unsafe extern "C" {
	fn close(fd: c_int) -> c_int;
	fn ftruncate(fd: c_int, len: i64) -> c_int;
	fn mmap(
		addr: *mut c_void,
		len: usize,
		prot: c_int,
		flags: c_int,
		fd: c_int,
		offset: isize,
	) -> *mut c_void;
	fn munmap(addr: *mut c_void, len: usize) -> c_int;
}

#[cfg(target_os = "linux")]
#[link(name = "rt")]
unsafe extern "C" {
	fn shm_open(name: *const c_char, oflag: c_int, mode: u32) -> c_int;
	fn shm_unlink(name: *const c_char) -> c_int;
}

#[cfg(not(target_os = "linux"))]
unsafe extern "C" {
	fn shm_open(name: *const c_char, oflag: c_int, mode: u32) -> c_int;
	fn shm_unlink(name: *const c_char) -> c_int;
}