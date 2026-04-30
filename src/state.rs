use std::collections::{BTreeMap, HashMap};
use std::fmt;

use crate::ipc::{EventKind, HeapEvent, STACK_DEPTH};

pub const TCACHE_BINS: usize = 64;
pub const FASTBIN_BINS: usize = 10;
const TCACHE_FILL_COUNT: usize = 7;

#[derive(Clone, Copy, Debug, Default)]
pub struct StackTrace {
	pub frames: [u64; STACK_DEPTH],
	pub len: usize,
}

impl StackTrace {
	pub fn from_event(event: HeapEvent) -> Self {
		Self {
			frames: event.stack(),
			len: usize::min(event.stack_len as usize, STACK_DEPTH),
		}
	}

	pub fn first_frame(self) -> Option<u64> {
		(self.len > 0).then_some(self.frames[0])
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinType {
	Tcache(usize),
	Fastbin(usize),
	Smallbin(usize),
	Largebin,
	Reallocated,
}

impl fmt::Display for BinType {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Tcache(idx) => write!(f, "tcache[{idx}]"),
			Self::Fastbin(idx) => write!(f, "fastbin[{idx}]"),
			Self::Smallbin(idx) => write!(f, "smallbin[{idx}]"),
			Self::Largebin => f.write_str("largebin"),
			Self::Reallocated => f.write_str("reallocated"),
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UafReason {
	DoubleFree,
	InvalidFree,
	ReallocOfFreed,
}

impl fmt::Display for UafReason {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::DoubleFree => f.write_str("double-free"),
			Self::InvalidFree => f.write_str("invalid-free"),
			Self::ReallocOfFreed => f.write_str("realloc-after-free"),
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkState {
	Allocated,
	Freed { bin: BinType },
	Uaf { reason: UafReason },
}

#[derive(Clone, Debug)]
pub struct ChunkRecord {
	pub index: usize,
	pub addr: u64,
	pub size: usize,
	pub state: ChunkState,
	pub alloc_stack: StackTrace,
	pub free_stack: Option<StackTrace>,
	pub last_event_ns: u64,
	pub generation: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct OracleAlert {
	pub addr: u64,
	pub reason: UafReason,
	pub timestamp_ns: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ApplyResult {
	pub alert: Option<OracleAlert>,
	pub bin: Option<BinType>,
	pub chunk_index: Option<usize>,
	pub chunk_size: Option<usize>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OracleSummary {
	pub total_chunks: usize,
	pub allocated: usize,
	pub freed: usize,
	pub uaf: usize,
	pub alerts: usize,
}

#[derive(Clone, Copy, Debug)]
enum BinLocation {
	Tcache(usize),
	Fastbin(usize),
}

pub struct HeapOracle {
	pub chunks: BTreeMap<u64, ChunkRecord>,
	pub tcache: [Vec<u64>; TCACHE_BINS],
	pub fastbins: [Vec<u64>; FASTBIN_BINS],
	pub alerts: Vec<OracleAlert>,
	pub total_events: u64,
	pub next_index: usize,
	counts: [usize; 3],
	bin_index: HashMap<u64, BinLocation>,
}

impl Default for HeapOracle {
	fn default() -> Self {
		Self::new()
	}
}

impl HeapOracle {
	pub fn new() -> Self {
		Self {
			chunks: BTreeMap::new(),
			tcache: std::array::from_fn(|_| Vec::new()),
			fastbins: std::array::from_fn(|_| Vec::new()),
			alerts: Vec::new(),
			total_events: 0,
			next_index: 0,
			counts: [0; 3],
			bin_index: HashMap::new(),
		}
	}

	pub fn apply_event(&mut self, event: HeapEvent) -> ApplyResult {
		self.total_events = self.total_events.saturating_add(1);

		match event.kind() {
			EventKind::Alloc | EventKind::Calloc | EventKind::Memalign => {
				self.apply_alloc(event.addr, event.size as usize, StackTrace::from_event(event), event.timestamp_ns)
			}
			EventKind::Free => self.apply_free(event.addr, StackTrace::from_event(event), event.timestamp_ns),
			EventKind::Realloc => self.apply_realloc(event),
			EventKind::Invalid => ApplyResult::default(),
		}
	}

	pub fn summary(&self) -> OracleSummary {
		OracleSummary {
			total_chunks: self.chunks.len(),
			allocated: self.counts[0],
			freed: self.counts[1],
			uaf: self.counts[2],
			alerts: self.alerts.len(),
		}
	}

	fn count_state_change(&mut self, old: Option<ChunkState>, new: ChunkState) {
		if let Some(old) = old {
			self.counts[state_index(old)] -= 1;
		}
		self.counts[state_index(new)] += 1;
	}

	fn apply_alloc(
		&mut self,
		addr: u64,
		size: usize,
		stack: StackTrace,
		timestamp_ns: u64,
	) -> ApplyResult {
		if addr == 0 {
			return ApplyResult::default();
		}

		self.remove_from_bins(addr);
		let old_state = self.chunks.get(&addr).map(|r| r.state);
		let next_generation = self
			.chunks
			.get(&addr)
			.map(|record| record.generation.saturating_add(1))
			.unwrap_or(0);

		let index = self.next_index;
		self.next_index += 1;

		self.count_state_change(old_state, ChunkState::Allocated);
		self.chunks.insert(
			addr,
			ChunkRecord {
				index,
				addr,
				size,
				state: ChunkState::Allocated,
				alloc_stack: stack,
				free_stack: None,
				last_event_ns: timestamp_ns,
				generation: next_generation,
			},
		);

		ApplyResult {
			chunk_index: Some(index),
			chunk_size: Some(glibc_chunk_size(size)),
			..ApplyResult::default()
		}
	}

	fn apply_free(&mut self, addr: u64, stack: StackTrace, timestamp_ns: u64) -> ApplyResult {
		let mut result = ApplyResult::default();

		if addr == 0 {
			return result;
		}

		self.remove_from_bins(addr);
		match self.chunks.get(&addr).map(|r| (r.state, r.size, r.index)) {
			Some((ChunkState::Allocated, size, idx)) => {
				let bin = self.classify_free_bin(size);
				let new_state = ChunkState::Freed { bin };

				self.count_state_change(Some(ChunkState::Allocated), new_state);
				if let Some(record) = self.chunks.get_mut(&addr) {
					record.state = new_state;
					record.free_stack = Some(stack);
					record.last_event_ns = timestamp_ns;
				}

				self.push_bin(addr, bin);
				result.bin = Some(bin);
				result.chunk_index = Some(idx);
				result.chunk_size = Some(glibc_chunk_size(size));
			}
			Some((old @ (ChunkState::Freed { .. } | ChunkState::Uaf { .. }), size, idx)) => {
				let new_state = ChunkState::Uaf { reason: UafReason::DoubleFree };
				let alert = self.raise_alert(addr, UafReason::DoubleFree, timestamp_ns);

				self.count_state_change(Some(old), new_state);
				if let Some(record) = self.chunks.get_mut(&addr) {
					record.state = new_state;
					record.free_stack = Some(stack);
					record.last_event_ns = timestamp_ns;
				}

				result.alert = Some(alert);
				result.chunk_index = Some(idx);
				if size > 0 {
					result.chunk_size = Some(glibc_chunk_size(size));
				}
			}
			None => {
				let idx = self.next_index;
				self.next_index += 1;
				let new_state = ChunkState::Uaf { reason: UafReason::InvalidFree };
				let alert = self.raise_alert(addr, UafReason::InvalidFree, timestamp_ns);

				self.count_state_change(None, new_state);
				self.chunks.insert(
					addr,
					ChunkRecord {
						index: idx,
						addr,
						size: 0,
						state: new_state,
						alloc_stack: StackTrace::default(),
						free_stack: Some(stack),
						last_event_ns: timestamp_ns,
						generation: 0,
					},
				);
				result.alert = Some(alert);
				result.chunk_index = Some(idx);
			}
		}

		result
	}

	fn apply_realloc(&mut self, event: HeapEvent) -> ApplyResult {
		let old_addr = event.aux_addr;
		let new_addr = event.addr;
		let size = event.size as usize;
		let stack = StackTrace::from_event(event);
		let timestamp_ns = event.timestamp_ns;
		let mut result = ApplyResult::default();

		if old_addr == 0 {
			return self.apply_alloc(new_addr, size, stack, timestamp_ns);
		}
		if size == 0 {
			return self.apply_free(old_addr, stack, timestamp_ns);
		}
		if new_addr == 0 {
			return result;
		}

		self.remove_from_bins(old_addr);
		match self.chunks.get(&old_addr).map(|record| record.state) {
			Some(old @ ChunkState::Allocated) => {
				let new_state = ChunkState::Freed { bin: BinType::Reallocated };
				self.count_state_change(Some(old), new_state);
				if let Some(record) = self.chunks.get_mut(&old_addr) {
					record.state = new_state;
					record.free_stack = Some(stack);
					record.last_event_ns = timestamp_ns;
				}
			}
			Some(old @ (ChunkState::Freed { .. } | ChunkState::Uaf { .. })) => {
				let new_state = ChunkState::Uaf { reason: UafReason::ReallocOfFreed };
				let alert = self.raise_alert(old_addr, UafReason::ReallocOfFreed, timestamp_ns);
				self.count_state_change(Some(old), new_state);
				if let Some(record) = self.chunks.get_mut(&old_addr) {
					record.state = new_state;
					record.free_stack = Some(stack);
					record.last_event_ns = timestamp_ns;
				}
				result.alert = Some(alert);
			}
			None => {}
		}

		let alloc_result = self.apply_alloc(new_addr, size, stack, timestamp_ns);
		if result.alert.is_none() {
			result.alert = alloc_result.alert;
		}
		result.chunk_index = alloc_result.chunk_index;
		result.chunk_size = alloc_result.chunk_size;

		result
	}

	fn raise_alert(&mut self, addr: u64, reason: UafReason, timestamp_ns: u64) -> OracleAlert {
		let alert = OracleAlert {
			addr,
			reason,
			timestamp_ns,
		};

		self.alerts.push(alert);
		if self.alerts.len() > 128 {
			let keep_from = self.alerts.len() - 128;
			self.alerts.drain(0..keep_from);
		}

		alert
	}

	fn classify_free_bin(&self, size: usize) -> BinType {
		let chunk_size = glibc_chunk_size(size);

		if let Some(idx) = tcache_index(chunk_size) {
			if self.tcache[idx].len() < TCACHE_FILL_COUNT {
				return BinType::Tcache(idx);
			}
		}
		if let Some(idx) = fastbin_index(chunk_size) {
			return BinType::Fastbin(idx);
		}
		if chunk_size <= 0x400 {
			return BinType::Smallbin((chunk_size.saturating_sub(0x20)) / 0x10);
		}

		BinType::Largebin
	}

	fn push_bin(&mut self, addr: u64, bin: BinType) {
		match bin {
			BinType::Tcache(idx) if idx < self.tcache.len() => {
				self.tcache[idx].push(addr);
				self.bin_index.insert(addr, BinLocation::Tcache(idx));
			}
			BinType::Fastbin(idx) if idx < self.fastbins.len() => {
				self.fastbins[idx].push(addr);
				self.bin_index.insert(addr, BinLocation::Fastbin(idx));
			}
			_ => {}
		}
	}

	fn remove_from_bins(&mut self, addr: u64) {
		let Some(loc) = self.bin_index.remove(&addr) else { return };
		let bin = match loc {
			BinLocation::Tcache(idx) => &mut self.tcache[idx],
			BinLocation::Fastbin(idx) => &mut self.fastbins[idx],
		};
		if let Some(pos) = bin.iter().position(|entry| *entry == addr) {
			bin.remove(pos);
		}
	}
}

/// Compute the glibc chunk size for a given allocation request.
///
/// glibc's `request2size` macro is:
///   (req + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK
/// where SIZE_SZ = 8 and MALLOC_ALIGN_MASK = 15 on 64-bit, giving:
///   (req + 8 + 15) & ~15  =  (req + 23) & ~15
///
/// The minimum chunk is MINSIZE = 4 * SIZE_SZ = 32 = 0x20.
pub fn glibc_chunk_size(size: usize) -> usize {
	// SIZE_SZ = 8, MALLOC_ALIGN_MASK = 15
	let aligned = (size.saturating_add(8 + 15)) & !15usize;
	aligned.max(0x20)
}

fn tcache_index(chunk_size: usize) -> Option<usize> {
	// glibc tcache covers chunk sizes 0x20..=0x410 (indices 0..=63).
	// The previous upper bound of 0x420 would yield index 64, which is
	// out-of-bounds for TCACHE_BINS=64 and causes incorrect classification.
	if !(0x20..=0x410).contains(&chunk_size) {
		return None;
	}

	Some((chunk_size - 0x20) / 0x10)
}

fn fastbin_index(chunk_size: usize) -> Option<usize> {
	if !(0x20..=0xb0).contains(&chunk_size) {
		return None;
	}

	let idx = (chunk_size - 0x20) / 0x10;
	(idx < FASTBIN_BINS).then_some(idx)
}

fn state_index(state: ChunkState) -> usize {
	match state {
		ChunkState::Allocated => 0,
		ChunkState::Freed { .. } => 1,
		ChunkState::Uaf { .. } => 2,
	}
}