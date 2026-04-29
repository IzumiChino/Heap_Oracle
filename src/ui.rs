#![cfg(feature = "ui")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use eframe::egui;
use eframe::egui::{Color32, RichText};

use crate::state::{BinType, ChunkRecord, ChunkState, HeapOracle};
use crate::RuntimeStats;

pub fn run_ui(
	title: &str,
	oracle: Arc<RwLock<HeapOracle>>,
	stats: Arc<RuntimeStats>,
	stop: Arc<AtomicBool>,
) -> Result<(), String> {
	let app_title = title.to_owned();
	let native_options = eframe::NativeOptions {
		viewport: egui::ViewportBuilder::default()
			.with_inner_size([1360.0, 820.0])
			.with_min_inner_size([960.0, 640.0]),
		..Default::default()
	};

	eframe::run_native(
		title,
		native_options,
		Box::new(move |_cc| {
			Ok(Box::new(OracleApp {
				title: app_title.clone(),
				oracle: oracle.clone(),
				stats: stats.clone(),
				stop: stop.clone(),
			}))
		}),
	)
	.map_err(|err| err.to_string())
}

struct OracleApp {
	title: String,
	oracle: Arc<RwLock<HeapOracle>>,
	stats: Arc<RuntimeStats>,
	stop: Arc<AtomicBool>,
}

impl Drop for OracleApp {
	fn drop(&mut self) {
		self.stop.store(true, Ordering::Release);
	}
}

impl eframe::App for OracleApp {
	fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
		ctx.request_repaint_after(Duration::from_millis(16));
		let runtime = self.stats.snapshot();

		egui::TopBottomPanel::top("overview").show(ctx, |ui| {
			ui.horizontal_wrapped(|ui| {
				ui.heading(&self.title);
				ui.separator();
				ui.monospace(format!("events {}", runtime.consumed));
				ui.separator();
				ui.monospace(format!("pending {}", runtime.pending));
				ui.separator();
				ui.monospace(format!("dropped {}", runtime.dropped));
				if runtime.target_exited {
					ui.separator();
					ui.colored_label(
						Color32::LIGHT_RED,
						format!("target exited ({})", runtime.target_status),
					);
				}
			});
		});

		egui::SidePanel::right("bins")
			.min_width(340.0)
			.show(ctx, |ui| {
				ui.heading("Bins");
				ui.separator();
				if let Ok(oracle) = self.oracle.try_read() {
					render_bins(ui, &oracle);
					ui.separator();
					render_alerts(ui, &oracle);
				} else {
					ui.label("state writer is busy");
				}
			});

		egui::CentralPanel::default().show(ctx, |ui| {
			if let Ok(oracle) = self.oracle.try_read() {
				let summary = oracle.summary();

				ui.horizontal_wrapped(|ui| {
					ui.monospace(format!("chunks {}", summary.total_chunks));
					ui.separator();
					ui.colored_label(Color32::LIGHT_GREEN, format!("allocated {}", summary.allocated));
					ui.separator();
					ui.colored_label(Color32::GRAY, format!("freed {}", summary.freed));
					ui.separator();
					ui.colored_label(Color32::LIGHT_RED, format!("uaf {}", summary.uaf));
					ui.separator();
					ui.monospace(format!("alerts {}", summary.alerts));
				});

				ui.separator();
				ui.heading("Heap Layout");

				// Collect into a Vec so we can index by row range.
				// This is a &-borrow of oracle (already read-locked above),
				// so no extra cloning is needed.
				let chunks: Vec<&ChunkRecord> = oracle.chunks.values().collect();
				let total = chunks.len();

				// Approximate the height of one "chunk row" (horizontal
				// label + separator) so egui can skip off-screen rows.
				let text_h = ui.text_style_height(&egui::TextStyle::Monospace);
				let row_h = text_h + ui.spacing().item_spacing.y + 1.0;

				egui::ScrollArea::vertical().show_rows(
					ui,
					row_h,
					total,
					|ui, range| {
						for chunk in &chunks[range] {
							render_chunk(ui, chunk);
							ui.separator();
						}
					},
				);
			} else {
				ui.label("heap state is updating");
			}
		});
	}
}

fn render_bins(ui: &mut egui::Ui, oracle: &HeapOracle) {
	for (idx, bin) in oracle.tcache.iter().enumerate() {
		if bin.is_empty() {
			continue;
		}

		ui.monospace(format!("tcache[{idx:02}]: {}", format_chain(bin)));
	}

	for (idx, bin) in oracle.fastbins.iter().enumerate() {
		if bin.is_empty() {
			continue;
		}

		ui.monospace(format!("fastbin[{idx:02}]: {}", format_chain(bin)));
	}
}

fn render_alerts(ui: &mut egui::Ui, oracle: &HeapOracle) {
	ui.heading("Alerts");
	if oracle.alerts.is_empty() {
		ui.label("No anomalies yet");
		return;
	}

	for alert in oracle.alerts.iter().rev().take(16) {
		ui.colored_label(
			Color32::LIGHT_RED,
			format!("{:#014x}  {}  @ {} ns", alert.addr, alert.reason, alert.timestamp_ns),
		);
	}
}

fn render_chunk(ui: &mut egui::Ui, chunk: &ChunkRecord) {
	let (color, label, suffix) = match chunk.state {
		ChunkState::Allocated => (Color32::LIGHT_GREEN, "ALLOC", String::new()),
		ChunkState::Freed { bin } => (Color32::GRAY, "FREE ", format!(" -> {}", bin_label(bin))),
		ChunkState::Uaf { reason } => (Color32::LIGHT_RED, "UAF  ", format!(" ({reason})")),
	};
	let top_frame = chunk
		.alloc_stack
		.first_frame()
		.map(|frame| format!(" @ {frame:#x}"))
		.unwrap_or_default();

	ui.horizontal(|ui| {
		ui.colored_label(color, RichText::new(block_for_state(chunk.state)).strong());
		ui.monospace(format!(
			"#{:<4} {:#014x} [{:#06x}] {}{}{}",
			chunk.index, chunk.addr, chunk.size, label, suffix, top_frame
		));
	});
}

fn format_chain(bin: &[u64]) -> String {
	let mut line = String::new();

	for (idx, addr) in bin.iter().enumerate().take(10) {
		if idx > 0 {
			line.push_str(" -> ");
		}
		line.push_str(&format!("{addr:#x}"));
	}
	if bin.len() > 10 {
		line.push_str(" -> ...");
	}

	line
}

fn block_for_state(state: ChunkState) -> &'static str {
	match state {
		ChunkState::Allocated => "██",
		ChunkState::Freed { .. } => "░░",
		ChunkState::Uaf { .. } => "!!",
	}
}

fn bin_label(bin: BinType) -> String {
	bin.to_string()
}