mod ipc;
mod state;
#[cfg(feature = "ui")]
mod ui;

use std::env;
use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipc::{EventKind, HeapEvent, SharedRing};
use state::{ApplyResult, HeapOracle};

const READER_BATCH_SIZE: usize = 128;
const READER_IDLE_MS: u64 = 8;

#[derive(Default)]
pub struct RuntimeStats {
    consumed: AtomicU64,
    pending: AtomicU64,
    dropped: AtomicU64,
    target_exited: AtomicBool,
    target_status: AtomicI32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RuntimeSnapshot {
    pub consumed: u64,
    pub pending: u64,
    pub dropped: u64,
    pub target_exited: bool,
    pub target_status: i32,
}

impl RuntimeStats {
    fn snapshot(&self) -> RuntimeSnapshot {
        RuntimeSnapshot {
            consumed: self.consumed.load(Ordering::Acquire),
            pending: self.pending.load(Ordering::Acquire),
            dropped: self.dropped.load(Ordering::Acquire),
            target_exited: self.target_exited.load(Ordering::Acquire),
            target_status: self.target_status.load(Ordering::Acquire),
        }
    }

    fn update_ring(&self, pending: u64, dropped: u64) {
        self.pending.store(pending, Ordering::Release);
        self.dropped.store(dropped, Ordering::Release);
    }

    fn mark_target_exit(&self, status: i32) {
        self.target_status.store(status, Ordering::Release);
        self.target_exited.store(true, Ordering::Release);
    }

    fn add_consumed(&self, count: usize) {
        self.consumed.fetch_add(count as u64, Ordering::AcqRel);
    }
}

enum ParseResult {
    Run(Options),
    Help,
}

struct Options {
    mode: Mode,
    shm_name: String,
    no_ui: bool,
    main_only: bool,
    use_color: bool,
}

enum Mode {
    Run {
        command: Vec<OsString>,
        hook_library: PathBuf,
    },
    Monitor,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("heap-oracle: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let options = match parse_args()? {
        ParseResult::Run(options) => options,
        ParseResult::Help => {
            print_usage();
            return Ok(());
        }
    };

    let ring = SharedRing::create(&options.shm_name)?;
    eprintln!("heap-oracle: shm={}", ring.name());

    let oracle = Arc::new(RwLock::new(HeapOracle::new()));
    let stats = Arc::new(RuntimeStats::default());
    let stop = Arc::new(AtomicBool::new(false));
    let reader = spawn_reader_thread(
        ring,
        oracle.clone(),
        stats.clone(),
        stop.clone(),
        options.no_ui,
        options.use_color,
    );

    match options.mode {
        Mode::Run {
            command,
            hook_library,
        } => run_target_mode(command, &hook_library, &options.shm_name, options.no_ui, options.main_only, oracle, stats, stop, reader),
        Mode::Monitor => run_monitor_mode(options.no_ui, oracle, stats, stop, reader),
    }
}

fn run_target_mode(
    command: Vec<OsString>,
    hook_library: &Path,
    shm_name: &str,
    no_ui: bool,
    main_only: bool,
    oracle: Arc<RwLock<HeapOracle>>,
    stats: Arc<RuntimeStats>,
    stop: Arc<AtomicBool>,
    reader: thread::JoinHandle<()>,
) -> Result<(), String> {
    let child = spawn_target(&command, hook_library, shm_name, main_only)?;

    if no_ui {
        let status = wait_for_child(child, &stats)?;
        drain_after_exit(&stats);
        stop.store(true, Ordering::Release);
        let _ = reader.join();
        print_summary(&oracle, &stats);
        if status != 0 {
            return Err(format!("target exited with status {status}"));
        }
        return Ok(());
    }

    #[cfg(feature = "ui")]
    {
        let stats_for_waiter = stats.clone();
        thread::spawn(move || {
            let _ = wait_for_child(child, &stats_for_waiter);
        });
        let result = ui::run_ui("Heap Oracle", oracle, stats, stop.clone());
        stop.store(true, Ordering::Release);
        let _ = reader.join();
        return result;
    }

    #[cfg(not(feature = "ui"))]
    {
        let _ = child;
        let _ = oracle;
        let _ = stats;
        let _ = stop;
        let _ = reader;
        Err(String::from(
            "ui support is disabled; rebuild without --no-default-features or pass --no-ui",
        ))
    }
}

fn run_monitor_mode(
    no_ui: bool,
    oracle: Arc<RwLock<HeapOracle>>,
    stats: Arc<RuntimeStats>,
    stop: Arc<AtomicBool>,
    reader: thread::JoinHandle<()>,
) -> Result<(), String> {
    if no_ui {
        eprintln!("heap-oracle: monitoring without UI, press Ctrl-C to stop");
        // Loop until the stop flag is raised (e.g., by a future signal
        // handler) so that the reader thread can be joined cleanly.
        // Without a ctrlc handler wired up, Ctrl-C will SIGKILL the
        // process and the OS cleans up; but if stop is ever set via
        // another code path the shutdown here will be orderly.
        while !stop.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(500));
        }
        let _ = reader.join();
        print_summary(&oracle, &stats);
        return Ok(());
    }

    #[cfg(feature = "ui")]
    {
        let result = ui::run_ui("Heap Oracle", oracle, stats, stop.clone());
        stop.store(true, Ordering::Release);
        let _ = reader.join();
        return result;
    }

    #[cfg(not(feature = "ui"))]
    {
        let _ = oracle;
        let _ = stats;
        let _ = stop;
        let _ = reader;
        Err(String::from(
            "ui support is disabled; rebuild without --no-default-features or pass --no-ui",
        ))
    }
}

fn spawn_reader_thread(
    mut ring: SharedRing,
    oracle: Arc<RwLock<HeapOracle>>,
    stats: Arc<RuntimeStats>,
    stop: Arc<AtomicBool>,
    cli_trace: bool,
    use_color: bool,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut batch = Vec::with_capacity(READER_BATCH_SIZE);

        loop {
            let count = ring.read_batch(READER_BATCH_SIZE, &mut batch);
            let ring_stats = ring.stats();
            stats.update_ring(ring_stats.pending(), ring_stats.dropped);

            if count == 0 {
                if stop.load(Ordering::Acquire) && ring_stats.pending() == 0 {
                    break;
                }
                thread::sleep(Duration::from_millis(READER_IDLE_MS));
                continue;
            }

            let mut lines = Vec::new();
            if let Ok(mut oracle) = oracle.write() {
                for event in batch.iter().copied() {
                    let result = oracle.apply_event(event);
                    if cli_trace {
                        lines.push(format_event_line(event, result, use_color));
                    }
                }
            }

            stats.add_consumed(count);
            if cli_trace {
                for line in lines {
                    println!("{line}");
                }
            }
        }
    })
}

fn format_event_line(event: HeapEvent, result: ApplyResult, color: bool) -> String {
    // ANSI escape codes — empty strings when color is off
    let (g, r, y, c, m, br, dim, rst) = if color {
        (
            "\x1b[32m",   // green   — alloc
            "\x1b[31m",   // red     — free
            "\x1b[33m",   // yellow  — realloc / sizes
            "\x1b[36m",   // cyan    — addresses
            "\x1b[35m",   // magenta — bin info
            "\x1b[1;91m", // bold bright red — alerts
            "\x1b[2m",    // dim     — invalid
            "\x1b[0m",    // reset
        )
    } else {
        ("", "", "", "", "", "", "", "")
    };

    let base = match event.kind() {
        EventKind::Alloc | EventKind::Calloc | EventKind::Memalign => {
            format!(
                "{g}[+] {:<8}{rst} size={y}0x{:x}{rst} addr={c}{:#x}{rst}",
                event.kind().as_str(),
                event.size,
                event.addr,
            )
        }
        EventKind::Free => {
            format!("{r}[-] free    {rst} addr={c}{:#x}{rst}", event.addr)
        }
        EventKind::Realloc => {
            format!(
                "{y}[*] realloc {rst} old={c}{:#x}{rst} new={c}{:#x}{rst} size={y}0x{:x}{rst}",
                event.aux_addr, event.addr, event.size,
            )
        }
        EventKind::Invalid => format!("{dim}[?] invalid event{rst}"),
    };

    let mut line = base;
    if let Some(bin) = result.bin {
        line.push_str(&format!(" {m}-> {bin}{rst}"));
    }
    if let Some(alert) = result.alert {
        line.push_str(&format!(" {br}[!] {}{rst}", alert.reason));
    }

    line
}

fn spawn_target(command: &[OsString], hook_library: &Path, shm_name: &str, main_only: bool) -> Result<Child, String> {
    if command.is_empty() {
        return Err(String::from("missing target command"));
    }
    if !hook_library.exists() {
        return Err(format!("hook library not found: {}", hook_library.display()));
    }

    let preload_var = if cfg!(target_os = "macos") {
        "DYLD_INSERT_LIBRARIES"
    } else {
        "LD_PRELOAD"
    };
    let separator = if cfg!(windows) { ";" } else { ":" };
    let mut preload = hook_library.as_os_str().to_os_string();

    if let Some(existing) = env::var_os(preload_var) {
        if !existing.is_empty() {
            preload.push(separator);
            preload.push(existing);
        }
    }

    let mut child = Command::new(&command[0]);
    child.args(&command[1..]);
    child.env(preload_var, preload);
    child.env("HEAP_ORACLE_SHM_NAME", shm_name);
    if main_only {
        child.env("HEAP_ORACLE_MAIN_ONLY", "1");
    }
    if cfg!(target_os = "macos") {
        child.env("DYLD_FORCE_FLAT_NAMESPACE", "1");
    }

    child
        .spawn()
        .map_err(|err| format!("failed to launch target: {err}"))
}

fn wait_for_child(mut child: Child, stats: &RuntimeStats) -> Result<i32, String> {
    let status = child
        .wait()
        .map_err(|err| format!("failed to wait for target: {err}"))?;
    let code = status.code().unwrap_or(-1);
    stats.mark_target_exit(code);
    Ok(code)
}

fn drain_after_exit(stats: &RuntimeStats) {
    let mut stable = 0usize;

    for _ in 0..50 {
        let pending = stats.snapshot().pending;
        if pending == 0 {
            stable += 1;
            if stable >= 2 {
                break;
            }
        } else {
            stable = 0;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn print_summary(oracle: &Arc<RwLock<HeapOracle>>, stats: &RuntimeStats) {
    let snapshot = stats.snapshot();
    if let Ok(oracle) = oracle.read() {
        let summary = oracle.summary();
        eprintln!(
            "heap-oracle: events={} chunks={} allocated={} freed={} uaf={} alerts={} dropped={}",
            snapshot.consumed,
            summary.total_chunks,
            summary.allocated,
            summary.freed,
            summary.uaf,
            summary.alerts,
            snapshot.dropped,
        );
        return;
    }

    eprintln!(
        "heap-oracle: events={} pending={} dropped={}",
        snapshot.consumed, snapshot.pending, snapshot.dropped,
    );
}

fn parse_args() -> Result<ParseResult, String> {
    let mut args = env::args_os();
    let _program = args.next();
    let Some(command) = args.next() else {
        return Ok(ParseResult::Help);
    };

    if command == "help" || command == "--help" || command == "-h" {
        return Ok(ParseResult::Help);
    }

    let mut no_ui = false;
    let mut main_only = false;
    let mut no_color = false;
    let mut shm_name = generate_shm_name();
    let mut hook_library = None;

    match command.to_string_lossy().as_ref() {
        "run" => {
            let mut target = Vec::new();

            while let Some(arg) = args.next() {
                if arg == "--" {
                    target.extend(args);
                    break;
                }
                if arg == "--no-ui" {
                    no_ui = true;
                    continue;
                }
                if arg == "--main-only" {
                    main_only = true;
                    continue;
                }
                if arg == "--no-color" {
                    no_color = true;
                    continue;
                }
                if arg == "--shm-name" {
                    shm_name = next_string(&mut args, "--shm-name")?;
                    continue;
                }
                if arg == "--hook-lib" {
                    hook_library = Some(PathBuf::from(next_string(&mut args, "--hook-lib")?));
                    continue;
                }

                return Err(format!("unknown flag {:?}\n\n{}", arg, usage_text()));
            }

            if target.is_empty() {
                return Err(format!("missing target command\n\n{}", usage_text()));
            }

            Ok(ParseResult::Run(Options {
                mode: Mode::Run {
                    command: target,
                    hook_library: hook_library.unwrap_or(default_hook_library_path()?),
                },
                shm_name,
                no_ui,
                main_only,
                use_color: !no_color && std::io::stdout().is_terminal(),
            }))
        }
        "monitor" => {
            while let Some(arg) = args.next() {
                if arg == "--no-ui" {
                    no_ui = true;
                    continue;
                }
                if arg == "--no-color" {
                    no_color = true;
                    continue;
                }
                if arg == "--shm-name" {
                    shm_name = next_string(&mut args, "--shm-name")?;
                    continue;
                }

                return Err(format!("unknown flag {:?}\n\n{}", arg, usage_text()));
            }

            Ok(ParseResult::Run(Options {
                mode: Mode::Monitor,
                shm_name,
                no_ui,
                main_only: false,
                use_color: !no_color && std::io::stdout().is_terminal(),
            }))
        }
        _ => Err(format!("unknown command {:?}\n\n{}", command, usage_text())),
    }
}

fn next_string(args: &mut impl Iterator<Item = OsString>, flag: &str) -> Result<String, String> {
    let value = args
        .next()
        .ok_or_else(|| format!("{flag} requires a value"))?;

    Ok(value.to_string_lossy().into_owned())
}

fn default_hook_library_path() -> Result<PathBuf, String> {
    if let Some(path) = option_env!("HEAP_ORACLE_HOOK_DEFAULT") {
        let candidate = PathBuf::from(path);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    let exe = env::current_exe().map_err(|err| format!("unable to resolve current executable: {err}"))?;
    let dir = exe
        .parent()
        .ok_or_else(|| format!("unable to determine executable directory from {}", exe.display()))?;
    let library = if cfg!(target_os = "windows") {
        dir.join("heap_oracle_hook.dll")
    } else if cfg!(target_os = "macos") {
        dir.join("libheap_oracle_hook.dylib")
    } else {
        dir.join("libheap_oracle_hook.so")
    };

    if library.exists() {
        return Ok(library);
    }

    Err(format!(
        "hook library not found next to executable: {}",
        library.display(),
    ))
}

fn generate_shm_name() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    format!("/heap-oracle-{}-{now:x}", std::process::id())
}

fn print_usage() {
    println!("{}", usage_text());
}

fn usage_text() -> &'static str {
    "Usage:
  heap-oracle run [OPTIONS] -- <target> [args...]
  heap-oracle monitor [OPTIONS]

Options:
  --no-ui        CLI-only mode (no GUI window)
  --no-color     Disable ANSI colour output
  --main-only    Only trace events after main() starts (skip libc init noise)
  --shm-name N   Override shared-memory name
  --hook-lib P   Override hook library path

Examples:
  heap-oracle run -- ./pwn_challenge
  heap-oracle run --no-ui --main-only -- ./heap_vuln
  heap-oracle run --no-ui -- /bin/ls -la
  heap-oracle monitor --shm-name /heap-oracle-demo"
}
