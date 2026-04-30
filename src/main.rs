mod ipc;
mod state;
#[cfg(feature = "ui")]
mod ui;

use std::env;
use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipc::{EventKind, HeapEvent, SharedRing};
use state::{ApplyResult, ChunkState, HeapOracle, glibc_chunk_size};

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
    no_stack: bool,
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
        } => run_target_mode(command, &hook_library, &options.shm_name, options.no_ui, options.main_only, options.no_stack, options.use_color, oracle, stats, stop, reader),
        Mode::Monitor => run_monitor_mode(options.no_ui, options.use_color, oracle, stats, stop, reader),
    }
}

fn run_target_mode(
    command: Vec<OsString>,
    hook_library: &Path,
    shm_name: &str,
    no_ui: bool,
    main_only: bool,
    no_stack: bool,
    use_color: bool,
    oracle: Arc<RwLock<HeapOracle>>,
    stats: Arc<RuntimeStats>,
    stop: Arc<AtomicBool>,
    reader: thread::JoinHandle<()>,
) -> Result<(), String> {
    let child = spawn_target(&command, hook_library, shm_name, main_only, no_stack)?;

    if no_ui {
        let status = wait_for_child(child, &stats)?;
        drain_after_exit(&stats);
        stop.store(true, Ordering::Release);
        let _ = reader.join();
        print_heap_state(&oracle, use_color);
        print_summary(&oracle, &stats);
        if !status.success() {
            eprintln!("heap-oracle: target {}", format_exit_status(&status));
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
    use_color: bool,
    oracle: Arc<RwLock<HeapOracle>>,
    stats: Arc<RuntimeStats>,
    stop: Arc<AtomicBool>,
    reader: thread::JoinHandle<()>,
) -> Result<(), String> {
    if no_ui {
        eprintln!("heap-oracle: monitoring without UI, press Ctrl-C to stop");
        while !stop.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(500));
        }
        let _ = reader.join();
        print_heap_state(&oracle, use_color);
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

            let mut results: Vec<(HeapEvent, ApplyResult)> = Vec::new();
            if let Ok(mut oracle) = oracle.write() {
                for event in batch.iter().copied() {
                    let result = oracle.apply_event(event);
                    if cli_trace {
                        results.push((event, result));
                    }
                }
            }

            stats.add_consumed(count);
            if cli_trace {
                for (event, result) in results {
                    if let Some(line) = format_event_line(event, result, use_color) {
                        println!("{line}");
                    }
                }
            }
        }
    })
}

fn ansi(enabled: bool) -> (&'static str, &'static str, &'static str, &'static str, &'static str, &'static str, &'static str, &'static str) {
    if enabled {
        ("\x1b[32m", "\x1b[31m", "\x1b[33m", "\x1b[36m", "\x1b[35m", "\x1b[1;91m", "\x1b[2m", "\x1b[0m")
    } else {
        ("", "", "", "", "", "", "", "")
    }
}

fn format_event_line(event: HeapEvent, result: ApplyResult, color: bool) -> Option<String> {
    if event.kind() == EventKind::Free && event.addr == 0 {
        return None;
    }
    if event.kind() == EventKind::Invalid {
        return None;
    }

    let (g, r, y, c, m, br, dim, rst) = ansi(color);
    let has_alert = result.alert.is_some();

    let idx = result.chunk_index
        .map(|i| format!("#{i:<4}"))
        .unwrap_or_else(|| "??   ".into());

    let cs = result.chunk_size
        .map(|s| format!(" {dim}(0x{s:x}){rst}"))
        .unwrap_or_default();

    let base = match event.kind() {
        EventKind::Alloc | EventKind::Calloc | EventKind::Memalign => {
            let pfx = if has_alert { format!("{br}[!]{rst}") } else { format!("{g}[+]{rst}") };
            format!(
                "{pfx} {c}{idx}{rst} {:<8} {y}0x{:x}{rst}{cs}  {c}{:#x}{rst}",
                event.kind().as_str(), event.size, event.addr,
            )
        }
        EventKind::Free => {
            let pfx = if has_alert { format!("{br}[!]{rst}") } else { format!("{r}[-]{rst}") };
            format!("{pfx} {c}{idx}{rst} free    {cs}  {c}{:#x}{rst}", event.addr)
        }
        EventKind::Realloc => {
            let pfx = if has_alert { format!("{br}[!]{rst}") } else { format!("{y}[*]{rst}") };
            format!(
                "{pfx} {c}{idx}{rst} realloc  {y}0x{:x}{rst}{cs}  {c}{:#x}{rst} {dim}<-{rst} {c}{:#x}{rst}",
                event.size, event.addr, event.aux_addr,
            )
        }
        EventKind::Invalid => unreachable!(),
    };

    let mut line = base;
    if let Some(bin) = result.bin {
        line.push_str(&format!("  {m}-> {bin}{rst}"));
    }
    if let Some(alert) = result.alert {
        line.push_str(&format!("  {br}<< {}{rst}", alert.reason));
    }

    Some(line)
}

fn spawn_target(command: &[OsString], hook_library: &Path, shm_name: &str, main_only: bool, no_stack: bool) -> Result<Child, String> {
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
    if no_stack {
        child.env("HEAP_ORACLE_NO_STACK", "1");
    }
    if cfg!(target_os = "macos") {
        child.env("DYLD_FORCE_FLAT_NAMESPACE", "1");
    }

    child
        .spawn()
        .map_err(|err| format!("failed to launch target: {err}"))
}

fn wait_for_child(mut child: Child, stats: &RuntimeStats) -> Result<ExitStatus, String> {
    let status = child
        .wait()
        .map_err(|err| format!("failed to wait for target: {err}"))?;
    let code = status.code().unwrap_or(-1);
    stats.mark_target_exit(code);
    Ok(status)
}

fn format_exit_status(status: &ExitStatus) -> String {
    if let Some(code) = status.code() {
        return format!("exited with status {code}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            let name = match sig {
                6 => "SIGABRT",
                11 => "SIGSEGV",
                4 => "SIGILL",
                8 => "SIGFPE",
                9 => "SIGKILL",
                15 => "SIGTERM",
                _ => "",
            };
            return if name.is_empty() {
                format!("killed by signal {sig}")
            } else {
                format!("killed by {name} (signal {sig})")
            };
        }
    }
    format!("exited (unknown status)")
}

fn drain_after_exit(stats: &RuntimeStats) {
    let mut stable = 0usize;
    let mut last_consumed = stats.snapshot().consumed;

    for _ in 0..50 {
        let snap = stats.snapshot();
        let idle = snap.pending == 0 && snap.consumed == last_consumed;
        if idle {
            stable += 1;
            if stable >= 3 {
                break;
            }
        } else {
            stable = 0;
        }
        last_consumed = snap.consumed;
        thread::sleep(Duration::from_millis(20));
    }
}

fn print_heap_state(oracle: &Arc<RwLock<HeapOracle>>, color: bool) {
    use std::collections::HashMap;

    let Ok(oracle) = oracle.read() else { return };
    if oracle.chunks.is_empty() {
        return;
    }

    let (_g, _r, _y, c, m, br, dim, rst) = ansi(color);
    let sep = "─".repeat(55);

    println!("\n{dim}{sep}{rst}");
    println!("{c} #     Address          Req     Chunk   State{rst}");
    println!("{dim}{sep}{rst}");

    let mut chunks: Vec<_> = oracle.chunks.values().collect();
    chunks.sort_by_key(|ch| ch.index);

    let addr_to_index: HashMap<u64, usize> = chunks.iter().map(|ch| (ch.addr, ch.index)).collect();

    for ch in &chunks {
        let chunk_size = glibc_chunk_size(ch.size);
        let (state_color, state_str, detail) = match ch.state {
            ChunkState::Allocated => (_g, "ALLOC", String::new()),
            ChunkState::Freed { bin } => (dim, "FREE ", format!("  {m}{bin}{rst}")),
            ChunkState::Uaf { reason } => (br, "UAF  ", format!("  {br}{reason}{rst}")),
        };
        println!(
            " {c}{:<5}{rst} {:#014x}   {:#06x}   {:#06x}  {state_color}{state_str}{rst}{detail}",
            format!("#{}", ch.index), ch.addr, ch.size, chunk_size,
        );
    }

    let has_bins = oracle.tcache.iter().any(|b| !b.is_empty())
        || oracle.fastbins.iter().any(|b| !b.is_empty());

    if has_bins {
        println!("\n{dim}{sep}{rst}");
        println!("{m} Bin Chains{rst}");
        println!("{dim}{sep}{rst}");

        for (idx, bin) in oracle.tcache.iter().enumerate() {
            if bin.is_empty() {
                continue;
            }
            let chain = format_bin_chain(bin, &addr_to_index);
            println!(" {m}tcache[{idx:02}]{rst} (0x{:x}): {chain}", (idx + 2) * 0x10);
        }

        for (idx, bin) in oracle.fastbins.iter().enumerate() {
            if bin.is_empty() {
                continue;
            }
            let chain = format_bin_chain(bin, &addr_to_index);
            println!(" {m}fastbin[{idx:02}]{rst} (0x{:x}): {chain}", (idx + 2) * 0x10);
        }
    }

    if !oracle.alerts.is_empty() {
        println!("\n{dim}{sep}{rst}");
        println!("{br} Alerts{rst}");
        println!("{dim}{sep}{rst}");
        for alert in &oracle.alerts {
            println!(" {br}{:#014x}  {}{rst}", alert.addr, alert.reason);
        }
    }

    println!("{dim}{sep}{rst}");
}

fn format_bin_chain(bin: &[u64], addr_to_index: &std::collections::HashMap<u64, usize>) -> String {
    let mut parts = Vec::new();
    for addr in bin.iter().rev() {
        if let Some(idx) = addr_to_index.get(addr) {
            parts.push(format!("#{idx}"));
        } else {
            parts.push(format!("{addr:#x}"));
        }
    }
    parts.join(" → ")
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
    let mut no_stack = false;
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
                if arg == "--no-stack" {
                    no_stack = true;
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
                no_stack,
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
                no_stack: false,
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
  --no-stack     Disable callstack capture (faster, smaller events)
  --shm-name N   Override shared-memory name
  --hook-lib P   Override hook library path

Examples:
  heap-oracle run -- ./pwn_challenge
  heap-oracle run --no-ui --main-only -- ./heap_vuln
  heap-oracle run --no-ui -- /bin/ls -la
  heap-oracle monitor --shm-name /heap-oracle-demo"
}
