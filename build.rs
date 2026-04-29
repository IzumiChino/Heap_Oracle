use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn find_artifact(root: &Path, name: &str) -> Option<PathBuf> {
	let entries = fs::read_dir(root).ok()?;

	for entry in entries.flatten() {
		let path = entry.path();

		if path.is_dir() {
			if let Some(found) = find_artifact(&path, name) {
				return Some(found);
			}
			continue;
		}

		if path.file_name().and_then(|file| file.to_str()) == Some(name) {
			return Some(path);
		}
	}

	None
}

fn platform_library_name() -> &'static str {
	if cfg!(target_os = "windows") {
		"heap_oracle_hook.dll"
	} else if cfg!(target_os = "macos") {
		"libheap_oracle_hook.dylib"
	} else {
		"libheap_oracle_hook.so"
	}
}

fn main() {
	let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("missing manifest dir"));
	let profile = env::var("PROFILE").unwrap_or_else(|_| String::from("debug"));
	let build_profile = if profile == "release" { "Release" } else { "Debug" };
	let artifact_name = platform_library_name();

	println!("cargo:rerun-if-changed=hook/CMakeLists.txt");
	println!("cargo:rerun-if-changed=hook/include/heap_oracle_hook.h");
	println!("cargo:rerun-if-changed=hook/src/hook.c");
	println!("cargo:rerun-if-changed=hook/src/ringbuf.c");
	println!("cargo:rerun-if-changed=hook/src/platform/linux.c");
	println!("cargo:rerun-if-changed=hook/src/platform/macos.c");
	println!("cargo:rerun-if-changed=hook/src/platform/windows.c");

	let dst = cmake::Config::new(manifest_dir.join("hook"))
		.profile(build_profile)
		.build();

	let built_library = find_artifact(&dst, artifact_name)
		.unwrap_or_else(|| panic!("unable to locate {artifact_name} below {}", dst.display()));

	let runtime_dir = manifest_dir.join("target").join(&profile);
	let runtime_library = runtime_dir.join(artifact_name);

	fs::create_dir_all(&runtime_dir)
		.unwrap_or_else(|err| panic!("failed to create {}: {err}", runtime_dir.display()));
	fs::copy(&built_library, &runtime_library).unwrap_or_else(|err| {
		panic!(
			"failed to copy {} to {}: {err}",
			built_library.display(),
			runtime_library.display(),
		)
	});

	println!(
		"cargo:rustc-env=HEAP_ORACLE_HOOK_DEFAULT={}",
		runtime_library.display()
	);
}