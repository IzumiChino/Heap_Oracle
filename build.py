#!/usr/bin/env python3

import argparse
import pathlib
import subprocess
import sys


def main() -> int:
	parser = argparse.ArgumentParser(description="Build Heap Oracle and its hook library")
	parser.add_argument("--release", action="store_true", help="build the release profile")
	parser.add_argument(
		"--cli-only",
		action="store_true",
		help="disable egui/eframe and build the CLI core only",
	)
	parser.add_argument(
		"cargo_args",
		nargs=argparse.REMAINDER,
		help="extra arguments forwarded to cargo after --",
	)
	args = parser.parse_args()

	cmd = ["cargo", "build"]
	if args.release:
		cmd.append("--release")
	if args.cli_only:
		cmd.append("--no-default-features")
	if args.cargo_args:
		cmd.extend(args.cargo_args)

	print("[build]", " ".join(cmd))
	subprocess.run(cmd, check=True)

	profile = "release" if args.release else "debug"
	root = pathlib.Path(__file__).resolve().parent
	if sys.platform == "darwin":
		lib_name = "libheap_oracle_hook.dylib"
	elif sys.platform.startswith("win"):
		lib_name = "heap_oracle_hook.dll"
	else:
		lib_name = "libheap_oracle_hook.so"

	hook_path = root / "target" / profile / lib_name
	print(f"[hook] {hook_path}")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())