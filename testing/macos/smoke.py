#!/usr/bin/env python3
"""Validate macOS collectors using temporary APFS and HFS+ disk images."""
import json
import os
import pathlib
import plistlib
import re
import subprocess
import sys
import tempfile


def run(*args, minimal_path=False):
    environment = os.environ.copy()
    if minimal_path:
        environment["PATH"] = "/usr/bin:/bin"
    return subprocess.check_output(args, stderr=subprocess.PIPE, env=environment)


def main():
    binary = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "target/debug/iodyne").resolve()
    attached = []
    with tempfile.TemporaryDirectory(prefix="iodyne-macos-") as temporary:
        root = pathlib.Path(temporary).resolve()
        expected = {}
        try:
            for filesystem, fs_type in [("APFS", "apfs"), ("JHFS+", "hfs")]:
                image = root / (fs_type + ".dmg")
                mount = root / fs_type
                mount.mkdir()
                run("hdiutil", "create", "-size", "128m", "-fs", filesystem,
                    "-volname", "iodyne-" + fs_type, str(image))
                result = plistlib.loads(run("hdiutil", "attach", "-plist", "-nobrowse",
                                            "-mountpoint", str(mount), str(image)))
                attached.append(next(entity["dev-entry"] for entity in result["system-entities"]
                                     if "dev-entry" in entity))
                expected[str(mount)] = fs_type
            diag = run(str(binary), "--diag").decode()
            records = [json.loads(line) for line in run(str(binary), "--jsonl",
                       "--interval-ms", "100", "--intervals", "2", minimal_path=True).splitlines()]
            inventory = records[0]
            assert inventory["record_type"] == "inventory"
            for mount, fs_type in expected.items():
                entry = next(item for item in inventory["mounts"] if item["path"] == mount)
                assert entry["filesystem"] == fs_type, entry
                source = entry["source"]
                assert any(edge["kind"] == "mount_backed_by" and edge["from"] == mount
                           and edge["to"] == source for edge in inventory["topology"])
                row = next(line for line in diag.splitlines() if "kind=" in line
                           and "mounts=" in line and mount in line)
                assert "size=0 " not in row and "counter_sources=[]" not in row, row
                backing = json.loads(re.search(r"member_disks=(\[[^\]]*\])", row).group(1))
                counters = json.loads(re.search(r"counter_sources=(\[[^\]]*\])", row).group(1))
                assert backing and backing != counters, "disk image was not grouped with its host disk: " + row
            samples = records[1:]
            assert len(samples) == 2
            assert all(sample["devices"] for sample in samples), "no disk counters with /usr/sbin absent from PATH"
            assert all(sample["collectors"]["block_io"]["state"] == "active" for sample in samples)
            assert all(sample["record_type"] == "sample" for sample in samples)
            assert all(sample["collectors"]["latency"]["state"] == "unsupported_platform"
                       for sample in samples)
            print("PASS: APFS and HFS+ capacity rows, mount topology, and two JSONL samples")
        finally:
            for device in reversed(attached):
                run("hdiutil", "detach", device)


if __name__ == "__main__":
    main()
