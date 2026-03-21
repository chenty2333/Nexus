#!/usr/bin/env python3

from __future__ import annotations

import argparse
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import BinaryIO


PROMPT = b"~ #"


@dataclass(frozen=True)
class ShellStep:
    command: str
    expect: bytes


class Transcript:
    def __init__(self) -> None:
        self._data = bytearray()
        self._closed = False
        self._cond = threading.Condition()

    def append(self, chunk: bytes) -> None:
        with self._cond:
            self._data.extend(chunk)
            self._cond.notify_all()

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    def snapshot(self) -> bytes:
        with self._cond:
            return bytes(self._data)

    def wait_for(self, needle: bytes, start: int, timeout_s: float) -> int:
        deadline = time.monotonic() + timeout_s
        with self._cond:
            while True:
                idx = self._data.find(needle, start)
                if idx >= 0:
                    return idx
                if self._closed:
                    raise RuntimeError(
                        f"missing output {needle!r} before qemu stdout closed"
                    )
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"timed out waiting for {needle!r}")
                self._cond.wait(remaining)


def stream_output(pipe: BinaryIO, transcript: Transcript) -> None:
    try:
        while True:
            read1 = getattr(pipe, "read1", None)
            if read1 is not None:
                chunk = read1(4096)
            else:
                chunk = pipe.read(4096)
            if not chunk:
                break
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
            transcript.append(chunk)
    finally:
        transcript.close()


def shell_steps() -> list[ShellStep]:
    return [
        ShellStep("echo shell-ok", b"shell-ok"),
        ShellStep("ls / && echo ls-ok", b"ls-ok"),
        ShellStep("ls /dev/ptmx /dev/pts /dev/pts/0 && echo tty-ok", b"tty-ok"),
        ShellStep("cat /etc/passwd && echo cat-ok", b"cat-ok"),
        ShellStep("mkdir /tmp/shell-dir && echo mkdir-ok", b"mkdir-ok"),
        ShellStep("echo rm-me > /tmp/rm-me", PROMPT),
        ShellStep("rm /tmp/rm-me && echo rm-ok", b"rm-ok"),
        ShellStep("ps && echo ps-ok", b"ps-ok"),
    ]


def qemu_command(kernel: str, init: str, init_size: int) -> list[str]:
    return [
        "qemu-system-x86_64",
        "-machine",
        "q35",
        "-m",
        "256M",
        "-smp",
        "2",
        "-nographic",
        "-serial",
        "stdio",
        "-monitor",
        "none",
        "-no-reboot",
        "-device",
        "isa-debug-exit,iobase=0xf4,iosize=0x04",
        "-device",
        f"loader,file={init},addr=0x7000000,force-raw=on",
        "-device",
        f"loader,data={init_size},data-len=8,addr=0x6fffff8",
        "-device",
        f"loader,file={init},addr=0x5000000,force-raw=on",
        "-device",
        f"loader,data={init_size},data-len=8,addr=0x4fffff8",
        "-kernel",
        kernel,
    ]


def send_line(process: subprocess.Popen[bytes], command: str) -> None:
    assert process.stdin is not None
    process.stdin.write(command.encode("utf-8") + b"\n")
    process.stdin.flush()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--init", required=True)
    parser.add_argument("--timeout", type=float, default=150.0)
    args = parser.parse_args()

    init_size = int(subprocess.check_output(["stat", "-c%s", args.init], text=True).strip())
    process = subprocess.Popen(
        qemu_command(args.kernel, args.init, init_size),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert process.stdout is not None
    transcript = Transcript()
    reader = threading.Thread(
        target=stream_output,
        args=(process.stdout, transcript),
        daemon=True,
    )
    reader.start()

    try:
        cursor = 0
        cursor = transcript.wait_for(PROMPT, cursor, args.timeout)
        for step in shell_steps():
            send_line(process, step.command)
            cursor = transcript.wait_for(step.expect, cursor, args.timeout)
            cursor = transcript.wait_for(PROMPT, cursor, args.timeout)
        send_line(process, "exit")
        exit_code = process.wait(timeout=args.timeout)
    except Exception:
        process.kill()
        process.wait(timeout=5)
        raise
    finally:
        reader.join(timeout=5)

    print(f"qemu_exit={exit_code}")
    if exit_code != 33:
        return 1
    full = transcript.snapshot()
    if b"can't access tty" in full:
        raise RuntimeError("shell transcript still reports missing tty")
    required = [b"shell-ok", b"ls-ok", b"tty-ok", b"cat-ok", b"mkdir-ok", b"rm-ok", b"ps-ok"]
    for needle in required:
        if needle not in full:
            raise RuntimeError(f"missing shell transcript token {needle!r}")
    echoed = [
        b"echo shell-ok",
        b"ls / && echo ls-ok",
        b"ls /dev/ptmx /dev/pts /dev/pts/0 && echo tty-ok",
        b"cat /etc/passwd && echo cat-ok",
        b"mkdir /tmp/shell-dir && echo mkdir-ok",
        b"ps && echo ps-ok",
    ]
    for needle in echoed:
        if needle not in full:
            raise RuntimeError(f"missing echoed shell command {needle!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
