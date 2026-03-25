#!/usr/bin/env python3

from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


PROMPT = b"~ # "


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def qemu_command(kernel: str, init: str, init_size: int, serial: str, port: int) -> list[str]:
    return [
        "qemu-system-x86_64",
        "-machine",
        "q35,accel=kvm",
        "-cpu",
        "host",
        "-m",
        "256M",
        "-smp",
        "2",
        "-nographic",
        "-serial",
        f"file:{serial}",
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
        "-netdev",
        f"user,id=net0,hostfwd=tcp::{port}-:22",
        "-device",
        "virtio-net-pci,netdev=net0",
    ]


def connect_shell(port: int, timeout_s: float) -> socket.socket:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=1.0)
            sock.settimeout(timeout_s)
            return sock
        except OSError:
            if time.monotonic() >= deadline:
                raise TimeoutError("timed out connecting to forwarded remote shell port")
            time.sleep(0.2)


def read_until(sock: socket.socket, needle: bytes, timeout_s: float, initial: bytes = b"") -> bytes:
    deadline = time.monotonic() + timeout_s
    data = bytearray(initial)
    while needle not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"timed out waiting for {needle!r}")
        sock.settimeout(remaining)
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError(f"socket closed while waiting for {needle!r}: {bytes(data)!r}")
        data.extend(chunk)
    return bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--init", required=True)
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args()

    init_size = int(subprocess.check_output(["stat", "-c%s", args.init], text=True).strip())
    port = free_tcp_port()
    with tempfile.TemporaryDirectory(prefix="starnix-remote-shell-") as temp_dir:
        serial = str(Path(temp_dir) / "remote-shell.serial.log")
        qemu = subprocess.Popen(
            qemu_command(args.kernel, args.init, init_size, serial, port),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            sock = connect_shell(port, args.timeout)
            with sock:
                transcript = read_until(sock, PROMPT, args.timeout)
                print("prompt-ok")
                sock.sendall(b"echo remote-shell-ok\n")
                transcript = read_until(sock, b"remote-shell-ok", args.timeout, transcript)
                transcript = read_until(sock, PROMPT, args.timeout, transcript)
                print("remote-shell-ok")
                sock.sendall(b"ls /dev/ptmx /dev/pts /dev/pts/0 && echo remote-tty-ok\n")
                transcript = read_until(sock, b"remote-tty-ok", args.timeout, transcript)
                transcript = read_until(sock, PROMPT, args.timeout, transcript)
                print("remote-tty-ok")
                sock.sendall(b"ps && echo remote-ps-ok\n")
                transcript = read_until(sock, b"remote-ps-ok", args.timeout, transcript)
                transcript = read_until(sock, PROMPT, args.timeout, transcript)
                print("remote-ps-ok")
                sock.sendall(b"exit\n")
            qemu.terminate()
            try:
                exit_code = qemu.wait(timeout=5)
            except subprocess.TimeoutExpired:
                qemu.kill()
                exit_code = qemu.wait(timeout=5)
        except Exception:
            qemu.kill()
            qemu.wait(timeout=5)
            with open(serial, "rb") as f:
                sys.stdout.buffer.write(f.read())
            raise
        if exit_code not in (0, -15, -9):
            with open(serial, "rb") as f:
                sys.stdout.buffer.write(f.read())
            raise RuntimeError(f"unexpected qemu exit code {exit_code}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
