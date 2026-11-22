#!/usr/bin/env python3
"""Self-contained Phase 0 E2E bringup & verification runner for HAL-OS (FreeBSD 14 + KVM)."""

from __future__ import annotations

import argparse
import hashlib
import lzma
import os
import pty
import re
import select
import shutil
import signal
import subprocess
import sys
import tarfile
import time
from pathlib import Path

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def run_host(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=check, text=True, capture_output=True)


def parse_checksum(checksum_path: Path, filename: str) -> str:
    target = f"({filename})"
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "SHA256" and parts[1] == target:
            return parts[3]
    raise RuntimeError(f"Could not find SHA256 entry for {filename} in {checksum_path}")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(4 * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def ensure_disks(images_dir: Path, freebsd_version: str) -> tuple[Path, Path]:
    images_dir.mkdir(parents=True, exist_ok=True)
    xz_name = f"FreeBSD-{freebsd_version}-amd64-zfs.qcow2.xz"
    base_url = f"https://download.freebsd.org/releases/VM-IMAGES/{freebsd_version}/amd64/Latest"
    checksum_path = images_dir / "CHECKSUM.SHA256"
    xz_path = images_dir / xz_name
    sys_disk = images_dir / "freebsd14-sys.qcow2"
    data_disk = images_dir / "halpool-data.qcow2"

    print(f"[1/6] Fetching checksum & checking FreeBSD {freebsd_version} image...")
    subprocess.run(
        ["curl", "-fSL", "--no-progress-meter", "--retry", "3", "-o", str(checksum_path), f"{base_url}/CHECKSUM.SHA256"],
        check=True,
    )
    expected_sha = parse_checksum(checksum_path, xz_name)

    if not xz_path.exists() or sha256_file(xz_path) != expected_sha:
        print(f"      Downloading {xz_name}...")
        subprocess.run(
            ["curl", "-fSL", "--no-progress-meter", "--retry", "3", "-C", "-", "-o", str(xz_path), f"{base_url}/{xz_name}"],
            check=True,
        )
        actual_sha = sha256_file(xz_path)
        if actual_sha != expected_sha:
            raise RuntimeError(f"SHA-256 mismatch for {xz_path}: expected {expected_sha}, got {actual_sha}")
    print(f"      SHA-256 verified: {expected_sha}")

    if not sys_disk.exists():
        print(f"      Decompressing {xz_name} via Python lzma -> {sys_disk}...")
        tmp_sys = images_dir / "freebsd14-sys.qcow2.tmp"
        with lzma.open(xz_path, "rb") as src, tmp_sys.open("wb") as dst:
            while True:
                buf = src.read(4 * 1024 * 1024)
                if not buf:
                    break
                dst.write(buf)
        tmp_sys.replace(sys_disk)
        subprocess.run(["qemu-img", "resize", str(sys_disk), "16G"], check=True)
    else:
        print(f"      Using existing system disk: {sys_disk}")

    if not data_disk.exists():
        print(f"      Creating 32G halpool disk -> {data_disk}...")
        subprocess.run(["qemu-img", "create", "-f", "qcow2", str(data_disk), "32G"], check=True)
    else:
        print(f"      Using existing data disk: {data_disk}")

    return sys_disk, data_disk


def ensure_seed_and_ssh_key(bundle_root: Path, images_dir: Path) -> tuple[Path, Path]:
    priv_key = images_dir / "hal-oob-id_ed25519"
    pub_key = images_dir / "hal-oob-id_ed25519.pub"
    seed_tar = images_dir / "hal-seed.tar"

    print("[2/6] Preparing lab OOB SSH keypair & offline hal-seed.tar...")
    if not priv_key.exists() or not pub_key.exists():
        if priv_key.exists():
            priv_key.unlink()
        if pub_key.exists():
            pub_key.unlink()
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "hal-os-phase0-lab", "-f", str(priv_key)],
            check=True,
        )
    os.chmod(priv_key, 0o600)

    config_dir = bundle_root / "config"
    freebsd_dir = bundle_root / "vm" / "freebsd"
    if not config_dir.is_dir() or not freebsd_dir.is_dir():
        raise RuntimeError(f"Missing config/ or vm/freebsd/ under bundle root: {bundle_root}")

    with tarfile.open(seed_tar, "w") as tf:
        for base, arc_prefix in ((config_dir, "config"), (freebsd_dir, "vm/freebsd")):
            for item in sorted(base.rglob("*")):
                rel = item.relative_to(base)
                arcname = f"{arc_prefix}/{rel.as_posix()}"
                info = tf.gettarinfo(str(item), arcname=arcname)
                if item.is_file() and item.suffix == ".sh":
                    info.mode = 0o755
                if item.is_file():
                    with item.open("rb") as fp:
                        tf.addfile(info, fp)
                else:
                    tf.addfile(info)

        pub_info = tf.gettarinfo(str(pub_key), arcname="ssh/authorized_keys")
        pub_info.mode = 0o644
        with pub_key.open("rb") as fp:
            tf.addfile(pub_info, fp)

    print(f"      Seed bundle ready: {seed_tar} ({seed_tar.stat().st_size} bytes)")
    return seed_tar, priv_key


def detect_accel() -> tuple[str, str]:
    if os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK):
        return "kvm", "host"
    return "tcg", "qemu64"


def build_qemu_cmd(
    sys_disk: Path,
    data_disk: Path,
    seed_tar: Path,
    oob_sock: Path,
    accel: str,
    cpu_model: str,
    cpus: int,
    mem_mb: int,
    ssh_port: int,
    oob_port: int,
) -> list[str]:
    return [
        "qemu-system-x86_64",
        "-name", "hal-os-freebsd14",
        "-machine", f"q35,accel={accel}",
        "-cpu", cpu_model,
        "-smp", str(cpus),
        "-m", str(mem_mb),
        "-device", "virtio-rng-pci",
        "-drive", f"if=virtio,format=qcow2,file={sys_disk}",
        "-drive", f"if=virtio,format=qcow2,file={data_disk}",
        "-drive", f"if=virtio,format=raw,readonly=on,file={seed_tar}",
        "-netdev", (
            f"user,id=net_mgmt,net=192.168.100.0/24,dhcpstart=192.168.100.10,"
            f"restrict=on,hostfwd=tcp:127.0.0.1:{ssh_port}-192.168.100.10:22,"
            f"hostfwd=tcp:127.0.0.1:{oob_port}-192.168.100.10:8443"
        ),
        "-device", "virtio-net-pci,netdev=net_mgmt,mac=52:54:00:aa:01:01",
        "-netdev", "user,id=net_wan,net=10.0.2.0/24",
        "-device", "virtio-net-pci,netdev=net_wan,mac=52:54:00:aa:01:02",
        "-chardev", f"socket,id=hal_oob_con,path={oob_sock},server=on,wait=off",
        "-device", "virtio-serial-pci",
        "-device", "virtconsole,chardev=hal_oob_con,name=org.halos.oob",
        "-nographic",
    ]


def dump_serial_tail(serial_log: Path, limit: int = 4000) -> None:
    if serial_log.exists():
        tail = serial_log.read_text(encoding="utf-8", errors="replace")[-limit:]
        print("\n--- serial log tail ---", file=sys.stderr)
        print(tail, file=sys.stderr)


class SerialVmSession:
    def __init__(self, cmd: list[str], serial_log: Path) -> None:
        self.cmd = cmd
        self.serial_log = serial_log
        self.master_fd = -1
        self.proc: subprocess.Popen[bytes] | None = None
        self.log_fp = None
        self.buf = ""

    def __enter__(self) -> "SerialVmSession":
        self.log_fp = self.serial_log.open("w", encoding="utf-8", errors="replace")
        master_fd, slave_fd = pty.openpty()
        self.master_fd = master_fd
        try:
            self.proc = subprocess.Popen(
                self.cmd,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                start_new_session=True,
                close_fds=True,
            )
        finally:
            os.close(slave_fd)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if self.proc is not None and self.proc.poll() is None:
                try:
                    os.killpg(self.proc.pid, signal.SIGTERM)
                    self.proc.wait(timeout=10)
                except Exception:
                    try:
                        os.killpg(self.proc.pid, signal.SIGKILL)
                        self.proc.wait(timeout=5)
                    except Exception:
                        pass
        finally:
            if self.master_fd >= 0:
                try:
                    os.close(self.master_fd)
                except OSError:
                    pass
            if self.log_fp is not None:
                self.log_fp.close()

    def _pump(self, timeout_s: float = 0.25) -> bool:
        if self.master_fd < 0:
            return False
        rlist, _, _ = select.select([self.master_fd], [], [], timeout_s)
        if not rlist:
            return False
        try:
            data = os.read(self.master_fd, 65536)
        except OSError:
            return False
        if not data:
            return False
        text = strip_ansi(data.decode("utf-8", errors="replace")).replace("\r\n", "\n").replace("\r", "")
        self.buf += text
        if len(self.buf) > 512 * 1024:
            self.buf = self.buf[-256 * 1024:]
        if self.log_fp is not None:
            self.log_fp.write(text)
            self.log_fp.flush()
        return True

    def drain(self, duration_s: float = 0.5) -> None:
        deadline = time.monotonic() + duration_s
        while time.monotonic() < deadline:
            self._pump(0.1)

    def send(self, s: str) -> None:
        os.write(self.master_fd, s.encode("utf-8"))

    def send_paced(self, s: str, chunk_size: int = 8, delay_s: float = 0.015) -> None:
        raw = s.encode("utf-8")
        idx = 0
        while idx < len(raw):
            n = os.write(self.master_fd, raw[idx:idx + chunk_size])
            if n <= 0:
                raise OSError("Zero-byte write to QEMU PTY master")
            idx += n
            deadline = time.monotonic() + delay_s
            while time.monotonic() < deadline:
                self._pump(max(0.001, deadline - time.monotonic()))

    def wait_regex(self, pattern: str, timeout_s: int, flags: int = re.MULTILINE) -> re.Match[str]:
        compiled = re.compile(pattern, flags)
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            m = compiled.search(self.buf)
            if m:
                return m
            if self.proc is not None and self.proc.poll() is not None:
                # Drain any remaining bytes before failing
                self.drain(0.3)
                m = compiled.search(self.buf)
                if m:
                    return m
                raise RuntimeError(
                    f"QEMU exited prematurely (rc={self.proc.returncode}) while waiting for /{pattern}/.\n"
                    f"Last serial output:\n{self.buf[-2000:]}"
                )
            self._pump(0.25)
        raise TimeoutError(f"Timed out after {timeout_s}s waiting for /{pattern}/.\nLast serial output:\n{self.buf[-2000:]}")

    def enable_serial_console_at_loader(self, timeout_s: int = 90) -> None:
        self.wait_regex(r"Autoboot in\s+\d+\s+second", timeout_s)
        time.sleep(0.3)
        self.send("3")
        self.wait_regex(r"(?:^|\n)OK\s", 20)
        for cmd in (
            'set console="comconsole"',
            'set boot_serial="YES"',
            'set comconsole_speed="115200"',
        ):
            self.buf = ""
            self.send_paced(cmd + "\r", chunk_size=1, delay_s=0.02)
            self.wait_regex(r"(?:^|\n)(?:OK|OOKK)\s", 15)
        self.buf = ""
        self.send_paced("boot\r", chunk_size=1, delay_s=0.02)

    def login_root(self, timeout_s: int = 300) -> None:
        self.wait_regex(r"(?:^|\n)login:\s*", timeout_s)
        for attempt in range(2):
            self.buf = ""
            if attempt > 0:
                self.send_paced("\n", chunk_size=8, delay_s=0.015)
                self.drain(0.5)
            self.send_paced("root\n", chunk_size=8, delay_s=0.015)
            self.drain(1.5)
            if re.search(r"Password:", self.buf, re.IGNORECASE):
                raise RuntimeError("Guest requested a password for root; unexpected for official FreeBSD VM image.")
            self.send_paced("exec /bin/sh\n", chunk_size=8, delay_s=0.015)
            self.drain(0.6)
            self.buf = ""
            self.send_paced("PS1='HAL# ' && printf '__HAL_%s__\\n' 'LOGIN_OK'\n", chunk_size=8, delay_s=0.015)
            try:
                self.wait_regex(r"^__HAL_LOGIN_OK__\s*$", 20 if attempt == 0 else 30)
                self.buf = ""
                return
            except TimeoutError:
                if attempt == 1:
                    raise

    def run_guest_cmd(self, cmd: str, timeout_s: int = 300) -> tuple[int, str]:
        self.buf = ""
        wrapped = f"( {cmd} ); printf '__HAL_RC_%d__\\n' \"$?\"\n"
        self.send_paced(wrapped, chunk_size=8, delay_s=0.015)
        m = self.wait_regex(r"^__HAL_RC_(\d+)__\s*$", timeout_s)
        rc = int(m.group(1))
        output = self.buf[:m.start()]
        self.buf = self.buf[m.end():]
        return rc, output


def migrate_legacy_images(legacy_dir: Path, images_dir: Path) -> None:
    subprocess.run(["pkill", "-f", r"^qemu-system-x86_64.*-name hal-os-freebsd14"], check=False)
    time.sleep(2.0)
    if not legacy_dir.exists():
        return
    images_dir.mkdir(parents=True, exist_ok=True)
    for pattern in ("CHECKSUM.SHA256", "*.qcow2.xz", "hal-oob-id_ed25519*"):
        for src in legacy_dir.glob(pattern):
            dst = images_dir / src.name
            if not dst.exists() and src.is_file():
                print(f"      Migrating {src} -> {dst}...")
                shutil.move(str(src), str(dst))
    shutil.rmtree(legacy_dir, ignore_errors=True)
    print(f"      Cleaned legacy images directory: {legacy_dir}")


def main() -> int:
    t_start = time.monotonic()
    parser = argparse.ArgumentParser(description="HAL-OS Phase 0 automated KVM E2E runner")
    bundle_root = Path(__file__).resolve().parent.parent
    parser.add_argument("--images-dir", default="/var/tmp/hal-os-vm")
    parser.add_argument("--freebsd-version", default="14.5-RELEASE")
    parser.add_argument("--migrate-from", default="")
    parser.add_argument("--fresh-disks", action="store_true")
    parser.add_argument("--cpus", type=int, default=4)
    parser.add_argument("--mem", type=int, default=4096)
    parser.add_argument("--ssh-port", type=int, default=2222)
    parser.add_argument("--oob-port", type=int, default=8443)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    images_dir = Path(args.images_dir).resolve()
    accel, cpu_model = detect_accel()
    oob_sock = images_dir / "hal-os-oob.sock"

    if args.dry_run:
        cmd = build_qemu_cmd(
            images_dir / "freebsd14-sys.qcow2",
            images_dir / "halpool-data.qcow2",
            images_dir / "hal-seed.tar",
            oob_sock,
            accel,
            cpu_model,
            args.cpus,
            args.mem,
            args.ssh_port,
            args.oob_port,
        )
        print(f"Bundle root: {bundle_root}")
        print(f"Images dir:  {images_dir}")
        print(f"Accel:       {accel} ({cpu_model})")
        print("QEMU cmd:    " + " ".join(cmd))
        return 0

    for req in ("curl", "qemu-img", "qemu-system-x86_64", "ssh-keygen", "ssh"):
        if shutil.which(req) is None:
            raise RuntimeError(f"Required host binary not found on PATH: {req}")

    subprocess.run(["pkill", "-f", r"^qemu-system-x86_64.*-name hal-os-freebsd14"], check=False)
    time.sleep(1.0)

    if args.migrate_from:
        migrate_legacy_images(Path(args.migrate_from).resolve(), images_dir)

    if args.fresh_disks:
        for disk_name in ("freebsd14-sys.qcow2", "halpool-data.qcow2"):
            disk_path = images_dir / disk_name
            if disk_path.exists():
                disk_path.unlink()

    sys_disk, data_disk = ensure_disks(images_dir, args.freebsd_version)
    seed_tar, priv_key = ensure_seed_and_ssh_key(bundle_root, images_dir)

    if oob_sock.exists():
        oob_sock.unlink()

    qemu_cmd = build_qemu_cmd(
        sys_disk,
        data_disk,
        seed_tar,
        oob_sock,
        accel,
        cpu_model,
        args.cpus,
        args.mem,
        args.ssh_port,
        args.oob_port,
    )
    serial_log = images_dir / "phase0-serial.log"
    report_path = images_dir / "phase0-e2e-report.txt"
    boot_timeout = 300 if accel == "kvm" else 600

    print(f"[3/6] ({time.monotonic() - t_start:.1f}s) Booting FreeBSD {args.freebsd_version} ({accel}/{cpu_model}) -> {serial_log}")
    try:
        with SerialVmSession(qemu_cmd, serial_log) as vm:
            vm.enable_serial_console_at_loader(timeout_s=90)
            vm.login_root(timeout_s=boot_timeout)

            print(f"[4/6] ({time.monotonic() - t_start:.1f}s) Unpacking vtbd2 seed bundle & running phase0-init.sh...")
            init_rc, init_out = vm.run_guest_cmd(
                "mkdir -p /tmp/hal && tar -xf /dev/vtbd2 -C /tmp/hal && sh /tmp/hal/vm/freebsd/phase0-init.sh",
                timeout_s=300,
            )
            print(init_out.strip())
            if init_rc != 0:
                raise RuntimeError(f"phase0-init.sh failed with exit code {init_rc}")

            print(f"[5/6] ({time.monotonic() - t_start:.1f}s) Rebooting FreeBSD to activate kern.racct.enable=1, mgmt0/wan0, PF & RCTL...")
            vm.buf = ""
            vm.send_paced("reboot\n", chunk_size=8, delay_s=0.015)
            vm.drain(3.0)
            vm.buf = ""
            vm.login_root(timeout_s=boot_timeout)

            print(f"[6/6] ({time.monotonic() - t_start:.1f}s) Running /usr/local/libexec/hal-os/phase0-verify.sh & host OOB SSH probe...")
            verify_rc, verify_out = vm.run_guest_cmd(
                "sh /usr/local/libexec/hal-os/phase0-verify.sh",
                timeout_s=240,
            )
            print(verify_out.strip())

            ssh_res: subprocess.CompletedProcess[str] | None = None
            for ssh_attempt in range(1, 4):
                ssh_res = subprocess.run(
                    [
                        "ssh",
                        "-o", "BatchMode=yes",
                        "-o", "IdentitiesOnly=yes",
                        "-o", "StrictHostKeyChecking=no",
                        "-o", "UserKnownHostsFile=/dev/null",
                        "-o", "ConnectTimeout=15",
                        "-i", str(priv_key),
                        "-p", str(args.ssh_port),
                        "root@127.0.0.1",
                        "hostname && sysctl -n kern.racct.enable && ifconfig mgmt0 | grep inet",
                    ],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                if (
                    ssh_res.returncode == 0
                    and "hal-os-node0" in ssh_res.stdout
                    and "192.168.100.10" in ssh_res.stdout
                ):
                    break
                if ssh_attempt < 3:
                    time.sleep(2.0)
            assert ssh_res is not None
            print(f"OOB SSH rc={ssh_res.returncode}")
            if ssh_res.stdout:
                print(ssh_res.stdout.strip())
            if ssh_res.stderr:
                print(ssh_res.stderr.strip(), file=sys.stderr)

            print(f"({time.monotonic() - t_start:.1f}s) Shutting down FreeBSD cleanly (poweroff)...")
            vm.send_paced("poweroff\n", chunk_size=8, delay_s=0.015)
            try:
                assert vm.proc is not None
                vm.proc.wait(timeout=45)
            except subprocess.TimeoutExpired:
                print("Warning: VM did not poweroff within 45s; terminating QEMU.", file=sys.stderr)
    except Exception:
        dump_serial_tail(serial_log)
        raise

    ssh_ok = (
        ssh_res.returncode == 0
        and "hal-os-node0" in ssh_res.stdout
        and "192.168.100.10" in ssh_res.stdout
    )
    overall_ok = (init_rc == 0) and (verify_rc == 0) and ssh_ok

    report_lines = [
        "HAL-OS Phase 0 E2E Report",
        f"FreeBSD Version: {args.freebsd_version}",
        f"Acceleration:    {accel} ({cpu_model})",
        f"Elapsed Seconds: {time.monotonic() - t_start:.1f}",
        f"Init Exit Code:  {init_rc}",
        f"Verify ExitCode: {verify_rc}",
        f"OOB SSH Exit:    {ssh_res.returncode}",
        f"Overall Status:  {'PASS' if overall_ok else 'FAIL'}",
        "",
        "--- phase0-verify.sh output ---",
        verify_out.strip(),
        "",
        "--- OOB SSH stdout ---",
        ssh_res.stdout.strip(),
    ]
    report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    print(f"Report written to {report_path}")
    if not overall_ok:
        dump_serial_tail(serial_log)
    return 0 if overall_ok else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
