# HAL-OS Phase 0 Testbed Runbook (FreeBSD 14 + QEMU/KVM)

This directory contains host and guest provisioning scripts for the **Phase 0** dual-NIC, dual-disk FreeBSD 14 testbed.

## Topology Summary

- **`vtbd0` (`16G`)**: FreeBSD 14.3 ZFS system disk (`zroot` + `bectl` boot environments).
- **`vtbd1` (`32G`)**: Dedicated `halpool` data disk (`halpool/vault` encrypted AES-256-GCM, `workspaces`, `memory`, `jails`, `audit` with `chflags sappnd`).
- **`vtbd2` (`hal-seed.tar`, read-only)**: Offline provisioning bundle carrying `config/` and `vm/freebsd/`.
- **`vtnet0` (`mgmt0`)**: Out-of-band human control plane (`192.168.100.10/24`). Default `user` mode uses QEMU SLIRP with `restrict=on` and forwards host `127.0.0.1:2222 -> 22` and `127.0.0.1:8443 -> 8443` with zero host `sudo` required.
- **`vtnet1` (`wan0`)**: Business egress NIC guarded by PF default-deny (`user _hal_broker` only).

---

## Step-by-Step Bringup

### 1. Fetch & Prepare FreeBSD 14 Disks (on Linux host)
```bash
./vm/fetch-freebsd-image.sh
```

### 2. Build the Offline Seed Bundle
Pass your SSH public key explicitly so `mgmt0` key-only SSH works immediately:
```bash
./vm/build-seed-bundle.sh --ssh-pubkey ~/.ssh/id_ed25519.pub
```

### 3. Boot the VM
```bash
./vm/run-vm.sh
```
*(Optional: use `--net-mode bridge` if you defined `vm/libvirt/hal-mgmt-net.xml` in libvirt, or `--accel tcg` if `/dev/kvm` is unavailable.)*

### 4. Initialize Phase 0 Inside FreeBSD Serial Console
Log in as `root` (default official VM image has no initial password) and run:
```sh
mkdir -p /tmp/hal && tar -xf /dev/vtbd2 -C /tmp/hal
sh /tmp/hal/vm/freebsd/phase0-init.sh
reboot
```

### 5. Verify Spinal Cord & Multi-Agent Isolation (After Reboot)
Log back in via serial console or OOB SSH (`ssh -p 2222 root@127.0.0.1`) and run:
```sh
sh /usr/local/libexec/hal-os/phase0-verify.sh
```
All 5 verification suites (`Spinal Kernel & RCTL`, `PF Default-Deny`, `Encrypted Vault & sappnd Audit`, `Atomic Multi-Dataset ZFS Dual-Snapshot/Rollback`, `Multi-Agent No-IP Jail Isolation`) must report **`PASS`**.

### 6. Installing Rust Inside FreeBSD (Temporary Maintenance Window)
Because `wan0` blocks `root` outbound connections by default, enable the temporary PF maintenance anchor only while installing packages:
```sh
hal-maint-net on
pkg install -y rust git
hal-maint-net off
```
Then sync repository source over `mgmt0` from the host:
```bash
./vm/sync-to-vm.sh
```
