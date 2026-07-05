# QEMU Mode Support + fwupgrade Target Setup

## Part 1: Add QEMU Mode to CLI & Campaign Runner

### Problem
The current `campaign.py` hardcodes `afl-fuzz -M default ... -- binary @@` with no QEMU flag. For ARM/MIPS firmware targets, AFL++ needs:
- `-Q` flag to invoke `afl-qemu-trace` instead of direct execution
- `QEMU_LD_PREFIX` environment variable pointing to the firmware's sysroot
- `AFL_QEMU_CUSTOM_BIN` (optional) if the afl-qemu-trace was built for a specific architecture

### Proposed Changes

#### [MODIFY] [cli.py](file:///home/adi/Documents/IoT_Lab/Agentic-AFL/whiteboard/Agentic-AFL-dev/agentic_afl/cli.py)
- Add `--qemu` flag to fuzz subparser (enables `-Q` for afl-fuzz)
- Add `--qemu-sysroot` argument (sets `QEMU_LD_PREFIX`)
- Pass both to `CampaignRunner`
- Display in banner

#### [MODIFY] [campaign.py](file:///home/adi/Documents/IoT_Lab/Agentic-AFL/whiteboard/Agentic-AFL-dev/agentic_afl/campaign.py)
- `_start_afl()`: Accept `qemu_mode` bool and `qemu_sysroot` path parameters
- When `qemu_mode=True`: insert `-Q` into the afl-fuzz command
- When `qemu_sysroot`: set `QEMU_LD_PREFIX` in the environment
- `CampaignRunner.__init__()`: Accept `qemu_mode` and `qemu_sysroot` parameters

---

## Part 2: Build afl-qemu-trace for ARM

### Current State
Your system has AFL++ 4.40c installed with `afl-qemu-trace` built for **x86_64 only**. For ARM32 firmware targets, we need to build the QEMU mode for ARM.

> [!IMPORTANT]
> **Required step (manual):** Build AFL++ QEMU mode with `CPU_TARGET=arm`. This takes ~5-10 minutes.
>
> ```bash
> # Clone AFL++ source
> cd /home/adi/Documents/IoT_Lab/Agentic-AFL/whiteboard
> git clone --depth=1 https://github.com/AFLplusplus/AFLplusplus.git
> cd AFLplusplus
> 
> # Build QEMU mode for ARM
> cd qemu_mode
> CPU_TARGET=arm ./build_qemu_support.sh
> 
> # The output is: AFLplusplus/afl-qemu-trace
> # Copy it somewhere accessible
> cp ../afl-qemu-trace /usr/local/bin/afl-qemu-trace-arm
> ```
>
> Then use: `--qemu --qemu-bin /usr/local/bin/afl-qemu-trace-arm`

### Alternative: Use QEMU User Mode Directly

If building AFL++ QEMU is too heavy, we can use vanilla `qemu-arm` with AFL++'s `AFL_NO_FORKSRV=1` (much slower but works immediately). This is the **quick-start path** for initial validation.

---

## Part 3: fwupgrade Target Setup

### The fw_printenv Problem

`fwupgrade` calls `popen("/usr/sbin/fw_printenv bootbank")` as a subprocess. Under QEMU user-mode, this subprocess call executes a shell script on the host, which can't resolve the ARM sysroot properly. 

**Workaround:** Create a host-native `fw_printenv` shell script in the sysroot that echoes `bootbank=0`. When QEMU user-mode runs `popen()`, the child process inherits the `PATH` from the host (not the sysroot), so we need to place the script where the host shell can find it, OR we mock `/proc/cmdline` properly and let the binary fall through to the kernel-cmdline-based bootbank detection.

> [!IMPORTANT]
> **Alternative approach:** Instead of fighting `fwupgrade`'s boot initialization, we can **patch the binary** to skip the bootbank check. Since it's stripped, we'd NOP out the `fw_printenv` call branch using `patchelf` or a small binary patcher. This is standard practice for firmware fuzzing research.

### Sysroot Layout
```
fwupgrade_sysroot/
├── bin/fwupgrade           (from UBIFS extraction, chmod +x)
├── lib/                    (glibc 2.17 ARM + libssl + libcrypto)
├── usr/lib/                (libltrxlog, libltrxipc, libsecurity, libzmq)
├── usr/sbin/fw_printenv    (mock: echo "bootbank=0")
├── proc/mtd                (mock MTD partition table)
├── proc/cmdline            (mock: root=/dev/mtdblock2 bootbank=0)
├── run/fw_printenv.lock    (empty file)
├── dev/mtd{0-7}            (zero-filled mock devices)
└── tmp/                    (writable temp directory)
```

### Seed Corpus

We have the real SGX5150 firmware (48MB). Extract the header structure for seeds:

```bash
# Seed 1: First 256 bytes (header only — minimal)
dd if=SGX5150_10.0.0.0R3.signed.rom bs=256 count=1 of=seeds/seed_header_256.bin

# Seed 2: First 4KB (header + start of first image)
dd if=SGX5150_10.0.0.0R3.signed.rom bs=4096 count=1 of=seeds/seed_header_4k.bin

# Seed 3: All zeros (baseline)
dd if=/dev/zero bs=256 count=1 of=seeds/seed_zeros_256.bin

# Seed 4: Random (forces different error paths)
dd if=/dev/urandom bs=256 count=1 of=seeds/seed_random_256.bin
```

---

## Open Questions

> [!IMPORTANT]
> **Q1:** Do you want me to proceed with the binary-patching approach for `fwupgrade` (NOP out the `fw_printenv` call), or should we try the mock sysroot approach first? The patching is more reliable for fuzzing but modifies the binary.

> [!IMPORTANT]
> **Q2:** For the AFL++ QEMU ARM build — do you want me to set up the build script, or would you prefer to install it from your distro's AUR/package manager? On Arch/CachyOS: `yay -S afl++-git` may include QEMU ARM support if built with the right flags.

> [!IMPORTANT]
> **Q3:** Should we also add a `--frida` flag alongside `--qemu`? FRIDA mode (`-O`) is architecture-independent and might be simpler for cross-arch targets, though it requires the FRIDA gadget to be installed.

## Verification Plan

### Automated Tests
1. Run `afl-fuzz -Q` with the ARM sysroot on `fwupgrade` — verify it starts and produces crashes/queue entries
2. Compare edge count at T=5min between AFL++ baseline and Agentic-AFL
3. Check for `HeaderChecksum32` bypass in queue entries

### Manual Verification
- Confirm fwupgrade reads past the header by checking for `"Header %u:"` output in debug logs
- Verify checksum validation error paths are reachable
