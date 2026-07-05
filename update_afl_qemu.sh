#!/usr/bin/env bash
# update_afl_qemu.sh
#
# This script updates AFL++ and specifically ensures that QEMU mode (afl-qemu-trace)
# is built with the latest version to avoid the `SIGILL` (Illegal Instruction)
# crashes caused by CET endbr64 instructions on modern glibc.
#
# Target OS: CachyOS / Arch Linux

set -e

echo "[*] Updating CachyOS system and installing dependencies..."
# glib2, ninja, and pixman are explicitly required to compile QEMU mode
sudo pacman -Syu --needed base-devel git python glib2 ninja pixman python-setuptools

echo "[*] Removing any old/conflicting AFL packages via yay..."
yay -Rns afl afl++ aflplusplus afl++-git || true

echo "[*] Cloning the absolute latest AFL++ from source..."
cd /tmp
rm -rf AFLplusplus
git clone https://github.com/AFLplusplus/AFLplusplus.git
cd AFLplusplus

echo "[*] Building AFL++ along with ALL modes (including QEMU & Unicorn)..."
# 'make distrib' is the official way to build the main fuzzer + qemu_mode + frida_mode
# We set NO_NYX=1 and NO_FRIDA=1 to speed up the build if you only care about QEMU
export NO_NYX=1
export NO_FRIDA=1
make distrib

echo "[*] Installing AFL++ globally..."
sudo make install

echo "[*] Verification..."
afl-fuzz -V
afl-qemu-trace -version

echo ""
echo "[+] SUCCESS! AFL++ and QEMU mode have been fully updated."
echo "You can now run Stage 4: afl-fuzz -Q -i /tmp/in -o /tmp/out -- ./libmodbus_harness @@"
