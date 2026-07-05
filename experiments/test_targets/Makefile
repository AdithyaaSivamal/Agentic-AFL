# ICS/OT Test Targets — Compilation Matrix
#
# Builds the three ICS test binaries for Phase 1+2 validation.
# Default target: x86_64 (desktop testing).
# Optional: ARM Cortex-M cross-compilation with arm-none-eabi-gcc.

CC_X86    ?= gcc
CC_ARM32  ?= arm-none-eabi-gcc
CFLAGS    ?= -O1 -g -Wall -Wextra
CFLAGS_ARM = -O1 -g -Wall -static -specs=nosys.specs

TARGETS_X86 = modbus_rtu_x86 iec104_apci_x86 modbus_state_x86
TARGETS_ARM = modbus_rtu_arm iec104_apci_arm modbus_state_arm

.PHONY: all x86 arm clean test

all: x86

x86: $(TARGETS_X86)

modbus_rtu_x86: modbus_rtu_slave.c
	$(CC_X86) $(CFLAGS) -o $@ $<

iec104_apci_x86: iec104_apci_parser.c
	$(CC_X86) $(CFLAGS) -o $@ $<

modbus_state_x86: modbus_state_machine.c
	$(CC_X86) $(CFLAGS) -o $@ $<

# ARM targets (optional — requires arm-none-eabi-gcc)
arm: $(TARGETS_ARM)

modbus_rtu_arm: modbus_rtu_slave.c
	$(CC_ARM32) $(CFLAGS_ARM) -o $@ $<

iec104_apci_arm: iec104_apci_parser.c
	$(CC_ARM32) $(CFLAGS_ARM) -o $@ $<

modbus_state_arm: modbus_state_machine.c
	$(CC_ARM32) $(CFLAGS_ARM) -o $@ $<

# Quick validation: create test inputs and run each binary
test: x86
	@echo "=== Modbus RTU (should REJECT: bad TID) ==="
	@printf '\x00\x02\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0A\x00\x00' > /tmp/modbus_test.bin
	@./modbus_rtu_x86 /tmp/modbus_test.bin || true
	@echo ""
	@echo "=== IEC-104 (should REJECT: bad start byte) ==="
	@printf '\x67\x04\x00\x00\x00\x00' > /tmp/iec104_test.bin
	@./iec104_apci_x86 /tmp/iec104_test.bin || true
	@echo ""
	@echo "=== Modbus State Machine (should REJECT: bad magic) ==="
	@printf '\x00\x00\x00\x00' > /tmp/modbus_state_test.bin
	@./modbus_state_x86 /tmp/modbus_state_test.bin || true

clean:
	rm -f $(TARGETS_X86) $(TARGETS_ARM) /tmp/modbus_test.bin /tmp/iec104_test.bin /tmp/modbus_state_test.bin
