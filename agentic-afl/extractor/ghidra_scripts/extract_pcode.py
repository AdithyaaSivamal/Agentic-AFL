# extract_pcode.py -- Ghidra Headless P-Code Backward Slicer
# pyright: reportUndefinedVariable=false, reportMissingImports=false
# -*- coding: utf-8 -*-
#
# THIS IS A JYTHON (Python 2.7) SCRIPT. It runs INSIDE Ghidra's JVM.
# No f-strings. No type hints. print is a statement.
#
# Invoked by pcode_slicer.py via:
#   analyzeHeadless <project_dir> <project_name> \
#       -import <binary> \
#       -postScript extract_pcode.py <stall_addr> <taint_source> <max_depth> \
#       -deleteProject
#
# Script Arguments (via getScriptArgs() in headless, or askString() dialogs in GUI):
#   [0] stall_address   -- Hex address of the CBRANCH blocking coverage (e.g., "0x08001234")
#   [1] taint_source    -- EITHER a hex memory address (e.g., "0x20001000" for bare-metal)
#                         OR a register name (e.g., "RDI" for x86_64 function args)
#   [2] max_depth       -- Maximum backward traversal depth (e.g., "20")
#
# Output: JSON to stdout, parsed by pcode_slicer.py.
#
# Algorithm: Taint-Bounded Backward Def-Use Traversal
#   Reference: AutoBug Algorithm 2 (GenSlice)
#   Reference: TDD_v2 S4.1 -- Taint bounding prevents memory-state explosion
#
#   1. Decompile the function containing stall_address via DecompInterface.
#   2. Find the PcodeOpAST at or near the stall_address (the CBRANCH sink).
#   3. For each input Varnode of the sink, recursively call getDef() to find
#      the PcodeOp that produced it.
#   4. TAINT BOUND: When we encounter a LOAD operation, check the pointer:
#      - If the pointer resolves to the taint_source region -> TAINTED (include)
#      - If the pointer resolves to a different region -> UNTAINTED (prune)
#      This single check prevents the slice from exploding into OS timer
#      logic, global config reads, and other irrelevant firmware state.
#   5. Collect all included PcodeOps and emit as JSON.
#
# Danger Zones (from Gemini review):
#   - LOAD pointers: A LOAD's address input may itself be computed. If the
#     pointer is a register holding a value computed from tainted input, the
#     LOAD is transitively tainted. We track this via the visited set.
#   - Loop detection: P-Code has no explicit loop labels. Back-edges are
#     detected by checking if a Varnode's defining PcodeOp has already been
#     visited (cycle in the Def-Use graph).
#   - PHI nodes: In SSA form, PHI nodes merge values from different control
#     flow paths. We trace ALL inputs of PHI nodes (both paths matter).

import json
import sys

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.pcode import PcodeOp
from ghidra.util.task import ConsoleTaskMonitor


# =========================================================================
# Constants
# =========================================================================

# P-Code opcodes we care about for classification.
# Full list: ghidra.program.model.pcode.PcodeOp
OPCODE_NAMES = {
    PcodeOp.UNIMPLEMENTED: "UNIMPLEMENTED",
    PcodeOp.COPY:          "COPY",
    PcodeOp.LOAD:          "LOAD",
    PcodeOp.STORE:         "STORE",
    PcodeOp.BRANCH:        "BRANCH",
    PcodeOp.CBRANCH:       "CBRANCH",
    PcodeOp.BRANCHIND:     "BRANCHIND",
    PcodeOp.CALL:          "CALL",
    PcodeOp.CALLIND:       "CALLIND",
    PcodeOp.CALLOTHER:     "CALLOTHER",
    PcodeOp.RETURN:        "RETURN",
    PcodeOp.INT_EQUAL:     "INT_EQUAL",
    PcodeOp.INT_NOTEQUAL:  "INT_NOTEQUAL",
    PcodeOp.INT_SLESS:     "INT_SLESS",
    PcodeOp.INT_SLESSEQUAL:"INT_SLESSEQUAL",
    PcodeOp.INT_LESS:      "INT_LESS",
    PcodeOp.INT_LESSEQUAL: "INT_LESSEQUAL",
    PcodeOp.INT_ZEXT:      "INT_ZEXT",
    PcodeOp.INT_SEXT:      "INT_SEXT",
    PcodeOp.INT_ADD:       "INT_ADD",
    PcodeOp.INT_SUB:       "INT_SUB",
    PcodeOp.INT_CARRY:     "INT_CARRY",
    PcodeOp.INT_SCARRY:    "INT_SCARRY",
    PcodeOp.INT_SBORROW:   "INT_SBORROW",
    PcodeOp.INT_2COMP:     "INT_2COMP",
    PcodeOp.INT_NEGATE:    "INT_NEGATE",
    PcodeOp.INT_XOR:       "INT_XOR",
    PcodeOp.INT_AND:       "INT_AND",
    PcodeOp.INT_OR:        "INT_OR",
    PcodeOp.INT_LEFT:      "INT_LEFT",
    PcodeOp.INT_RIGHT:     "INT_RIGHT",
    PcodeOp.INT_SRIGHT:    "INT_SRIGHT",
    PcodeOp.INT_MULT:      "INT_MULT",
    PcodeOp.INT_DIV:       "INT_DIV",
    PcodeOp.INT_SDIV:      "INT_SDIV",
    PcodeOp.INT_REM:       "INT_REM",
    PcodeOp.INT_SREM:      "INT_SREM",
    PcodeOp.BOOL_NEGATE:   "BOOL_NEGATE",
    PcodeOp.BOOL_XOR:      "BOOL_XOR",
    PcodeOp.BOOL_AND:      "BOOL_AND",
    PcodeOp.BOOL_OR:       "BOOL_OR",
    PcodeOp.MULTIEQUAL:    "MULTIEQUAL",   # PHI node in SSA
    PcodeOp.INDIRECT:      "INDIRECT",
    PcodeOp.PTRADD:        "PTRADD",
    PcodeOp.PTRSUB:        "PTRSUB",
    PcodeOp.CAST:          "CAST",
    PcodeOp.PIECE:         "PIECE",
    PcodeOp.SUBPIECE:      "SUBPIECE",
}


# =========================================================================
# Varnode Helpers
# =========================================================================

def varnode_to_str(vn):
    """
    Convert a Varnode to a human-readable string with SSA disambiguation.

    CRITICAL FIX: Ghidra's high P-Code uses SSA internally, but
    getRegister().getName() strips the SSA version, causing two different
    versions of the same register (e.g., AX_from_crc vs AX_from_packet)
    to render as identical strings. This makes the LLM generate
    tautologies like 'AX == AX' instead of 'AX_crc == AX_packet'.

    We fix this by appending the address of the PcodeOp that DEFINED
    this Varnode. This acts as a lightweight SSA version tag:
      AX          -> AX@101222  (the CRC result)
      AX          -> AX@101236  (the received CRC field)
    """
    if vn is None:
        return "None"
    space = vn.getAddress().getAddressSpace().getName()
    offset = "0x%x" % vn.getOffset()
    size = vn.getSize()

    # SSA suffix: append the defining op's address to disambiguate.
    ssa_suffix = ""
    def_op = vn.getDef()
    if def_op is not None:
        ssa_suffix = "@%x" % def_op.getSeqnum().getTarget().getOffset()

    if vn.isConstant():
        return "(const, %s, %d)" % (offset, size)
    if vn.isRegister():
        reg = currentProgram.getRegister(vn)
        name = reg.getName() if reg else "reg_%s" % offset
        return "(register, %s%s, %d)" % (name, ssa_suffix, size)
    if vn.isUnique():
        return "(unique, %s%s, %d)" % (offset, ssa_suffix, size)
    return "(%s, %s, %d)" % (space, offset, size)


def parse_taint_source(taint_source_str):
    """
    Parse the taint_source argument into a config dict.

    Supports two formats:
      - Hex address: "0x20001000" -> {"mode": "address", "start": 0x20001000}
        Used for bare-metal firmware where the input buffer is at a fixed SRAM address.
      - Register name: "RDI" or "r0" -> {"mode": "register", "name": "RDI"}
        Used for x86_64/ARM where the input is passed as a function argument register.

    Returns:
        Dict with "mode" key and mode-specific fields.
    """
    s = taint_source_str.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return {"mode": "address", "start": int(s, 16), "size": 0x1000}
    elif s.isdigit():
        return {"mode": "address", "start": int(s), "size": 0x1000}
    else:
        # Treat as register name (e.g., "RDI", "r0", "RSI")
        return {"mode": "register", "name": s.upper()}


def is_in_taint_region(vn, taint_config):
    """
    Check if a Varnode is tainted (connected to the input buffer).

    This is the TAINT BOUND check. When we encounter a LOAD, we check
    if the pointer being dereferenced points into the input buffer region
    or originates from a tainted register (function argument).

    Two modes:
      - Address mode: Check if a constant pointer falls in [start, start+size).
        For bare-metal firmware with fixed input buffer addresses.
      - Register mode: Check if a register Varnode matches the taint register.
        For x86_64/ARM where the input is passed via RDI/r0.

    Args:
        vn:           The address Varnode from a LOAD operation.
        taint_config: Dict from parse_taint_source().

    Returns:
        True  -- Varnode IS tainted (include this LOAD in the slice).
        False -- Varnode is definitely NOT tainted (prune this branch).
        None  -- Cannot determine statically (trace further backward).
    """
    if vn is None:
        return False

    mode = taint_config["mode"]

    if mode == "address":
        # Address mode: check constant pointers against the taint region.
        if vn.isConstant():
            addr = vn.getOffset()
            start = taint_config["start"]
            size = taint_config["size"]
            return start <= addr < (start + size)
        # If the pointer is a register/unique, check register mode fallback.
        if vn.isRegister():
            # In address mode, a register pointer means it was computed.
            # Return None to signal "trace further" -- the computation
            # chain may eventually resolve to a constant in the taint region.
            return None
        # Unique temp -- trace further.
        return None

    elif mode == "register":
        # Register mode: the taint source is a function argument register.
        # A Varnode IS tainted if it matches the taint register name.
        if vn.isRegister():
            reg = currentProgram.getRegister(vn)
            if reg:
                reg_name = reg.getName().upper()
                taint_name = taint_config["name"]
                # Check exact match or parent register match.
                # E.g., if taint is "RDI", also match "EDI", "DI", "DIL"
                # because they are sub-registers of the same physical register.
                parent = reg.getBaseRegister()
                parent_name = parent.getName().upper() if parent else reg_name
                if reg_name == taint_name or parent_name == taint_name:
                    return True
            # Register exists but doesn't match taint register.
            # Don't prune -- it may be derived FROM the taint register.
            return None
        if vn.isConstant():
            # In register mode, a constant pointer is NOT from the input.
            return False
        # Unique temp -- trace further.
        return None

    return None


# =========================================================================
# Backward Def-Use Slicer
# =========================================================================

def backward_slice(sink_op, taint_config, max_depth):
    """
    Perform taint-bounded backward Def-Use traversal from a sink PcodeOp.

    Starting from the sink (typically a CBRANCH), recursively trace each
    input Varnode's defining PcodeOp. Stop when:
      - max_depth is exceeded (truncation via assuming(0)).
      - A Varnode has no defining op (it's a function input/parameter).
      - A LOAD dereferences a pointer OUTSIDE the taint region (PRUNE).
      - A cycle is detected (Varnode already in visited set -- loop).

    Args:
        sink_op:      The PcodeOpAST at the stall address (the CBRANCH).
        taint_config: Taint configuration dict from parse_taint_source().
        max_depth:    Maximum backward traversal depth.

    Returns:
        Tuple of (slice_ops, was_truncated, pruned_loads):
          - slice_ops:     List of PcodeOpAST in the backward slice.
          - was_truncated: True if max_depth was hit.
          - pruned_loads:  List of pruned LOAD descriptions (for logging).
    """
    slice_ops = []
    visited = set()       # Set of PcodeOp unique IDs (avoid cycles)
    pruned_loads = []
    was_truncated = False

    # BFS worklist: (pcode_op, current_depth)
    worklist = [(sink_op, 0)]

    while worklist:
        op, depth = worklist.pop(0)

        if op is None:
            continue

        # Unique ID for cycle detection.
        # CRITICAL: Use (address, seqnum_time) not just address.
        # Multiple P-Code ops can share the same machine instruction address
        # (e.g., an INT_SUB and INT_LESS both at 0x101259 from a single CMP).
        # Using address alone causes false collisions that kill the slice.
        seq = op.getSeqnum()
        op_id = (seq.getTarget().getOffset(), seq.getTime())
        if op_id in visited:
            continue
        visited.add(op_id)

        # Depth check -- truncation (AutoBug assuming(0)).
        if depth > max_depth:
            was_truncated = True
            continue

        # Record this op in the slice.
        slice_ops.append(op)

        opcode = op.getOpcode()

        # --- TAINT BOUND at LOAD operations ---
        # LOAD has inputs: [address_space_id, pointer_varnode]
        # We check if the pointer points into the taint region.
        if opcode == PcodeOp.LOAD:
            if op.getNumInputs() >= 2:
                ptr_vn = op.getInput(1)  # The pointer being dereferenced
                taint_check = is_in_taint_region(ptr_vn, taint_config)

                if taint_check is False:
                    # Pointer is a constant OUTSIDE taint region -> PRUNE.
                    # This is the key optimization: without this check, we'd
                    # trace into global timer state, config tables, etc.
                    pruned_loads.append(
                        "PRUNED LOAD at 0x%x: pointer %s outside taint region" %
                        (op.getSeqnum().getTarget().getOffset(), varnode_to_str(ptr_vn))
                    )
                    continue  # Do NOT trace this LOAD's inputs further.

                # taint_check is True or None (computed pointer).
                # If True: pointer is in taint region, include and continue.
                # If None: pointer is computed, trace further to determine.

        # --- CALL handling ---
        # Record the CALL with its resolved function name (done in
        # pcode_op_to_dict) but don't trace into the callee's P-Code.
        # The decompiled C extraction (below) provides the LLM with
        # the callee's algorithm in readable C form instead.
        if opcode in (PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.CALLOTHER):
            continue

        # --- Trace all input Varnodes backward ---
        for i in range(op.getNumInputs()):
            input_vn = op.getInput(i)
            if input_vn is None:
                continue

            # Skip constants (they have no defining op).
            if input_vn.isConstant():
                continue

            # Get the defining PcodeOp for this input Varnode.
            def_op = input_vn.getDef()
            if def_op is not None:
                worklist.append((def_op, depth + 1))

    return slice_ops, was_truncated, pruned_loads


# Global ref set by main() so backward_slice can access the sink's function.
func_containing_sink = None


def _inline_callee(callee_func, taint_config, remaining_depth, parent_visited):
    """
    Decompile a callee and extract its P-Code ops for inlining.

    Only goes 1 level deep (no recursive inlining of sub-callees).
    Returns a list of PcodeOpAST from the callee's body.
    """
    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    options = DecompileOptions()
    ifc.setOptions(options)
    ifc.openProgram(currentProgram)

    results = ifc.decompileFunction(callee_func, 30, monitor)
    if not results.decompileCompleted():
        return []

    high_func = results.getHighFunction()
    if high_func is None:
        return []

    # Collect ALL P-Code ops from the callee (no sink-specific slicing,
    # since we want the full algorithm body for the LLM).
    callee_ops = []
    for op in high_func.getPcodeOps():
        seq = op.getSeqnum()
        op_id = (seq.getTarget().getOffset(), seq.getTime())
        if op_id not in parent_visited:
            parent_visited.add(op_id)
            callee_ops.append(op)

    return callee_ops


# =========================================================================
# PcodeOp -> JSON Serialization
# =========================================================================

def pcode_op_to_dict(op):
    """Serialize a PcodeOpAST to a JSON-compatible dictionary."""
    opcode = op.getOpcode()
    mnemonic = OPCODE_NAMES.get(opcode, "UNKNOWN_%d" % opcode)

    inputs = []
    for i in range(op.getNumInputs()):
        vn = op.getInput(i)
        inputs.append(varnode_to_str(vn))

    # -- CALL target resolution --
    # Replace raw RAM addresses with function names so the LLM can
    # leverage its training data. "CALL 0x1011c2" means nothing;
    # "CALL crc16_modbus" triggers the LLM's CRC knowledge.
    call_target_name = None
    if opcode in (PcodeOp.CALL, PcodeOp.CALLIND) and op.getNumInputs() > 0:
        target_vn = op.getInput(0)
        try:
            target_offset = target_vn.getAddress().getOffset()
            addr_space = currentProgram.getAddressFactory().getDefaultAddressSpace()
            target_ghidra_addr = addr_space.getAddress(target_offset)
            func_at_target = getFunctionAt(target_ghidra_addr)
            if func_at_target:
                call_target_name = func_at_target.getName()
                inputs[0] = "(func, %s, 0x%x)" % (call_target_name, target_offset)
        except Exception:
            pass  # Keep the raw address if resolution fails

    output_vn = op.getOutput()
    output_str = varnode_to_str(output_vn) if output_vn else None

    addr = "0x%x" % op.getSeqnum().getTarget().getOffset()

    # Build the raw P-Code text line (mimics Ghidra's P-Code display).
    if output_str:
        raw = "%s = %s %s" % (output_str, mnemonic, " ".join(inputs))
    else:
        raw = "%s %s" % (mnemonic, " ".join(inputs))

    result = {
        "address": addr,
        "mnemonic": mnemonic,
        "inputs": inputs,
        "output": output_str,
        "raw_pcode": raw,
    }

    # Include the resolved function name as a top-level field for easy access.
    if call_target_name:
        result["call_target"] = call_target_name

    return result


# =========================================================================
# Main Entry Point
# =========================================================================

def _count_backward_fanin(op, max_depth=15):
    """
    Count the backward def-use fan-in depth of a PcodeOp.

    This estimates the "complexity" of the data dependency chain feeding
    into a comparison. A trivial `len < 12` check has depth ~2.
    A CRC comparison has depth 10-20+ (loop body + table lookups).

    Returns:
        Integer depth count.
    """
    visited = set()
    count = 0
    worklist = [(op, 0)]

    while worklist:
        curr, depth = worklist.pop(0)
        if curr is None or depth > max_depth:
            continue

        seq = curr.getSeqnum()
        op_id = (seq.getTarget().getOffset(), seq.getTime())
        if op_id in visited:
            continue
        visited.add(op_id)
        count += 1

        # Skip CALL targets -- don't trace into callees.
        if curr.getOpcode() in (PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.CALLOTHER):
            continue

        for i in range(curr.getNumInputs()):
            inp = curr.getInput(i)
            if inp is not None and not inp.isConstant():
                def_op = inp.getDef()
                if def_op is not None:
                    worklist.append((def_op, depth + 1))

    return count


def find_cbranch_at_address(high_function, target_addr):
    """
    Find the most relevant CBRANCH PcodeOp for the given target address.

    Strategy:
      - If the target address is close to a CBRANCH/comparison op, pick it
        (original nearest-by-address behavior for precise stall addresses).
      - If the target address equals the function entry point, or if the
        nearest match is a trivially shallow comparison, switch to a
        "deepest CBRANCH" heuristic: score every CBRANCH in the function
        by its backward def-use fan-in depth and pick the most complex one.
        This ensures we select the CRC/hash comparison over a trivial
        length guard or NULL check at the function entry.
    """
    func_entry = high_function.getFunction().getEntryPoint().getOffset()
    is_entry_point = (target_addr == func_entry)

    # Collect ALL comparison/branch ops in the function.
    all_comparisons = []   # (op, distance_to_target)
    all_cbranches = []     # (op, distance_to_target)

    for op in high_function.getPcodeOps():
        op_addr = op.getSeqnum().getTarget().getOffset()
        distance = abs(op_addr - target_addr)
        opcode = op.getOpcode()

        if opcode == PcodeOp.CBRANCH:
            all_cbranches.append((op, distance))
        elif opcode in (PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL,
                         PcodeOp.INT_LESS, PcodeOp.INT_SLESS,
                         PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESSEQUAL):
            all_comparisons.append((op, distance))

    # If the target is a precise address (not function entry), use the
    # original nearest-by-address logic -- but verify the result isn't
    # trivially shallow.
    if not is_entry_point:
        candidates = all_cbranches + all_comparisons
        if candidates:
            # Prefer CBRANCH over comparison at same distance.
            candidates.sort(key=lambda x: (x[1], 0 if x[0].getOpcode() == PcodeOp.CBRANCH else 1))
            nearest = candidates[0][0]
            fanin = _count_backward_fanin(nearest)
            if fanin >= 5:
                # Reasonably complex -- use it.
                return nearest
            # Otherwise fall through to deepest-CBRANCH heuristic.
            printerr("  WARNING: Nearest comparison at 0x%x has shallow fan-in (%d), searching for deeper sink..." %
                      (nearest.getSeqnum().getTarget().getOffset(), fanin))

    # --- Deepest-CBRANCH heuristic ---
    # Score every CBRANCH by its backward data dependency depth.
    # Pick the one with the most complex constraint chain.
    best_op = None
    best_score = -1

    candidates = all_cbranches if all_cbranches else all_comparisons
    for op, _ in candidates:
        score = _count_backward_fanin(op)
        if score > best_score:
            best_score = score
            best_op = op

    if best_op:
        printerr("  Selected deepest CBRANCH at 0x%x with fan-in score %d" %
                  (best_op.getSeqnum().getTarget().getOffset(), best_score))

    return best_op


def main():
    # --- Parse script arguments (dual-mode: headless vs GUI) ---
    args = getScriptArgs()

    if args and len(args) >= 3:
        # HEADLESS MODE: arguments passed via analyzeHeadless command line.
        stall_addr_str = args[0]
        taint_source_str = args[1]
        max_depth_str = args[2]
    else:
        # GUI MODE: use Ghidra's ask dialogs for interactive input.
        # The Script Manager cannot pass command-line arguments, so we
        # pop up dialog boxes instead.
        try:
            stall_addr_str = askString(
                "Agentic-AFL Slicer",
                "Stall address (hex, e.g. 0x001011b7):",
                "0x001011b7"
            )
            taint_source_str = askString(
                "Agentic-AFL Slicer",
                "Taint source (hex addr e.g. 0x20001000, or register e.g. RDI):",
                "RDI"
            )
            max_depth_str = askString(
                "Agentic-AFL Slicer",
                "Max backward traversal depth:",
                "20"
            )
        except Exception:
            print("Script cancelled by user.")
            return

    stall_addr = int(stall_addr_str, 16)
    taint_config = parse_taint_source(taint_source_str)
    max_depth = int(max_depth_str)

    # --- Initialize Decompiler ---
    monitor = ConsoleTaskMonitor()
    options = DecompileOptions()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(currentProgram)

    # --- Find the function containing the stall address ---
    addr_factory = currentProgram.getAddressFactory()
    addr_space = addr_factory.getDefaultAddressSpace()
    ghidra_addr = addr_space.getAddress(stall_addr)
    func = getFunctionContaining(ghidra_addr)

    # --- PIE/ASLR rebasing ---
    # If the binary is a PIE (Position-Independent Executable), nm reports
    # file offsets (e.g., 0x6000) but Ghidra loads at a base address
    # (e.g., 0x100000). We detect this and rebase the address.
    if func is None:
        image_base = currentProgram.getImageBase().getOffset()
        if image_base != 0:
            rebased_addr = stall_addr + image_base
            printerr("  PIE detected: rebasing 0x%x + base 0x%x = 0x%x" %
                      (stall_addr, image_base, rebased_addr))
            ghidra_addr = addr_space.getAddress(rebased_addr)
            func = getFunctionContaining(ghidra_addr)

    # --- Fallback: scan the symbol table ---
    # If address-based lookup still fails (e.g., Ghidra didn't auto-detect
    # function boundaries due to AFL instrumentation), scan all functions
    # for one whose entry point matches the stall address (with or without
    # image base offset).
    if func is None:
        printerr("  Address lookup failed -- scanning symbol table...")
        func_mgr = currentProgram.getFunctionManager()
        image_base = currentProgram.getImageBase().getOffset()
        for candidate in func_mgr.getFunctions(True):
            entry = candidate.getEntryPoint().getOffset()
            # Match against both raw address and rebased address
            if entry == stall_addr or entry == (stall_addr + image_base):
                func = candidate
                ghidra_addr = candidate.getEntryPoint()
                printerr("  Found via symbol scan: %s @ 0x%x" %
                          (candidate.getName(), entry))
                break

    # --- Last resort: try to create a function at the (rebased) address ---
    if func is None:
        image_base = currentProgram.getImageBase().getOffset()
        for try_addr in [stall_addr, stall_addr + image_base]:
            try_ghidra_addr = addr_space.getAddress(try_addr)
            printerr("  Attempting createFunction at 0x%x..." % try_addr)
            try:
                createFunction(try_ghidra_addr, None)
                func = getFunctionContaining(try_ghidra_addr)
                if func is not None:
                    ghidra_addr = try_ghidra_addr
                    printerr("  Created function at 0x%x" % try_addr)
                    break
            except Exception as e:
                printerr("  createFunction(0x%x) failed: %s" % (try_addr, str(e)))

    if func is None:
        result = {
            "error": "No function found at address 0x%x (image_base=0x%x)" %
                     (stall_addr, currentProgram.getImageBase().getOffset()),
            "function_name": None,
            "function_entry": None,
            "instructions": [],
        }
        # Use a marker prefix so pcode_slicer.py can find the JSON in stdout.
        print("===PCODE_JSON_START===")
        print(json.dumps(result, indent=2))
        print("===PCODE_JSON_END===")
        return

    # --- Decompile the function ---
    results = ifc.decompileFunction(func, 60, monitor)

    if not results.decompileCompleted():
        result = {
            "error": "Decompilation failed: %s" % results.getErrorMessage(),
            "function_name": func.getName(),
            "function_entry": "0x%x" % func.getEntryPoint().getOffset(),
            "instructions": [],
        }
        print("===PCODE_JSON_START===")
        print(json.dumps(result, indent=2))
        print("===PCODE_JSON_END===")
        return

    high_function = results.getHighFunction()

    # --- Find the sink (CBRANCH at stall address) ---
    sink_op = find_cbranch_at_address(high_function, stall_addr)

    if sink_op is None:
        # Fallback: dump ALL P-Code ops in the function for debugging.
        all_ops = []
        for op in high_function.getPcodeOps():
            all_ops.append(pcode_op_to_dict(op))

        result = {
            "error": "No CBRANCH/comparison found near 0x%x" % stall_addr,
            "function_name": func.getName(),
            "function_entry": "0x%x" % func.getEntryPoint().getOffset(),
            "instructions": all_ops,
            "note": "Dumped all %d P-Code ops in function for debugging." % len(all_ops),
        }
        print("===PCODE_JSON_START===")
        print(json.dumps(result, indent=2))
        print("===PCODE_JSON_END===")
        return

    # Set global so backward_slice can avoid re-entering the sink's own function.
    global func_containing_sink
    func_containing_sink = func

    # --- Perform backward slice ---
    slice_ops, was_truncated, pruned_loads = backward_slice(
        sink_op, taint_config, max_depth
    )

    # --- Sort slice by address (ascending) for readability ---
    slice_ops.sort(key=lambda op: op.getSeqnum().getTarget().getOffset())

    # --- Extract decompiled C pseudocode ---
    decompiled_c = ""
    try:
        c_code = results.getDecompiledFunction()
        if c_code:
            decompiled_c = c_code.getC()
            printerr("  Decompiled C: %d chars extracted" % len(decompiled_c))
        else:
            printerr("  Decompiled C: getDecompiledFunction() returned None")
    except Exception as e:
        printerr("  Decompiled C extraction failed: %s" % str(e))

    # --- Serialize slice to instruction dicts ---
    instructions = [pcode_op_to_dict(op) for op in slice_ops]

    # --- Also decompile callees mentioned in the slice ---
    callee_c_sections = []
    seen_callees = set()
    for instr_dict in instructions:
        ct_name = instr_dict.get("call_target")
        if ct_name and ct_name not in seen_callees:
            seen_callees.add(ct_name)
            try:
                # Extract address from the input field: "(func, name, 0xADDR)"
                input0 = instr_dict.get("inputs", [""])[0]
                if input0.startswith("(func,"):
                    parts = input0.rstrip(")").split(",")
                    addr_str = parts[-1].strip()
                    callee_addr = int(addr_str, 16)
                    addr_space = currentProgram.getAddressFactory().getDefaultAddressSpace()
                    ghidra_callee_addr = addr_space.getAddress(callee_addr)
                    cf = getFunctionAt(ghidra_callee_addr)
                    if cf:
                        cr = ifc.decompileFunction(cf, 30, monitor)
                        if cr.decompileCompleted():
                            cc = cr.getDecompiledFunction()
                            if cc:
                                callee_c_sections.append({
                                    "name": ct_name,
                                    "c_code": cc.getC(),
                                })
                                printerr("  Callee C: %s (%d chars)" % (ct_name, len(cc.getC())))
            except Exception as e:
                printerr("  Callee C extraction failed for %s: %s" % (ct_name, str(e)))

    # --- CALLER CONTEXT EXPANSION ---
    # When the stall address equals the function's entry point, it means we
    # are targeting a callee function (e.g., checkSequenceNumber) rather than
    # a branch within the caller (e.g., checkMessage). The callee's decompiled
    # C shows the constraint algorithm but NOT how input buffer bytes are parsed
    # into function arguments. The CALLER's C shows that byte-to-parameter mapping.
    #
    # Strategy: Use getReferencesTo(entry_point) to find call sites, then
    # decompile the containing function. Limit to first 3 callers to avoid
    # context pollution.
    caller_c_sections = []
    func_entry = func.getEntryPoint()
    is_entry_stall = (stall_addr == func_entry.getOffset())

    if is_entry_stall:
        printerr("  Stall at function entry -- searching for callers...")
        try:
            refs = getReferencesTo(func_entry)
            caller_funcs_seen = set()
            for ref in refs:
                if len(caller_c_sections) >= 3:
                    break
                from_addr = ref.getFromAddress()
                caller_func = getFunctionContaining(from_addr)
                if caller_func is None:
                    continue
                caller_name = caller_func.getName()
                if caller_name in caller_funcs_seen:
                    continue
                caller_funcs_seen.add(caller_name)

                try:
                    cr = ifc.decompileFunction(caller_func, 30, monitor)
                    if cr.decompileCompleted():
                        cc = cr.getDecompiledFunction()
                        if cc:
                            caller_c_sections.append({
                                "name": caller_name,
                                "c_code": cc.getC(),
                            })
                            printerr("  Caller C: %s (%d chars)" % (caller_name, len(cc.getC())))
                except Exception as e:
                    printerr("  Caller C extraction failed for %s: %s" % (caller_name, str(e)))
        except Exception as e:
            printerr("  Caller resolution failed (indirect call?): %s" % str(e))

    result = {
        "error": None,
        "function_name": func.getName(),
        "function_entry": "0x%x" % func.getEntryPoint().getOffset(),
        "stall_address": "0x%x" % stall_addr,
        "taint_source": taint_source_str,
        "taint_mode": taint_config["mode"],
        "slice_depth": max_depth,
        "instruction_count": len(instructions),
        "was_truncated": was_truncated,
        "pruned_loads": pruned_loads,
        "instructions": instructions,
        "decompiled_c": decompiled_c,
        "callee_c": callee_c_sections,
        "caller_c": caller_c_sections,
    }

    print("===PCODE_JSON_START===")
    print(json.dumps(result, indent=2))
    print("===PCODE_JSON_END===")

    # --- Summary to stderr (visible in Ghidra console, not captured by pcode_slicer.py) ---
    printerr("Backward slice from 0x%x in %s:" % (stall_addr, func.getName()))
    printerr("  Instructions in slice: %d" % len(instructions))
    printerr("  Truncated: %s" % was_truncated)
    printerr("  Pruned LOADs: %d" % len(pruned_loads))
    for msg in pruned_loads:
        printerr("    %s" % msg)


# Ghidra Jython entry point.
main()
