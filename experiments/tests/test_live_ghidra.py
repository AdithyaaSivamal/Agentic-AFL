"""
test_live_ghidra.py — Stage 2: Live Ghidra Headless Integration Test.

Runs the PCodeSlicer against the compiled math_wall_x86 test binary.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agentic_afl.extractor.pcode_slicer import PCodeSlicer
from agentic_afl.constants import Architecture

def main():
    binary = Path(__file__).resolve().parents[1] / "test_targets" / "math_wall_x86"
    if not binary.exists():
        print(f"Test binary not found: {binary}")
        return

    # In math_wall_x86, the input buffer is passed in RDI.
    # The stall in check_magic is at the comparison against 0x5A01 (0x11b7).
    # Since it's a PIE binary, Ghidra loads it at 0x100000 base, so address is 0x1011b7.
    stall_address = "0x1011b7"
    taint_source = "RDI"

    slicer = PCodeSlicer(architecture=Architecture.X86_64, max_slice_depth=20)
    
    print(f"Running Ghidra headless P-Code extraction on {binary.name} @ {stall_address}...")
    try:
        slice_result = slicer.extract_slice(
            binary_path=binary,
            stall_address=stall_address,
            taint_source=taint_source
        )
        print("\nSUCCESS! Extracted P-Code:")
        print(f"Function: {slice_result.function_name} @ {slice_result.function_entry}")
        print(f"Instructions ({len(slice_result.instructions)}):")
        for inst in slice_result.instructions:
            print(f"  {inst.address}: {inst.raw_pcode}")
            
    except Exception as e:
        print(f"\nFAILED: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
