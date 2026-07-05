from agentic_afl.extractor.pcode_slicer import PCodeSlicer
from pathlib import Path

binary_path = Path("libmodbus_harness")
slicer = PCodeSlicer(max_slice_depth=15)
try:
    print(f"Extracting slice for {binary_path} at 0x403abc...")
    result = slicer.extract_slice(binary_path, "0x403abc", "AX")
    print("\nSUCCESS! Extracted P-Code:")
    print(f"Function: {result.function_name} @ {result.function_entry}")
    print(f"Instructions ({len(result.instructions)}):")
    for inst in result.instructions:
        print(f"  {inst.address}: {inst.raw_pcode}")
except Exception as e:
    print(f"Error: {e}")
