"""
Agentic-AFL: Neuro-Symbolic Fuzzing Orchestration for Brownfield ICS Binaries.

This package implements an asynchronous, execution-anchored framework that:
  1. Extracts P-Code slices from stripped binaries via Ghidra headless analysis.
  2. Translates those slices into Z3 SMT solver scripts using an LLM (translator, not solver).
  3. Retrieves relevant historical templates via Constraint-Aware Retrieval (CARM/Jaccard).
  4. Injects solved payloads asynchronously into AFL++ via sync directories.

Architecture Reference: See whiteboard/notes/TDD_v2.md
Literature Basis:       See whiteboard/literature_synthesis.md
"""

__version__ = "0.1.0-dev"
