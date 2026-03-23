import angr
import pyvex
from angr.analyses.cdg import CDG, TemporaryNode
from collections import deque
from utils import *

TARGET_BINARY = "examples/sample_001_alias"
OUTPUT_BINARY = "examples/sample_001_alias_patched"
TARGET_FUNC_NAME = "main"


# Patch CDG: _entry defaults to project.entry which may not be in a starts=[main]-only CFG
@staticmethod
def _patched_pd_graph_successors(graph, node):
    if node is None or type(node) is TemporaryNode:
        return iter([])
    return (s for s in graph.model.get_successors(node) if s is not None)
CDG._pd_graph_successors = _patched_pd_graph_successors


def find_store_sites(proj, func):
    """
    Yield (block_addr, store_stmt_idx, store_insn_addr) for every real VEX Store
    in the function.  VEX lifts `call` as a return-address push (STle) — these
    are skipped.  store_insn_addr is the assembly instruction that owns the Store
    (derived from the nearest preceding IMark).
    """
    for block_addr in func.block_addrs:
        irsb = proj.factory.block(block_addr).vex
        block_insns = {i.address: i for i in proj.factory.block(block_addr).capstone.insns}
        current_insn_addr = None
        for i, s in enumerate(irsb.statements):
            if isinstance(s, pyvex.stmt.IMark):
                current_insn_addr = s.addr
            elif isinstance(s, pyvex.stmt.Store):
                asm = block_insns.get(current_insn_addr)
                if asm and asm.mnemonic == 'call':
                    continue
                yield (block_addr, i, current_insn_addr)


def backward_slice_from_store(proj, cfg, ddg, block_addr, store_stmt_idx):
    """
    Return all DDG nodes in the backward slice of a Store statement.
    Seeds from the Store's stmt_idx; falls back to the two preceding stmt indices
    (the WrTmp nodes computing the address) if no DDG node exists at the Store itself.
    """
    candidates = [store_stmt_idx, store_stmt_idx - 1, store_stmt_idx - 2]
    seed_nodes = []
    for idx in candidates:
        seed_nodes = [
            n for n in ddg.graph.nodes()
            if getattr(n, 'block_addr', None) == block_addr
            and getattr(n, 'stmt_idx', None) == idx
        ]
        if seed_nodes:
            break

    if not seed_nodes:
        return set()

    visited = set()
    queue = deque(seed_nodes)
    slice_cls = set()
    while queue:
        cl = queue.popleft()
        if cl in visited:
            continue
        visited.add(cl)
        slice_cls.add(cl)
        for pred in ddg.graph.predecessors(cl):
            queue.append(pred)
    return slice_cls


def is_alias_obfuscated(slice_cls, func):
    """True if the slice crosses into functions outside the target (i.e. getter calls)."""
    func_blocks = set(func.block_addrs)
    return any(
        getattr(n, 'block_addr', None) not in func_blocks
        for n in slice_cls
        if getattr(n, 'block_addr', None) is not None
    )


proj, main_func, cfg, ddg = load_everything(
    TARGET_BINARY, target_func_name=TARGET_FUNC_NAME,
    cfg_type="Emulated", auto_load_libs=False)
assert proj is not None and main_func is not None and cfg is not None and ddg is not None

import keystone
ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
file_base = proj.loader.main_object.min_addr
func_blocks = set(main_func.block_addrs)

# ── Phase 1: resolve rbp-relative offsets for all obfuscated use-sites ──
# Map use_block_addr → rbp_rel for all successfully resolved stores.
resolved: dict[int, int] = {}
seen_stores: set[int] = set()

for block_addr, store_idx, store_insn_addr in find_store_sites(proj, main_func):
    if store_insn_addr is None or store_insn_addr in seen_stores:
        continue
    seen_stores.add(store_insn_addr)

    # Quick structural check: an AliasAccess-obfuscated store uses rax-based
    # addressing ([rax], [rax+offset]) and has a deref (mov rax,[rax]) in
    # its block.  Direct rbp-relative stores are not obfuscated.
    store_asm = None
    for insn in proj.factory.block(block_addr).capstone.insns:
        if insn.address == store_insn_addr:
            store_asm = insn
            break
    if store_asm is None:
        continue
    # The store's destination must reference rax (e.g. [rax], [rax+0x18])
    # but not rbp.  capstone op_str for obfuscated: "dword ptr [rax + 0x18], 0"
    if 'rax' not in store_asm.op_str or 'rbp' in store_asm.op_str:
        continue

    slice_cls = backward_slice_from_store(proj, cfg, ddg, block_addr, store_idx)
    if not slice_cls or not is_alias_obfuscated(slice_cls, main_func):
        continue

    rbp_rel = resolve_alias_chain(proj, slice_cls, main_func, block_addr)
    if rbp_rel is None:
        print(f"  [skip] could not resolve chain at 0x{store_insn_addr:x}")
        continue

    resolved[block_addr] = rbp_rel
    print(f"  0x{store_insn_addr:x} -> rbp + {rbp_rel:#x}")

# ── Phase 2: build patches ──
# Strategy: for each resolved store, overwrite the LAST getter call (in the
# preceding block) + the deref (first instruction of the use-site block) with
# a LEA + NOPs.  This avoids touching intermediate chain blocks that are
# shared with other stores.  The intermediate getter calls become harmless
# dead code (they compute rax, but the LEA overwrites it).
byte_map: dict[int, int] = {}

for use_block, rbp_rel in resolved.items():
    # Find the preceding block: the one whose call returns to use_block.
    pred_addr = None
    for ba in func_blocks:
        if ba == use_block:
            continue
        blk = proj.factory.block(ba)
        if blk.vex.jumpkind == 'Ijk_Call' and ba + blk.size == use_block:
            pred_addr = ba
            break

    # Find the deref instruction (mov rax, [rax]) at the start of the use-site block.
    deref_insn = None
    for insn in proj.factory.block(use_block).capstone.insns:
        if insn.bytes == b'\x48\x8b\x00':  # mov rax, [rax]
            deref_insn = insn
            break

    if pred_addr is None or deref_insn is None:
        print(f"  [skip patch] no pred/deref for use_block 0x{use_block:x}")
        continue

    # The last instruction of the preceding block is the getter call.
    pred_insns = proj.factory.block(pred_addr).capstone.insns
    call_insn = pred_insns[-1]

    # Assemble the LEA
    lea_asm = f"lea rax, [rbp + ({rbp_rel})]"
    lea_bytes, _ = ks.asm(lea_asm, addr=call_insn.address)
    if lea_bytes is None or len(lea_bytes) > call_insn.size:
        print(f"  [skip patch] LEA too large for call at 0x{call_insn.address:x}")
        continue

    # Patch 1: replace the getter CALL with the LEA + NOPs.
    # Instructions between the call and the deref (value loads, etc.) stay intact.
    patch = bytes(lea_bytes) + b'\x90' * (call_insn.size - len(lea_bytes))
    for i, b in enumerate(patch):
        byte_map[call_insn.address - file_base + i] = b

    # Patch 2: NOP the deref instruction separately.
    for i in range(deref_insn.size):
        byte_map[deref_insn.address - file_base + i] = 0x90

    print(f"  -> lea rax, [rbp + {rbp_rel:#x}] at 0x{call_insn.address:x}")

# Note: only derefs covered by the per-store patches above are NOPed.
# Other derefs (for reads, transparent_crc) are left intact — their
# getter chains are unmodified and produce correct results.

if byte_map:
    merged = {off: bytes([b]) for off, b in sorted(byte_map.items())}
    apply_patches([merged], TARGET_BINARY, OUTPUT_BINARY)
    print(f"\nWrote {len(resolved)} patches -> {OUTPUT_BINARY}")
else:
    print("No alias-obfuscated stores found.")
