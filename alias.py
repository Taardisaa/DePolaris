import angr
import pyvex
from angr.analyses.cdg import CDG, TemporaryNode
from collections import deque
from utils import *
from utils.vex_utils import _extract_getter_offset, setup_getter_hooks

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


# ── VEX-based helpers (register-independent) ──

def _store_addr_has_load(irsb, store_stmt_idx) -> bool:
    """True if the Store's address traces back to a memory Load (pointer deref).
    Obfuscated stores use pointer-based addressing (Load + optional offset),
    while direct stack stores use GET(rbp) + offset with no Load."""
    store = irsb.statements[store_stmt_idx]
    addr = store.addr
    if not isinstance(addr, pyvex.expr.RdTmp):
        return False
    for s in irsb.statements:
        if isinstance(s, pyvex.stmt.WrTmp) and s.tmp == addr.tmp:
            if isinstance(s.data, pyvex.expr.Load):
                return True
            if isinstance(s.data, pyvex.expr.Binop) and 'Add' in s.data.op:
                for arg in s.data.args:
                    if isinstance(arg, pyvex.expr.RdTmp):
                        for s2 in irsb.statements:
                            if isinstance(s2, pyvex.stmt.WrTmp) and s2.tmp == arg.tmp:
                                return isinstance(s2.data, pyvex.expr.Load)
            return False
    return False


def _find_deref_addr(irsb, store_stmt_idx):
    """Return the instruction address of the Load (deref) that feeds the Store's
    address, or None.  Works regardless of which register is used."""
    store = irsb.statements[store_stmt_idx]
    addr = store.addr
    if not isinstance(addr, pyvex.expr.RdTmp):
        return None

    load_tmp = None
    for s in irsb.statements:
        if isinstance(s, pyvex.stmt.WrTmp) and s.tmp == addr.tmp:
            if isinstance(s.data, pyvex.expr.Load):
                load_tmp = addr.tmp
            elif isinstance(s.data, pyvex.expr.Binop) and 'Add' in s.data.op:
                for arg in s.data.args:
                    if isinstance(arg, pyvex.expr.RdTmp):
                        for s2 in irsb.statements:
                            if isinstance(s2, pyvex.stmt.WrTmp) and s2.tmp == arg.tmp:
                                if isinstance(s2.data, pyvex.expr.Load):
                                    load_tmp = arg.tmp
                                break
            break

    if load_tmp is None:
        return None

    cur_imk = None
    for s in irsb.statements:
        if isinstance(s, pyvex.stmt.IMark):
            cur_imk = s.addr
        if isinstance(s, pyvex.stmt.WrTmp) and s.tmp == load_tmp:
            return cur_imk
    return None


# ── Store discovery ──

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


def is_alias_obfuscated(slice_cls, func, getter_addrs):
    """True if the backward slice includes blocks from getter functions."""
    return any(
        getattr(n, 'block_addr', None) in getter_addrs
        for n in slice_cls
        if getattr(n, 'block_addr', None) is not None
    )


# ── Main ──

proj, main_func, cfg, ddg = load_everything(
    TARGET_BINARY, target_func_name=TARGET_FUNC_NAME,
    cfg_type="Emulated", auto_load_libs=False)
assert proj is not None and main_func is not None and cfg is not None and ddg is not None

import keystone
ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
file_base = proj.loader.main_object.min_addr
func_blocks = set(main_func.block_addrs)

# Pre-compute getter function addresses and hook non-getters for symex.
getter_addrs: set[int] = set()
for f in proj.kb.functions.values():
    if f.addr in func_blocks:
        continue
    if _extract_getter_offset(proj, f.addr) is not None:
        getter_addrs.add(f.addr)

setup_getter_hooks(proj, main_func)

# ── Phase 1: resolve rbp-relative offsets for all obfuscated use-sites ──
resolved: dict[int, int] = {}
seen_stores: set[int] = set()

for block_addr, store_idx, store_insn_addr in find_store_sites(proj, main_func):
    if store_insn_addr is None or store_insn_addr in seen_stores:
        continue
    seen_stores.add(store_insn_addr)

    # VEX-based structural check: an obfuscated store's address traces back to
    # a memory Load (pointer deref), not a direct GET(rbp)+offset.
    irsb = proj.factory.block(block_addr).vex
    if not _store_addr_has_load(irsb, store_idx):
        continue

    slice_cls = backward_slice_from_store(proj, cfg, ddg, block_addr, store_idx)
    if not slice_cls or not is_alias_obfuscated(slice_cls, main_func, getter_addrs):
        continue

    rbp_rel = resolve_alias_chain(proj, slice_cls, main_func, block_addr)
    if rbp_rel is None:
        print(f"  [skip] could not resolve chain at 0x{store_insn_addr:x}")
        continue

    resolved[block_addr] = rbp_rel
    print(f"  0x{store_insn_addr:x} -> rbp + {rbp_rel:#x}")

# ── Phase 2: build patches ──
# Strategy: for each resolved store, overwrite the LAST getter call (in the
# preceding block) with a LEA, and NOP the deref (found via VEX) separately.
# This avoids touching intermediate chain blocks shared with other stores.
byte_map: dict[int, int] = {}

for use_block, rbp_rel in resolved.items():
    irsb = proj.factory.block(use_block).vex

    # Find the preceding block: the one whose call returns to use_block.
    pred_addr = None
    for ba in func_blocks:
        if ba == use_block:
            continue
        blk = proj.factory.block(ba)
        if blk.vex.jumpkind == 'Ijk_Call' and ba + blk.size == use_block:
            pred_addr = ba
            break

    # Find the deref via VEX: the Load that feeds the first Store's address.
    deref_addr = None
    for i, s in enumerate(irsb.statements):
        if isinstance(s, pyvex.stmt.Store):
            deref_addr = _find_deref_addr(irsb, i)
            break

    if pred_addr is None or deref_addr is None:
        print(f"  [skip patch] no pred/deref for use_block 0x{use_block:x}")
        continue

    # Find the deref's capstone instruction (for its size).
    deref_insn = None
    for insn in proj.factory.block(use_block).capstone.insns:
        if insn.address == deref_addr:
            deref_insn = insn
            break
    if deref_insn is None:
        continue

    # The last instruction of the preceding block is the getter call.
    call_insn = proj.factory.block(pred_addr).capstone.insns[-1]

    # Assemble the LEA
    lea_asm = f"lea rax, [rbp + ({rbp_rel})]"
    lea_bytes, _ = ks.asm(lea_asm, addr=call_insn.address)
    if lea_bytes is None or len(lea_bytes) > call_insn.size:
        print(f"  [skip patch] LEA too large for call at 0x{call_insn.address:x}")
        continue

    # Patch 1: replace the getter CALL with the LEA + NOPs.
    patch = bytes(lea_bytes) + b'\x90' * (call_insn.size - len(lea_bytes))
    for i, b in enumerate(patch):
        byte_map[call_insn.address - file_base + i] = b

    # Patch 2: NOP the deref instruction separately.
    for i in range(deref_insn.size):
        byte_map[deref_insn.address - file_base + i] = 0x90

    print(f"  -> lea rax, [rbp + {rbp_rel:#x}] at 0x{call_insn.address:x}")

if byte_map:
    merged = {off: bytes([b]) for off, b in sorted(byte_map.items())}
    apply_patches([merged], TARGET_BINARY, OUTPUT_BINARY)
    print(f"\nWrote {len(resolved)} patches -> {OUTPUT_BINARY}")
else:
    print("No alias-obfuscated stores found.")
