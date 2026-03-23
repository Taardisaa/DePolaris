import angr
import pyvex
from angr import sim_options as o
from angr.analyses.cdg import CDG, TemporaryNode
from collections import deque
from utils import *  # includes apply_patches from patch_utils

# from indcall import backward_slice_from

TARGET_BINARY = "examples/sample_001_bcf"
OUTPUT_BINARY = "examples/sample_001_bcf_patched"
TARGET_FUNC_NAME = "main"


# Patch CDG: _entry defaults to project.entry which may not be in a starts=[main]-only CFG
@staticmethod
def _patched_pd_graph_successors(graph, node):
    if node is None or type(node) is TemporaryNode:
        return iter([])
    return (s for s in graph.model.get_successors(node) if s is not None)
CDG._pd_graph_successors = _patched_pd_graph_successors


def find_branches(proj, func):
    result = []
    for block_addr in func.block_addrs:
        block = proj.factory.block(block_addr)
        irsb = block.vex
        # Branch: exit jumpkind is Ijk_Boring and there are multiple exits
        if irsb.jumpkind == 'Ijk_Boring' and any(
            isinstance(s, pyvex.stmt.Exit) and s.jumpkind == 'Ijk_Boring'
            for s in irsb.statements
        ):
            # The branch instruction is the last one in the block
            branch_insn = block.capstone.insns[-1]
            result.append(branch_insn.address)
    return result


def backward_slice_from(proj, cfg, ddg, target_insn_addr):
    """Return all DDG nodes in the backward slice of the instruction at target_insn_addr."""
    # Find the containing block
    block_node = cfg.model.get_any_node(target_insn_addr, anyaddr=True)
    if block_node is None:
        raise RuntimeError(f"No CFG node found containing 0x{target_insn_addr:x}")

    # Seed from the Exit statement(s) in the block (conditional branch guards),
    # falling back to stmt_idx == -2 (default/fallthrough exit used for calls).
    irsb = proj.factory.block(block_node.addr).vex
    exit_indices = {
        i for i, s in enumerate(irsb.statements)
        if isinstance(s, pyvex.stmt.Exit)
    } or {-2}

    seed_nodes = [
        n for n in ddg.graph.nodes()
        if getattr(n, 'block_addr', None) == block_node.addr
        and getattr(n, 'stmt_idx', None) in exit_indices
    ]
    if not seed_nodes:
        raise RuntimeError(f"No DDG nodes found for ins_addr=0x{target_insn_addr:x}")

    # BFS backward through the DDG
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



proj, main_func, cfg, ddg = load_everything(TARGET_BINARY, target_func_name=TARGET_FUNC_NAME, cfg_type="Emulated", auto_load_libs=False)
assert proj is not None and main_func is not None and cfg is not None and ddg is not None

branches = find_branches(proj, main_func)
print(f"Found {len(branches)} branches in {TARGET_FUNC_NAME}.")

all_patches = []
for branch_addr in branches:
    block_node = cfg.model.get_any_node(branch_addr, anyaddr=True)
    block_addr = block_node.addr

    slice_cls = backward_slice_from(proj, cfg, ddg, branch_addr)
    seen_addrs = set()
    print(f"\nBackward slice of 0x{branch_addr:x} ({len(slice_cls)} nodes):")
    for cl in sorted(slice_cls, key=lambda x: (x.block_addr or 0, x.stmt_idx or 0)):
        if cl.ins_addr is None or cl.ins_addr in seen_addrs:
            continue
        seen_addrs.add(cl.ins_addr)
        for insn in proj.factory.block(cl.ins_addr).capstone.insns:
            if insn.address == cl.ins_addr:
                print(f"  0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
                break

    kind, guard = analyze_branch_guard(proj, slice_cls, block_addr)
    print(f"  Guard: {kind}")

    if kind in ('always_true', 'always_false'):
        irsb = proj.factory.block(block_addr).vex
        cond_exit = next(s for s in irsb.statements if isinstance(s, pyvex.stmt.Exit))
        taken_addr = cond_exit.dst.value
        fall_addr = irsb.next.con.value
        patch_target = taken_addr if kind == 'always_true' else fall_addr
        all_patches.append(build_slice_patch(proj, slice_cls, patch_target, insn='jmp'))

if all_patches:
    apply_patches(all_patches, TARGET_BINARY, OUTPUT_BINARY)
    print(f"\nWrote {len(all_patches)} patches -> {OUTPUT_BINARY}")
