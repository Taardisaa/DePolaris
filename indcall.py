import angr
from angr import sim_options as o
from angr.analyses.cdg import CDG, TemporaryNode
from collections import deque

TARGET_BINARY = "examples/sample_001_indcall_mba"
OUTPUT_BINARY = "examples/sample_001_mba_patched"
TARGET_FUNC_NAME = "main"

# Patch CDG: _entry defaults to project.entry which may not be in a starts=[main]-only CFG
@staticmethod
def _patched_pd_graph_successors(graph, node):
    if node is None or type(node) is TemporaryNode:
        return iter([])
    return (s for s in graph.model.get_successors(node) if s is not None)
CDG._pd_graph_successors = _patched_pd_graph_successors

proj = angr.Project(TARGET_BINARY, auto_load_libs=False)
main_addr = proj.loader.find_symbol(TARGET_FUNC_NAME).rebased_addr  # type: ignore

cfg = proj.analyses.CFGEmulated(
    keep_state=True,
    normalize=True,
    starts=[main_addr],
    state_add_options={o.TRACK_REGISTER_ACTIONS, o.TRACK_MEMORY_ACTIONS, o.TRACK_TMP_ACTIONS},
)
ddg = proj.analyses.DDG(cfg, start=main_addr)

def find_indirect_calls(proj, func):
    """Return addresses of all indirect call instructions in a function."""
    import pyvex
    result = []
    for block_addr in func.block_addrs:
        block = proj.factory.block(block_addr)
        irsb = block.vex
        # Indirect call: exit jumpkind is Call and target is not a constant
        if irsb.jumpkind == 'Ijk_Call' and not isinstance(irsb.next, pyvex.expr.Const):
            # The call instruction is the last one in the block
            call_insn = block.capstone.insns[-1]
            result.append(call_insn.address)
    return result

def slice_to_symbolic(proj, slice_cls, target_reg='rax'):
    """
    Symbolically execute the blocks in a backward slice and return
    the symbolic expression for target_reg at the end of the slice.
    """
    block_addrs = sorted(set(
        cl.block_addr for cl in slice_cls if cl.block_addr is not None
    ))
    if not block_addrs:
        return None

    state = proj.factory.blank_state(addr=block_addrs[0])
    simgr = proj.factory.simgr(state)

    # Step through each block, keeping only states headed to the next slice block
    for next_addr in block_addrs[1:]:
        simgr.step()
        simgr.move('active', 'deadended', lambda s, na=next_addr: s.addr != na)
        if not simgr.active:
            break

    # Step the final block
    if simgr.active:
        simgr.step()

    all_states = simgr.active + simgr.deadended + simgr.unsat
    if not all_states:
        return None

    return all_states[0].regs.get(target_reg)

def build_slice_patch(proj, slice_cls, target_addr):
    """
    Compute the patch bytes for one slice: returns a dict {file_offset: bytes}.
    Finds the first contiguous slice region >= 5 bytes, places 'call target' there,
    and NOPs out everything else.
    """
    import keystone
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    CALL_SIZE = 5

    seen = {}
    for cl in slice_cls:
        addr = cl.ins_addr
        if addr is None or addr in seen:
            continue
        for insn in proj.factory.block(addr).capstone.insns:
            if insn.address == addr:
                seen[addr] = insn.size
                break
    insns = sorted(seen.items())

    patch_start = patch_total = None
    for i, (addr, size) in enumerate(insns):
        run_size = size
        for j in range(i + 1, len(insns)):
            if insns[j-1][0] + insns[j-1][1] != insns[j][0]:
                break
            run_size += insns[j][1]
            if run_size >= CALL_SIZE:
                break
        if run_size >= CALL_SIZE:
            patch_start, patch_total = addr, run_size
            break

    if patch_start is None:
        raise RuntimeError(f"No contiguous slice region >= {CALL_SIZE} bytes for call 0x{target_addr:x}")

    call_bytes, _ = ks.asm(f"call 0x{target_addr:x}", addr=patch_start)
    assert call_bytes is not None
    file_base = proj.loader.main_object.min_addr
    patches = {}
    patches[patch_start - file_base] = bytes(call_bytes) + b'\x90' * (patch_total - len(call_bytes))
    for addr, size in insns:
        if patch_start <= addr < patch_start + patch_total:
            continue
        patches[addr - file_base] = b'\x90' * size

    print(f"  -> call 0x{target_addr:x} at 0x{patch_start:x} (+{patch_total - CALL_SIZE} nops)")
    return patches

def apply_patches(patches_list, input_file, output_file):
    """Write all accumulated patches to output_file in one pass."""
    import shutil
    shutil.copy(input_file, output_file)
    with open(output_file, "r+b") as f:
        for patches in patches_list:
            for offset, data in patches.items():
                f.seek(offset)
                f.write(data)

def backward_slice_from(proj, cfg, ddg, target_insn_addr):
    """Return all DDG nodes in the backward slice of the instruction at target_insn_addr."""
    # Find the containing block
    block_node = cfg.model.get_any_node(target_insn_addr, anyaddr=True)
    if block_node is None:
        raise RuntimeError(f"No CFG node found containing 0x{target_insn_addr:x}")

    # Use only the block exit node (stmt_idx == -2), which represents
    # the indirect jump/call target — avoids pulling in call mechanics (RSP chain)
    seed_nodes = [
        n for n in ddg.graph.nodes()
        if getattr(n, 'block_addr', None) == block_node.addr
        and getattr(n, 'stmt_idx', None) == -2
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

main_func = cfg.kb.functions[main_addr]
indirect_calls = find_indirect_calls(proj, main_func)
print(f"Indirect calls in main: {[hex(a) for a in indirect_calls]}\n")

all_patches = []
for call_addr in indirect_calls:
    # call_rax_addr = 0x004011c7
    slice_cls = backward_slice_from(proj, cfg, ddg, call_addr)

    print(f"\nBackward slice of 0x{call_addr:x} ({len(slice_cls)} nodes):")
    for cl in sorted(slice_cls, key=lambda x: (x.block_addr or 0, x.stmt_idx or 0)):
        if cl.ins_addr is not None:
            block = proj.factory.block(cl.ins_addr)
            for insn in block.capstone.insns:
                if insn.address == cl.ins_addr:
                    print(f"  [{cl.stmt_idx:>3}] 0x{insn.address:x}:  {insn.mnemonic} {insn.op_str}")
                    break

    # TODO: the register here is hardcoded as `rax`. We should change to a more generic approach that detects which register is used in the indirect jump/call and tracks that instead.
    sym = slice_to_symbolic(proj, slice_cls, target_reg='rax')
    print(f"  symbolic rax: {sym}")

    if sym is not None and sym.concrete:
        all_patches.append(build_slice_patch(proj, slice_cls, sym.concrete_value))

if all_patches:
    apply_patches(all_patches, TARGET_BINARY, OUTPUT_BINARY)
    print(f"\nWrote {len(all_patches)} patches -> {OUTPUT_BINARY}")
