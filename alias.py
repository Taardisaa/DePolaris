import angr
import pyvex
import capstone.x86 as cx
from utils.patch_utils import apply_patches
from utils.vex_utils import _extract_getter_offset, resolve_alias_chain

TARGET_BINARY = "examples/sample_001_alias"
OUTPUT_BINARY = "examples/sample_001_alias_patched"
TARGET_FUNC_NAME = "main"


# ── Helpers ──

def _find_self_deref_insn(block):
    """Return the capstone insn of the first `mov REG, [REG]` (self-deref) in the
    block, or None.  Register-independent and encoding-independent."""
    for insn in block.capstone.insns:
        if insn.mnemonic != 'mov' or len(insn.operands) != 2:
            continue
        dst, src = insn.operands
        if (dst.type == cx.X86_OP_REG and src.type == cx.X86_OP_MEM
                and src.mem.base == dst.reg
                and src.mem.index == 0 and src.mem.disp == 0):
            return insn
    return None


def find_obfuscated_blocks(proj, func, getter_addrs):
    """
    Yield (use_block_addr, pred_block_addr, deref_insn) for every block that
    contains an obfuscated data access (read or store).

    Detection is purely structural:
      1. The block's predecessor ends with Ijk_Call to a getter function.
      2. The block itself contains a self-deref (`mov REG, [REG]`).

    Intermediate getter hops (which do `mov [REG], RDI` for the next call)
    are excluded because they don't have a self-deref.
    """
    func_blocks = set(func.block_addrs)
    for ba in sorted(func_blocks):
        for pred_ba in func_blocks:
            if pred_ba == ba:
                continue
            pred_blk = proj.factory.block(pred_ba)
            if pred_blk.vex.jumpkind != 'Ijk_Call':
                continue
            if pred_ba + pred_blk.size != ba:
                continue
            callee = pred_blk.vex.next
            if not isinstance(callee, pyvex.expr.Const):
                continue
            if callee.con.value not in getter_addrs:
                continue
            # Predecessor is a getter call → check for self-deref
            deref_insn = _find_self_deref_insn(proj.factory.block(ba))
            if deref_insn is not None:
                yield (ba, pred_ba, deref_insn)
            break


# ── Main ──

# CFGFast is sufficient — chain-walk resolver doesn't need DDG or CFGEmulated.
proj = angr.Project(TARGET_BINARY, auto_load_libs=False)
proj.analyses.CFGFast(normalize=True)
sym = proj.loader.find_symbol(TARGET_FUNC_NAME)
assert sym is not None, f"Function '{TARGET_FUNC_NAME}' not found"
main_func = proj.kb.functions[sym.rebased_addr]
print(f"Found function '{TARGET_FUNC_NAME}' at address 0x{sym.rebased_addr:x}.")

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

# No function hooks needed — chain-walk resolver bypasses all non-chain code.

# ── Phase 1: find all obfuscated access blocks and resolve addresses ──
resolved: dict[int, tuple[int, int, object]] = {}  # use_block → (rbp_rel, pred_block, deref_insn)

for use_block, pred_block, deref_insn in find_obfuscated_blocks(proj, main_func, getter_addrs):
    rbp_rel = resolve_alias_chain(proj, set(), main_func, use_block)
    if rbp_rel is None:
        print(f"  [skip] could not resolve chain for block 0x{use_block:x}")
        continue

    resolved[use_block] = (rbp_rel, pred_block, deref_insn)
    print(f"  0x{use_block:x} -> rbp + {rbp_rel:#x}")

# ── Phase 2: build patches ──
# For each resolved block, replace the LAST getter call (in the predecessor)
# with a LEA, and NOP the deref separately.
byte_map: dict[int, int] = {}

for use_block, (rbp_rel, pred_block, deref_insn) in resolved.items():
    call_insn = proj.factory.block(pred_block).capstone.insns[-1]

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

# ── Phase 3: NOP remaining dead getter calls ──
# After all data-access endpoints are patched with LEAs, intermediate getter
# hops (lea rdi,...; call getter; mov (%rax),%rdi) are dead code — their
# results are always overwritten.  NOP each entire hop sequence.
patched_calls = {call_addr for call_addr in byte_map}  # already patched in Phase 2

for ba in sorted(func_blocks):
    blk = proj.factory.block(ba)
    if blk.vex.jumpkind != 'Ijk_Call':
        continue
    callee = blk.vex.next
    if not isinstance(callee, pyvex.expr.Const):
        continue
    if callee.con.value not in getter_addrs:
        continue
    call_insn = blk.capstone.insns[-1]
    if call_insn.address - file_base in patched_calls:
        continue
    # NOP only the call instruction itself (other instructions in the block
    # may be live stores/reads interleaved with the dead getter chain).
    for i in range(call_insn.size):
        off = call_insn.address - file_base + i
        if off not in byte_map:
            byte_map[off] = 0x90

    # Also NOP the result load in the successor block: mov (%rax),%rdi
    succ_addr = ba + blk.size
    try:
        succ_insn = proj.factory.block(succ_addr).capstone.insns[0]
        # Verify it's a load from [rax] (the getter result)
        if (succ_insn.mnemonic == 'mov' and len(succ_insn.operands) == 2
                and succ_insn.operands[1].type == cx.X86_OP_MEM
                and succ_insn.operands[1].mem.disp == 0):
            for i in range(succ_insn.size):
                off = succ_insn.address - file_base + i
                if off not in byte_map:
                    byte_map[off] = 0x90
    except Exception:
        pass

if byte_map:
    merged = {off: bytes([b]) for off, b in sorted(byte_map.items())}
    apply_patches([merged], TARGET_BINARY, OUTPUT_BINARY)
    print(f"\nWrote {len(resolved)} access patches + dead-code cleanup -> {OUTPUT_BINARY}")
else:
    print("No alias-obfuscated accesses found.")
