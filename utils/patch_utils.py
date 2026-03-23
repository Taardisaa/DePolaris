import shutil
from typing import Literal
import angr


def apply_patches(patches_list, input_file, output_file):
    shutil.copy(input_file, output_file)
    with open(output_file, "r+b") as f:
        for patches in patches_list:
            for offset, data in patches.items():
                f.seek(offset)
                f.write(data)


def build_slice_patch(
    proj: angr.Project,
    slice_cls: set,
    target_addr: int,
    insn: Literal["call", "jmp"] = "call",
) -> dict[int, bytes]:
    """
    Compute patch bytes for a slice: returns a dict {file_offset: bytes}.
    Finds the first contiguous slice region >= 5 bytes, places `insn target`
    there, and NOPs out everything else.
    """
    import keystone
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    INSN_SIZE = 5

    seen = {}
    for cl in slice_cls:
        addr = cl.ins_addr
        if addr is None or addr in seen:
            continue
        for i in proj.factory.block(addr).capstone.insns:
            if i.address == addr:
                seen[addr] = i.size
                break
    insns = sorted(seen.items())

    patch_start = patch_total = None
    for i, (addr, size) in enumerate(insns):
        run_size = size
        for j in range(i + 1, len(insns)):
            if insns[j-1][0] + insns[j-1][1] != insns[j][0]:
                break
            run_size += insns[j][1]
            if run_size >= INSN_SIZE:
                break
        if run_size >= INSN_SIZE:
            patch_start, patch_total = addr, run_size
            break

    if patch_start is None:
        raise RuntimeError(
            f"No contiguous slice region >= {INSN_SIZE} bytes for {insn} 0x{target_addr:x}"
        )

    asm_bytes, _ = ks.asm(f"{insn} 0x{target_addr:x}", addr=patch_start)
    assert asm_bytes is not None
    file_base = proj.loader.main_object.min_addr
    patches: dict[int, bytes] = {}
    patches[patch_start - file_base] = bytes(asm_bytes) + b'\x90' * (patch_total - len(asm_bytes))
    for addr, size in insns:
        if patch_start <= addr < patch_start + patch_total:
            continue
        patches[addr - file_base] = b'\x90' * size

    print(f"  -> {insn} 0x{target_addr:x} at 0x{patch_start:x} (+{patch_total - INSN_SIZE} nops)")
    return patches


def build_lea_patch(
    proj: angr.Project,
    slice_cls: set,
    func,
    seed_insn_addr: int,
    seed_block_addr: int,
    rbp_rel: int,
) -> dict[int, bytes]:
    """
    Replace the getter call chain with `lea rax, [rbp + rbp_rel]` + NOPs.
    seed_insn_addr is the actual store instruction — it is excluded from the patch
    (left untouched so its offset(%rax) continues to apply correctly).
    Only instructions in getter-call blocks are patched; getter bodies, prologue
    init stores, and the use-site block are all left alone.
    """
    import pyvex
    import keystone
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    # Pre-assemble the LEA to determine its actual size (4B with disp8, 7B with disp32).
    lea_asm = f"lea rax, [rbp + ({rbp_rel})]"
    lea_bytes_pre, _ = ks.asm(lea_asm, addr=0)
    LEA_SIZE = len(lea_bytes_pre)

    func_blocks = set(func.block_addrs)

    # External (non-func) blocks present in the DDG slice — these are getter bodies.
    slice_ext_blocks = {
        getattr(cl, 'block_addr', None)
        for cl in slice_cls
        if getattr(cl, 'block_addr', None) is not None
        and getattr(cl, 'block_addr', None) not in func_blocks
    }

    # Func blocks present in the DDG slice.
    slice_func_blocks = {
        getattr(cl, 'block_addr', None)
        for cl in slice_cls
        if getattr(cl, 'block_addr', None) is not None
        and getattr(cl, 'block_addr', None) in func_blocks
    }

    # Identify getter-call blocks: func blocks in the slice that end with
    # Ijk_Call whose callee is a getter body in the slice.
    # Excluded:
    #   - seed_block_addr  (handled separately below for the deref instruction)
    #   - func.addr        (function entry — mixes prologue init stores with
    #                       the first getter call; the wasted call is harmless
    #                       since our LEA in the next block overwrites rax)
    chain_blocks = set()
    for ba in slice_func_blocks:
        if ba == seed_block_addr or ba == func.addr:
            continue
        irsb = proj.factory.block(ba).vex
        if irsb.jumpkind != 'Ijk_Call':
            continue
        callee = irsb.next
        if not isinstance(callee, pyvex.expr.Const):
            continue
        if callee.con.value not in slice_ext_blocks:
            continue
        # Only treat functions with the rdi+offset→rax getter pattern.
        # Regular functions (func_1, transparent_crc, …) also appear in the
        # slice via DDG edges but must not have their call sites NOPed.
        from utils.vex_utils import _extract_getter_offset
        if _extract_getter_offset(proj, callee.con.value) is not None:
            chain_blocks.add(ba)

    # For chain blocks: NOP only the CALL instruction (last insn, 5 bytes).
    # Other instructions in the block (stores/value-loads from adjacent chains,
    # arg-setup that writes rdi) are left as-is — they are harmless dead code
    # once the call they feed is removed.
    #
    # For the FIRST chain block (sorted by address): overwrite the tail
    # (call + preceding arg-setup) with the LEA instruction + NOPs.
    # This gives us the >= 7 contiguous bytes we need.
    seen: dict[int, int] = {}
    first_chain = min(chain_blocks) if chain_blocks else None

    for ba in chain_blocks:
        capstone_insns = proj.factory.block(ba).capstone.insns
        if ba == first_chain:
            # Overwrite the tail of the first chain block (call + arg setup)
            # to get >= LEA_SIZE contiguous bytes.
            tail_size = 0
            for insn in reversed(capstone_insns):
                seen[insn.address] = insn.size
                tail_size += insn.size
                if tail_size >= LEA_SIZE:
                    break
        else:
            # Other chain blocks: NOP only the call (last instruction).
            call_insn = capstone_insns[-1]
            seen[call_insn.address] = call_insn.size

    # In the seed block, the getter return value sits in rax.  Before the
    # store can use it, a deref instruction (e.g. `mov (%rax),%rax`) rewrites
    # rax.  We must NOP that deref so our LEA value reaches the store intact.
    # Find it via VEX: the last PUT to rax before the Store statement.
    rax_off = proj.arch.registers['rax'][0]
    seed_irsb = proj.factory.block(seed_block_addr).vex
    deref_insn_addr = None
    cur_addr = None
    for s in seed_irsb.statements:
        if isinstance(s, pyvex.stmt.IMark):
            cur_addr = s.addr
        elif isinstance(s, pyvex.stmt.Put) and s.offset == rax_off:
            if cur_addr is not None and cur_addr != seed_insn_addr:
                deref_insn_addr = cur_addr
        elif isinstance(s, pyvex.stmt.Store) and cur_addr == seed_insn_addr:
            break   # stop once we reach the store instruction

    if deref_insn_addr is not None and deref_insn_addr not in seen:
        for i in proj.factory.block(seed_block_addr).capstone.insns:
            if i.address == deref_insn_addr:
                seen[deref_insn_addr] = i.size
                break

    insns = sorted(seen.items())

    if not insns:
        raise RuntimeError(f"No chain instructions found for store at 0x{seed_insn_addr:x}")

    patch_start = patch_total = None
    for i, (addr, size) in enumerate(insns):
        run_size = size
        for j in range(i + 1, len(insns)):
            if insns[j-1][0] + insns[j-1][1] != insns[j][0]:
                break
            run_size += insns[j][1]
            if run_size >= LEA_SIZE:
                break
        if run_size >= LEA_SIZE:
            patch_start, patch_total = addr, run_size
            break

    if patch_start is None:
        raise RuntimeError(
            f"No contiguous chain region >= {LEA_SIZE} bytes at 0x{seed_insn_addr:x}"
        )

    lea_bytes, _ = ks.asm(lea_asm, addr=patch_start)
    assert lea_bytes is not None

    file_base = proj.loader.main_object.min_addr
    patches: dict[int, bytes] = {}
    patches[patch_start - file_base] = bytes(lea_bytes) + b'\x90' * (patch_total - LEA_SIZE)
    for addr, size in insns:
        if patch_start <= addr < patch_start + patch_total:
            continue
        patches[addr - file_base] = b'\x90' * size

    print(f"  -> lea rax, [rbp + {rbp_rel:#x}] at 0x{patch_start:x}")
    return patches
