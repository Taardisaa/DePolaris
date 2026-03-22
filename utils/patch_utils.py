from typing import Literal
import angr


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
