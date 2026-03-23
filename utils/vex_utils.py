import typing
from typing import Literal, Optional
import claripy
from angr import Project
import pyvex


def print_vex(proj: Project, block_addr: int):
    irsb = proj.factory.block(block_addr).vex
    print(irsb._pp_str())


def analyze_branch_guard(
    proj: Project,
    slice_cls: set,
    branch_block_addr: int,
) -> tuple[Literal["always_true", "always_false", "symbolic", "unconditional"], Optional[claripy.ast.Base]]:
    """
    Symbolically execute a backward slice up to and including the branch block,
    then determine whether the branch guard is an opaque predicate.

    Returns a (kind, guard) tuple where kind is one of:
      'always_true'    - branch is always taken       (opaque predicate)
      'always_false'   - branch is never taken         (opaque predicate)
      'symbolic'       - guard depends on real inputs  (genuine branch)
      'unconditional'  - block has no conditional exit
    """
    block_addrs = sorted(set(
        cl.block_addr for cl in slice_cls if cl.block_addr is not None
    ))
    if branch_block_addr not in block_addrs:
        block_addrs.append(branch_block_addr)

    state = proj.factory.blank_state(addr=block_addrs[0])
    simgr = proj.factory.simgr(state)

    for next_addr in block_addrs[1:]:
        simgr.step()
        simgr.move('active', 'deadended', lambda s, na=next_addr: s.addr != na)
        if not simgr.active:
            break

    if not simgr.active:
        return 'unconditional', None

    irsb = proj.factory.block(branch_block_addr).vex
    cond_exit = next(
        (s for s in irsb.statements if isinstance(s, pyvex.stmt.Exit)),
        None,
    )
    if cond_exit is None:
        return 'unconditional', None

    succs = simgr.active[0].step()

    # Angr concretely resolved the guard → only one successor produced.
    # This is the hallmark of an opaque predicate: the assembly is conditional
    # but the condition is always true or always false.
    if len(succs.successors) == 1:
        taken_addr = cond_exit.dst.value
        resolved_addr = succs.successors[0].addr
        if resolved_addr == taken_addr:
            return 'always_true', None
        else:
            return 'always_false', None

    guard = succs.successors[0].history.jump_guard
    solver = simgr.active[0].solver

    can_be_true  = solver.satisfiable(extra_constraints=[guard])
    can_be_false = solver.satisfiable(extra_constraints=[claripy.Not(guard)])

    if can_be_true and not can_be_false:
        return 'always_true', guard
    elif can_be_false and not can_be_true:
        return 'always_false', guard
    else:
        return 'symbolic', guard


def _extract_getter_offset(proj: Project, getter_addr: int) -> Optional[int]:
    """
    Return the constant offset K if the function at getter_addr is an
    AliasAccess getter (rax = rdi + K; ret), otherwise None.
    Checks the VEX IR for Add64(GET(rdi), Const) → PUT(rax) with Ijk_Ret.
    """
    try:
        irsb = proj.factory.block(getter_addr).vex
        if irsb.jumpkind != 'Ijk_Ret':
            return None
        rax_off = proj.arch.registers['rax'][0]
        for s in irsb.statements:
            if isinstance(s, pyvex.stmt.Put) and s.offset == rax_off:
                if isinstance(s.data, pyvex.expr.RdTmp):
                    tmp = s.data.tmp
                    for s2 in irsb.statements:
                        if isinstance(s2, pyvex.stmt.WrTmp) and s2.tmp == tmp:
                            if isinstance(s2.data, pyvex.expr.Binop) and 'Add' in s2.data.op:
                                for arg in s2.data.args:
                                    if isinstance(arg, pyvex.expr.Const):
                                        return arg.con.value
    except Exception:
        pass
    return None


_prologue_state_cache: dict = {}


def _get_prologue_state(proj: Project, func) -> 'claripy.ast.Base':
    """Execute the function prologue once and cache the resulting state."""
    import claripy as _claripy
    from angr import sim_options as o
    RBP_CONCRETE = 0x7FFF_0000
    key = (id(proj), func.addr)
    if key in _prologue_state_cache:
        return _prologue_state_cache[key]

    state = proj.factory.blank_state(
        addr=func.addr,
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY,
                     o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
    )
    state.regs.rsp = _claripy.BVV(RBP_CONCRETE + 8, 64)

    prologue_end = func.addr + proj.factory.block(func.addr).size
    simgr = proj.factory.simgr(state)
    simgr.explore(find=lambda s: s.addr >= prologue_end)

    if simgr.found:
        _prologue_state_cache[key] = simgr.found[0]
    return _prologue_state_cache.get(key)


def setup_getter_hooks(proj: Project, func) -> None:
    """Hook all non-getter external functions so symex skips them."""
    import angr as _angr
    func_blocks = set(func.block_addrs)

    class _SkipFunc(_angr.SimProcedure):
        def run(self):
            return 0

    for f in proj.kb.functions.values():
        if f.addr in func_blocks:
            continue
        if proj.is_hooked(f.addr):
            continue
        if _extract_getter_offset(proj, f.addr) is not None:
            continue
        proj.hook(f.addr, _SkipFunc())


def _symex_getter_offset(proj: Project, getter_addr: int) -> Optional[int]:
    """Fallback: symex a single getter function to determine its offset.
    Handles MBA-obfuscated getters where VEX pattern matching fails.
    Only runs on single-block Ijk_Ret functions (getter candidates)."""
    import claripy as _claripy
    try:
        # Pre-filter: only attempt on single-block ret functions
        irsb = proj.factory.block(getter_addr).vex
        if irsb.jumpkind != 'Ijk_Ret':
            return None
        rdi = _claripy.BVS("rdi", 64)
        state = proj.factory.call_state(getter_addr, rdi)
        simgr = proj.factory.simgr(state)
        simgr.run()
        if not simgr.deadended:
            return None
        s = simgr.deadended[0]
        rax = s.regs.rax
        if rax.symbolic:
            offset = s.solver.eval(rax - rdi)
            return offset
        return None
    except Exception:
        return None


def _resolve_getter_offset(proj: Project, getter_addr: int) -> Optional[int]:
    """Resolve a getter's constant offset: VEX pattern match first, symex fallback."""
    off = _extract_getter_offset(proj, getter_addr)
    if off is not None:
        return off
    return _symex_getter_offset(proj, getter_addr)


def _find_getter_pred(proj: Project, block_addr: int, func_blocks: set, getter_resolver) -> Optional[dict]:
    """Find the predecessor block that calls a getter and returns to block_addr.
    Returns {'block_addr': pred_addr, 'callee': callee_addr, 'offset': K} or None."""
    for ba in func_blocks:
        if ba == block_addr:
            continue
        blk = proj.factory.block(ba)
        if blk.vex.jumpkind != 'Ijk_Call':
            continue
        if ba + blk.size != block_addr:
            continue
        callee = blk.vex.next
        if not isinstance(callee, pyvex.expr.Const):
            continue
        offset = getter_resolver(proj, callee.con.value)
        if offset is not None:
            return {'block_addr': ba, 'callee': callee.con.value, 'offset': offset}
    return None


def resolve_alias_chain(proj: Project, slice_cls: set, func, use_block_addr: int) -> Optional[int]:
    """
    Resolve the getter call chain for a use-site via chain-walk:

    1. Walk backward from use_block_addr through getter-call predecessors
       (pure CFG structure, no branches traversed)
    2. At the chain entry (first block whose predecessor is NOT a getter call),
       single-block symex to get the concrete initial pointer value
    3. Walk forward through prologue memory using getter offsets

    No full-function symex, no SkipFunc hooks, no path explosion.
    Per-getter symex fallback handles MBA-obfuscated getter offsets.
    """
    RBP_CONCRETE = 0x7FFF_0000

    base_state = _get_prologue_state(proj, func)
    if base_state is None:
        return None

    func_blocks = set(func.block_addrs)

    # Step 1: walk backward from use_block, collecting getter offsets.
    # Import the deref checker from alias.py's scope — it's passed as a parameter
    # or we detect it locally.
    chain = []  # getter offsets in reverse order
    current = use_block_addr
    chain_entry = None

    for depth in range(20):
        pred = _find_getter_pred(proj, current, func_blocks, _resolve_getter_offset)
        if pred is None:
            break
        chain.append(pred['offset'])
        current = pred['block_addr']

        # Chain boundary check 1: this block has a self-deref (mov REG,[REG]).
        # That means it's a use-site for a DIFFERENT chain that also starts
        # THIS chain — the interleaved block pattern.  Stop here.
        import capstone.x86 as _cx
        has_self_deref = False
        for insn in proj.factory.block(current).capstone.insns:
            if insn.mnemonic != 'mov' or len(insn.operands) != 2:
                continue
            dst, src = insn.operands
            if (dst.type == _cx.X86_OP_REG and src.type == _cx.X86_OP_MEM
                    and src.mem.base == dst.reg
                    and src.mem.index == 0 and src.mem.disp == 0):
                has_self_deref = True
                break
        if has_self_deref:
            chain_entry = current
            break

        # Chain boundary check 2: predecessor is not a getter call →
        # this is the first hop (prologue or standalone lea block).
        own_pred = _find_getter_pred(proj, current, func_blocks, _resolve_getter_offset)
        if own_pred is None:
            chain_entry = current
            break

    if not chain or chain_entry is None:
        return None
    chain.reverse()

    # Step 2: get the initial pointer value (rdi at the getter call).
    import claripy as _claripy

    if chain_entry == func.addr:
        # Chain starts from the prologue block — the prologue state is already
        # positioned at the getter entry with rdi set by the prologue's lea.
        rdi = base_state.regs.rdi
    else:
        # Chain starts from a non-prologue block. Single-block symex using the
        # prologue state's memory/registers to compute rdi concretely.
        entry_state = base_state.copy()
        entry_state.regs.rip = _claripy.BVV(chain_entry, 64)
        succ = entry_state.step()
        if not succ.flat_successors:
            return None
        rdi = succ.flat_successors[0].regs.rdi

    if rdi.symbolic:
        return None
    initial_ptr = rdi.concrete_value

    # Step 3: walk forward — apply first getter offset, then read memory for each hop
    ptr = initial_ptr + chain[0]
    for getter_offset in chain[1:]:
        mem = base_state.memory.load(ptr, 8, endness=proj.arch.memory_endness)
        if mem.symbolic:
            return None
        ptr = mem.concrete_value + getter_offset

    # Final deref: read the slot pointer to get the raw struct address
    mem = base_state.memory.load(ptr, 8, endness=proj.arch.memory_endness)
    if mem.symbolic:
        return None

    return mem.concrete_value - RBP_CONCRETE


# ── Legacy: full-function explore (kept as utility) ──

def resolve_alias_chain_explore(proj: Project, func, use_block_addr: int) -> Optional[int]:
    """Full-function simgr.explore resolver (legacy). Requires setup_getter_hooks."""
    RBP_CONCRETE = 0x7FFF_0000
    base_state = _get_prologue_state(proj, func)
    if base_state is None:
        return None
    state = base_state.copy()
    simgr = proj.factory.simgr(state)
    simgr.explore(find=use_block_addr, num_find=1)
    if not simgr.found:
        return None
    state = simgr.found[0]
    rax = state.regs.rax
    rbp = state.regs.rbp
    if rax.symbolic or rbp.symbolic:
        return None
    derefed = state.memory.load(rax, 8, endness=proj.arch.memory_endness)
    if derefed.symbolic:
        return None
    return derefed.concrete_value - rbp.concrete_value
