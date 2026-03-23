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
    RBP_CONCRETE = 0x7FFF_0000
    key = (id(proj), func.addr)
    if key in _prologue_state_cache:
        return _prologue_state_cache[key]

    state = proj.factory.blank_state(addr=func.addr)
    state.regs.rsp = _claripy.BVV(RBP_CONCRETE + 8, 64)

    simgr = proj.factory.simgr(state)
    # Step through the prologue block (may be very large).
    # Use num_inst=20 to split large blocks into manageable chunks.
    prologue_end = func.addr + proj.factory.block(func.addr).size
    for _ in range(50):
        if not simgr.active:
            break
        if simgr.active[0].addr >= prologue_end:
            break
        simgr.step(num_inst=20)
        if len(simgr.active) > 1:
            simgr.active = simgr.active[:1]

    if simgr.active:
        _prologue_state_cache[key] = simgr.active[0]
    return _prologue_state_cache.get(key)


def resolve_alias_chain(proj: Project, slice_cls: set, func, use_block_addr: int) -> Optional[int]:
    """
    Symbolically execute from a cached post-prologue state up to the
    use-site block and return the rbp-relative offset that rax will
    hold after the getter chain's final deref.

    Non-getter function calls (crc32_gentab, func_1, …) are skipped via
    fast-return — the getter chain depends only on prologue-initialised
    transit-node memory.
    """
    import claripy as _claripy
    RBP_CONCRETE = 0x7FFF_0000
    MAX_STEPS = 500

    base_state = _get_prologue_state(proj, func)
    if base_state is None:
        return None

    func_blocks = set(func.block_addrs)

    # Identify getter functions: must have the rdi+offset→rax pattern.
    getter_addrs: set[int] = set()
    for f in proj.kb.functions.values():
        if f.addr in func_blocks:
            continue
        if _extract_getter_offset(proj, f.addr) is not None:
            getter_addrs.add(f.addr)

    state = base_state.copy()
    simgr = proj.factory.simgr(state)

    for _ in range(MAX_STEPS):
        if not simgr.active:
            break
        # Check if any state reached the target
        if any(s.addr == use_block_addr for s in simgr.active):
            simgr.active = [s for s in simgr.active if s.addr == use_block_addr]
            break

        # Fast-return: skip non-getter external functions immediately.
        for s in simgr.active:
            if s.addr not in func_blocks and s.addr not in getter_addrs:
                ret = s.memory.load(s.regs.rsp, 8, endness=proj.arch.memory_endness)
                if not ret.symbolic:
                    s.regs.rip = ret
                    s.regs.rsp = s.regs.rsp + 8

        prev_addrs = {s.addr for s in simgr.active}
        simgr.step(num_inst=20)

        # On branches, keep the state closest to (but not past) the target.
        if len(simgr.active) > 1:
            simgr.active = sorted(
                simgr.active,
                key=lambda s: (s.addr > use_block_addr, abs(s.addr - use_block_addr)),
            )[:1]

        # simgr can get stuck after branch pruning; recreate it if needed.
        if simgr.active and {s.addr for s in simgr.active} == prev_addrs:
            simgr = proj.factory.simgr(simgr.active[0].copy())
    else:
        return None

    if not simgr.active:
        return None

    # At use_block_addr the last getter returned a slot pointer in rax.
    # Read [rax] to simulate the use-site deref (which we NOP in the patch).
    state = simgr.active[0]
    rax = state.regs.rax
    rbp = state.regs.rbp
    if rax.symbolic or rbp.symbolic:
        return None

    derefed = state.memory.load(rax, 8, endness=proj.arch.memory_endness)
    if derefed.symbolic:
        return None

    return derefed.concrete_value - rbp.concrete_value
