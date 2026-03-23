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


def resolve_alias_chain(proj: Project, slice_cls: set, func, use_block_addr: int) -> Optional[int]:
    """
    Symbolically execute from a cached post-prologue state up to the
    use-site block and return the rbp-relative offset that rax will
    hold after the getter chain's final deref.

    Non-getter function calls are hooked (setup_getter_hooks) so symex
    only traverses the getter chain.  ZERO_FILL options on the initial
    state prevent path explosion by making all branches deterministic.
    """
    RBP_CONCRETE = 0x7FFF_0000

    base_state = _get_prologue_state(proj, func)
    if base_state is None:
        return None

    state = base_state.copy()
    simgr = proj.factory.simgr(state)
    simgr.explore(find=use_block_addr, num_find=1)

    if not simgr.found:
        # Blocks behind conditional branches may be unreachable with
        # ZERO_FILL (branch condition depends on uninitialised struct fields).
        # Retry from func entry WITHOUT ZERO_FILL — symbolic branches
        # fork but the state count stays small with hooked non-getters.
        import claripy as _claripy
        from angr import sim_options as o
        retry = proj.factory.blank_state(
            addr=func.addr,
            add_options={o.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                         o.SYMBOL_FILL_UNCONSTRAINED_REGISTERS},
        )
        retry.regs.rsp = _claripy.BVV(RBP_CONCRETE + 8, 64)
        simgr = proj.factory.simgr(retry)
        simgr.explore(find=use_block_addr, num_find=1)

    if not simgr.found:
        return None

    # At use_block_addr the last getter returned a slot pointer in rax.
    # Read [rax] to simulate the use-site deref (which we NOP in the patch).
    state = simgr.found[0]
    rax = state.regs.rax
    rbp = state.regs.rbp
    if rax.symbolic or rbp.symbolic:
        return None

    derefed = state.memory.load(rax, 8, endness=proj.arch.memory_endness)
    if derefed.symbolic:
        return None

    return derefed.concrete_value - rbp.concrete_value
