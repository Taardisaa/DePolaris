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
