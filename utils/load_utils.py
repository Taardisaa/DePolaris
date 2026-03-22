import angr
import pyvex
from pathlib import Path
from typing import Optional, Literal, Tuple, Union


def load_everything(binary_like: Union[Path, str, angr.Project], 
    target_func_name: Optional[str] = None,
    target_func_addr: Optional[int] = None,
    cfg_type: Literal["Emulated", "Fast"] = 'Emulated',
    auto_load_libs: bool = False
) -> Tuple[Optional[angr.Project], Optional[angr.knowledge_plugins.Function], Optional[Union[angr.analyses.CFGEmulated, angr.analyses.CFGFast]], Optional[angr.analyses.DDG]]:
    if isinstance(binary_like, (Path, str)):
        if isinstance(binary_like, Path):
            binary_path = binary_like
        else:
            binary_path = Path(binary_like)

        if not binary_path.is_file():
            print(f"Error: {binary_path} does not exist or is not a file.")
            return None, None, None, None

        proj = angr.Project(str(binary_path), auto_load_libs=auto_load_libs)
    elif isinstance(binary_like, angr.Project):
        proj = binary_like
    else:
        raise TypeError("binary_like must be a Path, str, or angr.Project.")

    sym = None

    if target_func_addr and target_func_name:
        raise ValueError("Cannot specify both target_func_name and target_func_addr.")

    if target_func_name:
        sym = proj.loader.find_symbol(target_func_name)
        if sym:
            print(f"Found function '{target_func_name}' at address 0x{sym.rebased_addr:x}.")

    if target_func_addr:
        print(f"Using provided target function address: 0x{target_func_addr:x}.")
        sym = proj.loader.find_symbol(target_func_addr)
        if sym:
            print(f"Found function at address 0x{target_func_addr:x}.")
    
    target_addr = sym.rebased_addr if sym else None
    
    if cfg_type == "Emulated":
        cfg_backend = proj.analyses.CFGEmulated
    elif cfg_type == "Fast":
        cfg_backend = proj.analyses.CFGFast
    else:
        raise ValueError(f"Invalid cfg_type: {cfg_type}. Must be 'Emulated' or 'Fast'.")

    cfg = cfg_backend(keep_state=True,
        normalize=True,
        starts=[target_addr] if target_addr else None,
        state_add_options={angr.options.TRACK_REGISTER_ACTIONS, angr.options.TRACK_MEMORY_ACTIONS, angr.options.TRACK_TMP_ACTIONS},
    )
    ddg = proj.analyses.DDG(cfg, start=target_addr or None)

    func = None
    if target_addr:
        func = cfg.kb.functions[target_addr]

    return proj, func, cfg, ddg


