import angr
from angr import sim_options as o
from angr.analyses.cdg import CDG, TemporaryNode
from collections import deque
from utils import *

# Patch CDG: _entry defaults to project.entry which may not be in a starts=[main]-only CFG
@staticmethod
def _patched_pd_graph_successors(graph, node):
    if node is None or type(node) is TemporaryNode:
        return iter([])
    return (s for s in graph.model.get_successors(node) if s is not None)
CDG._pd_graph_successors = _patched_pd_graph_successors

TARGET_BINARY = "examples/sample_001_bcf"
OUTPUT_BINARY = "examples/sample_001_bcf_patched"
TARGET_FUNC_NAME = "main"

proj, func, cfg, ddg = load_everything(
    TARGET_BINARY,
    target_func_name=TARGET_FUNC_NAME,
    cfg_type="Emulated",
    auto_load_libs=False
)
assert proj is not None and func is not None and cfg is not None and ddg is not None

print_vex(proj, 0x401160)