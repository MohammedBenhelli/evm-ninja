import copy

import z3

from .cfg import CFG
from .classes import Block
from .constants import EVM_BITVEC_SIZE


class SymbolicEVMState:
    storage: {int, z3.BitVec or z3.BitVecVal}
    transient_storage: {int, z3.BitVec or z3.BitVecVal}
    memory:  {int, z3.BitVec or z3.BitVecVal}
    stack: [z3.BitVec or z3.BitVecVal]
    tx_globals: {str, z3.BitVecVal or z3.BitVecVal}
    calldata: {int, z3.BitVec or z3.BitVecVal}

    def __init__(self, storage=None, transient_storage=None, memory=None, stack=None) -> None:
        self.storage = storage if storage is not None else {}
        self.transient_storage = transient_storage if transient_storage is not None else {}
        self.memory = memory if memory is not None else {}
        self.stack = stack if stack is not None else []


class SymbolicEVMEngine:
    cfg: CFG
    solver: z3.Solver
    # TODO: sym_state
    symbolic_state: SymbolicEVMState

    def __init__(self, cfg: CFG, debug=False) -> None:
        self.cfg = cfg
        self.solver = z3.Solver(logFile=f"s_evm_debug_log.smt2" if debug else None)
        self.symbolic_state = SymbolicEVMState()

    def breadth_first_reachability(self, start_addr: int, end_addr: int) -> []:
        print(self.cfg.blocks.keys())
        start_block = self.cfg.blocks.get(start_addr, None)
        if start_block is None:
            raise Exception(f"{start_addr=} does not belong to a block start")
        # TODO: check if the block is connected to the end_addr
        print(self.cfg.computed_branches[start_addr])
        worklist = [[start_block, self.save_symbolic_state(), []]]

        while len(worklist) != 0:
            current_block, symbolic_state, path_constraints = worklist.pop(0)
            if end_addr in current_block and self.check_path_constraints(path_constraints):
                print("Path constraints can be satisfied")
                return path_constraints
            self.restore_symbolic_state(symbolic_state)
            next_block = self.run_block_at(current_block)
            if not next_block.is_cond():
                worklist.append([
                    next_block,
                    self.save_symbolic_state(),
                    path_constraints
                ])
            else:
                # True branch
                worklist.append([
                    next_block.true_branch,
                    self.save_symbolic_state(),
                    path_constraints + [next_block == next_block.true_branch]
                ])
                # True branch
                worklist.append([
                    next_block.false_branch,
                    self.save_symbolic_state(),
                    path_constraints + [next_block == next_block.false_branch]
                ])
        return []

    def save_symbolic_state(self) -> SymbolicEVMState:
        return copy.deepcopy(self.symbolic_state)

    def restore_symbolic_state(self, symbolic_state: SymbolicEVMState):
        self.set_state(symbolic_state)

    def set_state(self, symbolic_state: SymbolicEVMState) -> None:
        self.symbolic_state = copy.deepcopy(symbolic_state)

    def check_path_constraints(self, path_constraints) -> bool:
        pass

    def run_block_at(self, current_block) -> Block:
        pass


def find_reachability(bytecode: bytes, start_addr: int, end_addr: int) -> []:
    s_evm = SymbolicEVMEngine(CFG(bytecode))
    return s_evm.breadth_first_reachability(start_addr, end_addr)
