import z3
import sys
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import ExprAssign, ExprInt
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.ir.translators.z3_ir import TranslatorZ3

'''
return values of the function and their corresponding addresses

return 0: 0x40071b
return 1: 0x400714
return 2: 0x4005ee
return 3: 0x400678
return 4: 0x4006f0
return 5: 0x4006f7
return 6: 0x400706
return 7: 0x40070d
'''


class CustomSeEngine(SymbolicExecutionEngine):
    """ Subclass symbolic execution engine to add custom funcitonality"""

    def __init__(self, lifter):
        super().__init__(lifter)

    def save_symbolic_state(self):
        """Saves the current symbolic state"""
        return self.symbols.copy()

    def restore_symbolic_state(self, symbolic_state):
        """Restores a given symbolic state"""
        self.symbols.clear()
        self.set_state(symbolic_state)


def check_path_constraints(path_constraints):
    """Checks if a list of path constraints is satisfiable"""
    global loc_db
    # init solver
    solver = z3.Solver()
    # init miasm -> z3 translator
    translator = TranslatorZ3(loc_db=loc_db)
    # walk over all path constraints of the form: next_block := cond ? src1 : src2 == <enforced block>
    for c in path_constraints:
        # enforce that src1 != src2
        solver.add(translator.from_expr(c.dst.src1) !=
                   translator.from_expr(c.dst.src2))
        # enforce next_block == <enforced block>
        solver.add(translator.from_expr(c))
    # check if satisfiable
    if solver.check() == z3.sat:
        # parse model output
        model = solver.model()
        rdi = z3.BitVec("RDI", 64)
        rsi = z3.BitVec("RSI", 64)
        rdx = z3.BitVec("RDX", 64)
        print(
            "./samples/input_crafting_challenge {} {} {}".format(model[rdi], model[rsi], model[rdx]))
        return True
    else:
        return False


if __name__ == "__main__":
    # check args
    if len(sys.argv) < 4:
        print("[x] Syntax: {} <file> <start addr> <end addr>".format(sys.argv[0]))
        sys.exit()
    # parse arguments
    file_path = sys.argv[1]
    start_addr = int(sys.argv[2], 16)
    end_addr = int(sys.argv[3], 16)
    # init symbol table
    loc_db = LocationDB()
    # read binary file
    container = Container.from_stream(open(file_path, 'rb'), loc_db)
    # get CPU abstraction
    machine = Machine(container.arch)
    # disassembly engine
    mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)
    # init intermediate representation analysis (IRA) / lifter class
    lifter = machine.lifter_model_call(mdis.loc_db)
    # asm cfg and ira cfg
    asm_cfg = mdis.dis_multiblock(start_addr)
    ira_cfg = lifter.new_ircfg_from_asmcfg(asm_cfg)
    # init customized SE engine
    sb = CustomSeEngine(lifter)
    # worklist for symbolic exploration. start at provided start address
    worklist = [(ExprInt(start_addr, 64), sb.save_symbolic_state(), [])]
    # perform a breadth first search by following the native code execution flow and exploring both sides of conditional branches
    while len(worklist) != 0:
        # get current exploration state -- current block, symbolic state and path constraints
        current_block, symbolic_state, path_constraints = worklist.pop(0)
        # if current block is target address -> verify if path constraints can be satisfied
        if current_block.is_int() and int(current_block) == end_addr:
            print(
                f"Checking if path constraints can be satisfied for address {hex(end_addr)}.")
            # exit program if we found a satisfiable path
            if check_path_constraints(path_constraints):
                exit()
        # restore symbolic state from worklist
        sb.restore_symbolic_state(symbolic_state)
        # sequentially follow execution flow until we reach a conditional jump
        next_block = sb.run_block_at(ira_cfg, current_block)
        # next block is concrete address or label => add to worklist
        if next_block.is_int() or next_block.is_loc():
            # define new state
            state = (
                # next block
                next_block,
                # re-use current symbolic state
                sb.save_symbolic_state(),
                # do not modify path constraints
                path_constraints
            )
            # add state to worklist
            worklist.append(state)
            continue
        # next block is conditional jump which depends on user input -> add both branch targets to the worklist
        if next_block.is_cond():
            # state1: true case, jump taken
            state1 = (
                # jump to target of true case
                next_block.src1,
                # save symbolic state
                sb.save_symbolic_state(),
                # add path constraint: next_block == next_block.src1
                path_constraints + [ExprAssign(next_block, next_block.src1)]
            )
            # state2: false case, jump not taken
            state2 = (
                # jump to target of false case
                next_block.src2,
                # save symbolic state
                sb.save_symbolic_state(),
                # add path constraint: next_block == next_block.src1
                path_constraints + [ExprAssign(next_block, next_block.src2)]
            )
            # add states to worklist
            worklist.append(state1)
            worklist.append(state2)
            continue