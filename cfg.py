
from .classes import Block, Function, Instruction
from .constants import EVM_BLOCK_END, EVM_FUNCTION_RETURN
from .disas import disassemble_bytecode


class CFG:
    blocks: dict[int, "Block"]
    bytecode: bytes
    functions: dict[int, "Function"]
    instructions: dict[int, "Instruction"]
    computed_branches: dict[int, bool]
    # TODO: fake storage, memory, transient-memory, stack and tx.globals

    def __init__(self, bytecode: bytes) -> None:
        self.blocks = {}
        self.bytecode = bytecode
        self.functions = {}
        self.instructions = {}
        self.computed_branches = {}
        self.create_functions()

    def create_functions(self) -> None:
        self.compute_blocks()
        # self.compute_functions(self.blocks[0])

        # Add unconnected block
        for block in self.blocks.values():
            # TODO: cond need to be improved
            if block.start.location not in self.functions:
                self.compute_functions(block)

    def compute_blocks(self) -> None:
        block = Block(instructions=[])
        for op in disassemble_bytecode(self.bytecode):
            self.instructions[op.location] = op

            if op.name == "JUMPDEST":
                if block.instructions:
                    self.blocks[block.end.location] = block
                block = Block(instructions=[])
                self.blocks[op.location] = block

            block.add_instruction(op)
            if block.start.location == op.location:
                self.blocks[op.location] = block

            if block.end.name in EVM_BLOCK_END:
                self.blocks[block.end.location] = block
                block = Block(instructions=[])

    def compute_functions(self, block: "Block") -> None:
        if block.start.location == 0 and block.start.location not in self.functions:
            self.functions[block.start.location] = Function(
                hash_value=hash(block),
                start=block.start.location,
                blocks=[block],
                name=hex(block.start.location),
            )

        # WARNING: PAS FAN DU TOUT DE CETTE CONDITION
        if block.start.location == 0 and block.end_with("JUMPI"):
            true_branch = block.true_branch_destination
            self.compute_functions(self.blocks[true_branch])
            return

        if block.end.name in EVM_FUNCTION_RETURN:
            new_function = Function(
                hash_value=hash(block),
                start=block.start.location,
                blocks=[block],
                name=hex(block.start.location),
            )
            self.functions[block.start.location] = new_function
            return

        # TODO: compute all block of a function
        if block.start.location not in self.functions and block.start_with("JUMPDEST"):
            new_function = Function(
                hash_value=hash(block),
                start=block.start.location,
                blocks=[block],
                name=hex(block.start.location),
            )
            self.functions[block.start.location] = new_function


def is_jump_to_function(block: Block):
    has_calldata_size = False
    last_pushed_value = None
    previous_last_pushed_value = None
    for i in block.instructions:
        if i.name == "CALLDATASIZE":
            has_calldata_size = True

        if i.name.startswith("PUSH"):
            previous_last_pushed_value = last_pushed_value
            last_pushed_value = i.var.value

    if block.end_with("JUMPI") and has_calldata_size:
        return last_pushed_value, -1

    if block.end_with("JUMPI") and previous_last_pushed_value:
        return last_pushed_value, previous_last_pushed_value

    return None, None
