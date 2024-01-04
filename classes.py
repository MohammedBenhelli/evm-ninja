from dataclasses import dataclass, field
from enum import IntEnum
from threading import Thread
import z3

from binaryninja import BackgroundTaskThread

from .constants import EVM_CHANGE_STATE_OPCODES, EVM_IMPURE_OPCODES


@dataclass
class _Thread(Thread):
    task: "BackgroundTaskThread"

    def run(self):
        ...


@dataclass
class Variable:
    value: int
    tainted: bool = False


@dataclass
class FakeStack:
    values: list[Variable] = field(default_factory=list)

    def push(self, value: int) -> None:
        self.values.append(Variable(value=value))

    def pop(self) -> int:
        return self.values.pop().value

    def peek(self) -> int:
        return self.values[-1].value

    def __len__(self) -> int:
        return len(self.values)

    def swap(self, param):
        pass


@dataclass
class Block:
    instructions: list["Instruction"]

    def add_instruction(self, instruction: "Instruction") -> None:
        self.instructions.append(instruction)

    @property
    def start(self) -> "Instruction":
        return self.instructions[0]

    @property
    def end(self) -> "Instruction":
        return self.instructions[-1]

    def end_with(self, mnemonic: str) -> bool:
        return self.end.name == mnemonic

    def start_with(self, mnemonic: str) -> bool:
        return self.start.name == mnemonic

    def contains(self, mnemonic: str) -> bool:
        return any(i.name == mnemonic for i in self.instructions)

    def __hash__(self):
        return hash(self.start.location)

    @property
    def non_dyn_jumpdests(self) -> set[int]:
        jumpdests = set()
        for i, op in enumerate(self.instructions):
            if op.name in ["JUMP", "JUMPI"] and self.instructions[i - 1].name.startswith("PUSH"):
                jumpdests.add(self.instructions[i - 1].var.value)
        return jumpdests

    @property
    def to_constraints(self):
        constraints = []
        for inst in self.instructions:
            pass
        return constraints

    # TODO: iterate in reverse on the instructions to compute the jump destination?
    @property
    def true_branch_destination(self) -> int:
        # fs = FakeStack()
        # for instruction in self.instructions:
        #     if instruction.name == "JUMPDEST":
        #         pass
        #     elif instruction.name == "JUMP":
        #         pass
        #     elif instruction.name == "JUMPI":
        #         fs.pop()
        #         return fs.pop()
        #     elif instruction.name.startswith("PUSH"):
        #         fs.push(instruction.value)
        #     elif instruction.name.startswith("DUP"):
        #         fs.swap(int(instruction.name[3:]))
        #     elif instruction.name == "SWAP":
        #         fs.swap(int(instruction.name[4:]))
        for instruction in reversed(self.instructions):
            if instruction.name.startswith("PUSH"):
                return instruction.var.value
        return 0

    @property
    def false_branch(self):
        pass

    @property
    def true_branch(self):
        pass

    def __contains__(self, address: int) -> bool:
        return self.start.location <= address <= self.end.location


@dataclass
class Instruction:
    location: int
    name: str
    size: int
    input_length: int = 0
    output_length: int = 0
    var: Variable = None
    # WARNING: probably useless
    stack_inputs: list[int] = None
    stack_outputs: list[int] = None


@dataclass
class Function:
    hash_value: int
    start: int
    blocks: list[Block]
    name: str
    attributes: set[str] = field(default_factory=set)

    @property
    def is_payable(self) -> bool:
        if "payable" in self.attributes:
            return True
        if self.entry_block.contains("CALLVALUE"):
            self.attributes.add("payable")
            return True
        return False

    @property
    def entry_block(self) -> Block:
        return self.blocks[0]

    @property
    def is_pure(self) -> bool:
        if "pure" in self.attributes:
            return True
        for opcode in EVM_IMPURE_OPCODES:
            if self.entry_block.contains(opcode):
                return False
        self.attributes.add("pure")
        return True

    @property
    def is_view(self) -> bool:
        if "view" in self.attributes:
            return True
        for opcode in EVM_CHANGE_STATE_OPCODES:
            if self.entry_block.contains(opcode):
                return False
        self.attributes.add("view")
        return True


class BranchEnum(IntEnum):
    UnconditionalBranch = 0
    FalseBranch = 1
    TrueBranch = 2
    CallDestination = 3
    FunctionReturn = 4
    Call = 5
    DelegateCall = 6
    CreateCall = 7
    Creat2Call = 8
    IndirectBranch = 9
    ExceptionBranch = 10


@dataclass
class Branch:
    type: BranchEnum
    target: int = None
