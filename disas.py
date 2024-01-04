from collections.abc import Iterator
from functools import cache

from binaryninja import log_debug

from .classes import Instruction, Variable
from .constants import EVM_OPCODES, LOGGER_SYMBOL


@cache
def disassemble_one(bytecode: bytes, location: int = 0) -> Instruction:
    if len(bytecode) == 0 or location >= len(bytecode):
        return Instruction(location=-1, name="EOF", size=0)
    hex_op = hex(bytecode[location])[2:]
    if hex_op not in EVM_OPCODES:
        log_debug(f"Unknown opcode {hex_op} at {hex(location)}", LOGGER_SYMBOL)
        return Instruction(location=-2, name="UNKNOWN", size=1)
    op = EVM_OPCODES[hex_op]
    # log_debug(f"Disassembling {op[0]} at {hex(location)}", LOGGER_SYMBOL)
    return Instruction(
        location=location,
        name=op[0],
        size=op[-1],
        input_length=op[1],
        output_length=op[2],
        var=Variable(
            value=int.from_bytes(bytecode[location + 1:location + op[-1]], byteorder="big"),
        ) if op[-1] > 1 else Variable(value=0),
    )


def disassemble_bytecode(bytecode: bytes) -> Iterator["Instruction"]:
    log_debug(f"Disassembling {len(bytecode)} bytes of bytecode", LOGGER_SYMBOL)
    location = 0
    while True:
        if (op := disassemble_one(bytecode, location)).name != "EOF":
            yield op
            location += op.size
        else:
            return None
