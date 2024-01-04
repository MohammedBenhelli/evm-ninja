from vyper import compile_code

from smt import find_reachability
from utils import convert_bytecode

if __name__ == "__main__":
    with open("basic_add.vy") as f:
        out = compile_code(f.read(), ["bytecode_runtime"], obfuscate=False)
        print(out["bytecode_runtime"][2:])
        bytecode = convert_bytecode(out["bytecode_runtime"][2:].encode('ascii'))
        find_reachability(bytecode, start_addr=0x00, end_addr=0x2c)
