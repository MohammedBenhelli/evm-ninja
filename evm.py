from abc import ABC

from binaryninja import (
    LLIL_TEMP,
    Architecture,
    BinaryView,
    BranchType,
    Endianness,
    Function,
    InstructionInfo,
    InstructionTextToken,
    InstructionTextTokenType,
    LowLevelILFunction,
    Platform,
    RegisterInfo,
    RegisterName,
    Settings,
    SettingsScope,
    Symbol,
    SymbolType,
    log_debug,
)
from interval3 import Interval, IntervalSet

from .cfg import CFG
from .constants import (
    EVM_ADDR_SIZE,
    EVM_CODE_SEGMENT,
    EVM_FUNCTION_EXCEPTION,
    EVM_FUNCTION_RETURN,
    EVM_OPCODES_EMULATION,
    EVM_SWARM_HASH_PREFIX,
    EVM_SWARM_HASH_SEGMENT,
    EVM_SWARM_HASH_SUFFIX,
    LOGGER_SYMBOL,
)
from .disas import disassemble_one
from .utils import convert_bytecode
from .vsa import VsaNotification


# TODO: clean code
global_cfg: CFG


class EVM(Architecture):
    name: str = "EVM"
    address_size: int = EVM_ADDR_SIZE
    default_int_size: int = EVM_ADDR_SIZE
    endianness: int = Endianness.BigEndian
    instr_alignment: int = 1
    max_instr_length: int = EVM_ADDR_SIZE + 1
    regs: dict = {
        "sp": RegisterInfo(RegisterName("sp"), EVM_ADDR_SIZE),
        "code": RegisterInfo(RegisterName("code"), EVM_ADDR_SIZE),
        "callvalue": RegisterInfo(RegisterName("callvalue"), EVM_ADDR_SIZE),
        "mstore": RegisterInfo(RegisterName("mstore"), EVM_ADDR_SIZE),
        "sstore": RegisterInfo(RegisterName("sstore"), EVM_ADDR_SIZE),
        "tstore": RegisterInfo(RegisterName("tstore"), EVM_ADDR_SIZE),
    }
    stack_pointer: str = "sp"

    def get_true_branch(self: "EVM", addr: int) -> int | bool:
        global global_cfg
        if addr in global_cfg.computed_branches:
            return global_cfg.computed_branches[addr][0].target
        return False

    def get_instruction_info(self: "EVM", data: bytes, addr: int):
        global global_cfg
        instruction = disassemble_one(data)
        if instruction.name == "EOF":
            return None
        result = InstructionInfo()
        result.length = instruction.size
        if instruction.name == "JUMP":
            # TODO compute potential jump branch
            if (dest := self.get_true_branch(addr)) is not False:
                # log_debug(f"Resolved branch at {addr}: {dest}", LOGGER_SYMBOL)
                result.add_branch(BranchType.TrueBranch, dest + 1)
            else:
                log_debug(f"Unresolved branch at {addr}", LOGGER_SYMBOL)
                result.add_branch(BranchType.UnresolvedBranch)
        elif instruction.name == "JUMPI":
            # TODO compute TrueBranch
            if (dest := self.get_true_branch(addr)) is not False:
                result.add_branch(BranchType.TrueBranch, dest + 1)
            else:
                log_debug(f"Unresolved branch at {addr}", LOGGER_SYMBOL)
                result.add_branch(BranchType.UnresolvedBranch)
            result.add_branch(BranchType.FalseBranch, addr + 1)
        elif instruction.name in EVM_FUNCTION_EXCEPTION:
            result.add_branch(BranchType.ExceptionBranch, addr)
        elif instruction.name in EVM_FUNCTION_RETURN:
            result.add_branch(BranchType.FunctionReturn)

        return result

    def get_instruction_text(self: "EVM", data: bytes, addr: int):
        instruction = disassemble_one(data)
        if instruction.name == "EOF":
            return None

        tokens = [InstructionTextToken(
            InstructionTextTokenType.InstructionToken,
            f"{instruction.name:7} ",
        )]
        # TODO handle more tokens
        if instruction.name == "PUSH20":
            tokens.append(
                InstructionTextToken(
                    InstructionTextTokenType.PossibleAddressToken,
                    hex(instruction.var.value),
                    instruction.var.value,
                ),
            )
        elif instruction.size > 1:
            tokens.append(
                InstructionTextToken(
                    InstructionTextTokenType.IntegerToken,
                    hex(instruction.var.value),
                    instruction.var.value,
                ),
            )

        return tokens, instruction.size

    def get_instruction_low_level_il(self: "EVM", data: bytes, addr: int, il: LowLevelILFunction) -> int | None:
        instruction = disassemble_one(data)
        # log_debug(f"Emulating {instruction.name} {addr} {data}", LOGGER_SYMBOL)

        ill = EVM_OPCODES_EMULATION.get(instruction.name, None)
        if ill is None:
            log_debug(f"Emulation of {instruction.name} not implemented", LOGGER_SYMBOL)
            for i in range(instruction.input_length):
                il.append(
                    il.set_reg(EVM_ADDR_SIZE, LLIL_TEMP(i), il.pop(EVM_ADDR_SIZE)),
                )
            for i in range(instruction.output_length):
                il.append(il.push(EVM_ADDR_SIZE, il.unimplemented()))
            il.append(il.nop())
            return instruction.size

        # log_debug(f"Emulating {instruction.name} with {ill.__name__}", LOGGER_SYMBOL)
        ils = ill(il, addr, instruction.var.value)

        if isinstance(ils, list):
            for res in ils:
                il.append(res)
        else:
            il.append(ils)

        return instruction.size

    def assemble(self: "EVM", code: str, addr: int = 0) -> bytes:
        return b"test"


class EVMView(BinaryView, ABC):
    arch: Architecture
    long_name: str = "Ethereum Virtual Machine Bytecode"
    max_function_size_for_analysis: int
    name: str = "EVM"
    platform: Platform
    raw: BinaryView

    def __init__(self: "EVMView", bv: BinaryView) -> None:
        BinaryView.__init__(self, parent_view=bv, file_metadata=bv.file)
        self.raw = bv

    def init(self: "EVMView") -> bool:
        global global_cfg
        self.arch = Architecture["EVM"]
        self.max_function_size_for_analysis = 0
        self.platform = Architecture["EVM"].standalone_platform
        bytecode = convert_bytecode(self.raw.read(0, self.raw.length))
        code = IntervalSet([Interval(0, len(bytecode))])

        # TODO: virer cette lib interval3 de ses morts
        #  + extraire des metadata propre (et compatile avec tt les compilos)
        #  => https://www.rareskills.io/post/solidity-metadata
        for start, sz in self.find_swarm_hashes(bytecode):
            self.add_auto_segment(
                start,
                sz,
                start,
                sz,
                EVM_SWARM_HASH_SEGMENT,
            )
            code -= IntervalSet([Interval(start, start + sz)])

        for interval in code:
            if isinstance(interval, int):
                continue
            self.add_auto_segment(
                interval.lower_bound,
                interval.upper_bound,
                interval.lower_bound,
                interval.upper_bound,
                EVM_CODE_SEGMENT,
            )

        cfg = CFG(bytecode)
        global_cfg = cfg
        self.register_notification(VsaNotification())
        Function.set_default_session_data("cfg", cfg)
        self.add_entry_point(0)

        # TODO: flag delegate as library func and CALL has external func

        for function in cfg.functions.values():
            log_debug(f"Adding function at {function.start}", LOGGER_SYMBOL)
            function_start = function.start if function.start != 0 else 0
            self.define_auto_symbol(
                Symbol(
                    SymbolType.FunctionSymbol,
                    function_start,
                    function.name,
                ),
            )
            self.add_function(function_start)

        # TODO: extract potential selectors from code
        # for function in self.functions:
        #     function.analysis_skipped = True

        return Settings().set_bool(
            "analysis.linearSweep.autorun",
            False,
            view=self,
            scope=SettingsScope.SettingsResourceScope,
        )

    # ? A swarm hash is 32 bytes long and has a 9 byte prefix with 2 bytes of suffix like this regex:
    # r'\xa1\x65\x62\x7a\x7a\x72\x30\x58\x20[\x00-\xff]{32}\x00\x29'
    # See http://solidity.readthedocs.io/en/v0.4.24/metadata.html#encoding-of-the-metadata-hash-in-the-bytecode
    @staticmethod
    def find_swarm_hashes(bytecode: bytes) -> list:
        rv = []
        offset = bytecode.find(EVM_SWARM_HASH_PREFIX)
        while offset != -1:
            if bytecode[offset + 41:offset + 43] != EVM_SWARM_HASH_SUFFIX:
                continue
            log_debug(f"Adding r-- segment at: {offset}", LOGGER_SYMBOL)
            rv.append((offset, 43))
            offset = bytecode.find(EVM_SWARM_HASH_PREFIX, offset + 1)
        return rv

    @staticmethod
    def get_entry_point() -> int:
        return 0

    @staticmethod
    def is_valid_for_data(bv: BinaryView) -> bool:
        return bv.file.original_filename.endswith(".evm")

    @staticmethod
    def is_executable() -> bool:
        return True

    def perform_get_address_size(self: "EVMView") -> int:
        return self.arch.address_size
