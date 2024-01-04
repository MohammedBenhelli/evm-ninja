from hashlib import sha3_256

from binaryninja import (
    LLIL_TEMP,
    Architecture,
    ExpressionIndex,
    LowLevelILFunction,
    LowLevelILLabel,
    LowLevelILOperation,
    RegisterName,
)

EVM_ADDR_SIZE = 32

NUMBER_BLOCK_MAGIC = 0x2600cafe

BLOCKHASH_MAGIC = 0x2600cafe2600cafe

ADDRESS_MAGIC = 0xcafecafecafe

BALANCE_MAGIC = 0xcafe

ORIGIN_MAGIC = 0xcafecafe

CALLER_MAGIC = 0xcafecafe

CALLVALUE_MAGIC = 0xcafe260042


def push_helper(il: LowLevelILFunction, imm: ExpressionIndex) -> ExpressionIndex:
    return il.push(EVM_ADDR_SIZE, imm)


def stop(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.no_ret()


def add(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.add(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE)))


def mul(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.mult(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE)))


def sub(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.sub(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE)))


def div(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.div_unsigned(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE)))


def sdiv(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.div_signed(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE)))


def mod(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.mod_unsigned(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE)))


def smod(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.mod_signed(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE)))


def addmod(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.mod_unsigned(
        EVM_ADDR_SIZE,
        il.add(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE)),
        il.pop(EVM_ADDR_SIZE),
    ))


def mulmod(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.mod_unsigned(
        EVM_ADDR_SIZE,
        il.mult(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE)),
        il.pop(EVM_ADDR_SIZE),
    ))


def exp(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def signextend(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def lt(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.compare_unsigned_less_than(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE)))


def gt(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il,
                       il.compare_unsigned_greater_than(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE)))


def slt(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.compare_signed_less_than(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE)))


def sgt(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.compare_signed_greater_than(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE)))


def eq(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.compare_equal(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE)))


def iszero(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.compare_equal(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.const(EVM_ADDR_SIZE, 0)))


def and_(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.and_expr(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE)))


def or_(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.or_expr(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE)))


def xor(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.xor_expr(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE)))


def not_(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.not_expr(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE)))


def byte_(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.append(il.unimplemented()))


def shl(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.shift_left(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE)))


def shr(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.logical_shift_right(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE)))


def sar(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.arith_shift_right(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE)))


def sha3(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    # return il.push(EVM_ADDR_SIZE, il.const(EVM_ADDR_SIZE, int.from_bytes(sha3_256(il.pop(EVM_ADDR_SIZE)).digest(), "big")))
    # return il.append(il.unimplemented())
    return push_helper(il, il.expr(size=EVM_ADDR_SIZE, operation='sha3', a=il.pop(EVM_ADDR_SIZE)))


def address(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.const(EVM_ADDR_SIZE, ADDRESS_MAGIC))


def balance(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.const(EVM_ADDR_SIZE, BALANCE_MAGIC))


def origin(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.const(EVM_ADDR_SIZE, ORIGIN_MAGIC))


def caller(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.const(EVM_ADDR_SIZE, CALLER_MAGIC))


def callvalue(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.const(EVM_ADDR_SIZE, CALLVALUE_MAGIC))


def calldataload(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def calldatasize(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def calldatacopy(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def codesize(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def codecopy(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def gasprice(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def extcodesize(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def extcodecopy(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def returndatasize(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def returndatacopy(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def extcodehash(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def blockhash(il: LowLevelILFunction, addr: int, imm: int) -> list[ExpressionIndex]:
    return [
        il.pop(EVM_ADDR_SIZE),
        push_helper(il, il.const(EVM_ADDR_SIZE, BLOCKHASH_MAGIC)),
    ]


def coinbase(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def timestamp(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def number(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.const(EVM_ADDR_SIZE, NUMBER_BLOCK_MAGIC))
    # return push_helper(il, il.expr(size=EVM_ADDR_SIZE, operation='number', a=il.const(EVM_ADDR_SIZE, NUMBER_BLOCK_MAGIC)))


def prevrandao(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def gaslimit(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def chainid(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def selfbalance(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def basefee(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def pop(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.pop(EVM_ADDR_SIZE)


def mload(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.load(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE)))


def mstore(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.store(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE))


def mstore8(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.store(1, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE))


def sload(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.load(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE)))


def sstore(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.store(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE))


def jump(il: LowLevelILFunction, addr: int, imm: int) -> list[ExpressionIndex]:
    dest = il.pop(EVM_ADDR_SIZE)

    push = il[len(il) - 1] if len(il) > 0 else None

    if (push is not None and
            push.operation == LowLevelILOperation.LLIL_PUSH and
            push.src.operation == LowLevelILOperation.LLIL_CONST):
        dest = il.const(EVM_ADDR_SIZE, push.src.constant)
        il.append(il.set_reg(EVM_ADDR_SIZE, LLIL_TEMP(0), il.pop(EVM_ADDR_SIZE)))

    # We need to use a temporary register here. The il.if_expr() helper
    # function makes a tree and evaluates the condition's il.pop()
    # first, but dest needs to be first.
    il.append(il.set_reg(EVM_ADDR_SIZE, LLIL_TEMP(addr), dest))

    il.append(il.jump(il.reg(EVM_ADDR_SIZE, LLIL_TEMP(addr))))

    return []


def jumpi(il: LowLevelILFunction, addr: int, imm: int) -> list[ExpressionIndex]:
    dest = il.pop(EVM_ADDR_SIZE)

    push = il[len(il) - 1] if len(il) > 0 else None

    if (push is not None and
            push.operation == LowLevelILOperation.LLIL_PUSH and
            push.src.operation == LowLevelILOperation.LLIL_CONST):
        dest = il.const(EVM_ADDR_SIZE, push.src.constant)
        il.append(il.set_reg(EVM_ADDR_SIZE, LLIL_TEMP(1), il.pop(EVM_ADDR_SIZE)))
    else:
        il.append(dest)

    t = LowLevelILLabel()
    f = il.get_label_for_address(Architecture["EVM"], addr + 1)
    must_mark = False

    if f is None:
        f = LowLevelILLabel()
        must_mark = True

    # We need to use a temporary register here. The il.if_expr() helper
    # function makes a tree and evaluates the condition's il.pop()
    # first, but dest needs to be first.
    # il.append(il.set_reg(EVM_ADDR_SIZE, LLIL_TEMP(addr), dest))

    il.append(il.set_reg(EVM_ADDR_SIZE, LLIL_TEMP(0), il.pop(EVM_ADDR_SIZE)))
    il.append(il.if_expr(il.reg(EVM_ADDR_SIZE, LLIL_TEMP(0)), t, f))

    il.mark_label(t)
    il.append(il.jump(il.unimplemented()))  # il.reg(EVM_ADDR_SIZE, LLIL_TEMP(1))))

    if must_mark:
        il.mark_label(f)
        # false is the fall through case
        il.append(il.jump(il.const(EVM_ADDR_SIZE, addr + 1)))

    return []


def pc(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def msize(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def gas(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def jumpdest(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def tload(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return push_helper(il, il.load(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE)))


def tstore(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.store(EVM_ADDR_SIZE, il.pop(EVM_ADDR_SIZE), il.pop(EVM_ADDR_SIZE))


def push0(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.push(EVM_ADDR_SIZE, il.const(EVM_ADDR_SIZE, 0))


def push(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.push(EVM_ADDR_SIZE, il.const(EVM_ADDR_SIZE, imm))


def dup(il: LowLevelILFunction, addr: int, distance: int) -> list[ExpressionIndex]:
    il.append(
        il.set_reg(
            EVM_ADDR_SIZE, LLIL_TEMP(0), il.load(
                EVM_ADDR_SIZE, il.add(
                    EVM_ADDR_SIZE, il.reg(EVM_ADDR_SIZE, RegisterName("sp")),
                    il.const(EVM_ADDR_SIZE, (distance - 1) * EVM_ADDR_SIZE),
                ),
            ),
        ),
    )
    # val = il.pop(EVM_ADDR_SIZE)
    il.append(il.push(EVM_ADDR_SIZE, il.reg(EVM_ADDR_SIZE, LLIL_TEMP(0))))
    return []
    # return [il.push(EVM_ADDR_SIZE, val) for _ in range(distance)]


def swap(il: LowLevelILFunction, addr: int, distance: int) -> list[ExpressionIndex]:
    stack_offset = distance * EVM_ADDR_SIZE

    load = il.load(
        EVM_ADDR_SIZE, il.add(
            EVM_ADDR_SIZE,
            il.reg(EVM_ADDR_SIZE, RegisterName("sp")),
            il.const(EVM_ADDR_SIZE, stack_offset),
        ),
    )

    il.append(il.set_reg(EVM_ADDR_SIZE, LLIL_TEMP(0), load))

    il.append(
        il.set_reg(
            EVM_ADDR_SIZE, LLIL_TEMP(1),
            il.load(EVM_ADDR_SIZE, il.reg(EVM_ADDR_SIZE, RegisterName("sp"))),
        ),
    )

    il.append(
        il.store(
            EVM_ADDR_SIZE, il.add(
                EVM_ADDR_SIZE, il.reg(EVM_ADDR_SIZE, RegisterName("sp")),
                il.const(EVM_ADDR_SIZE, stack_offset),
            ),
            il.reg(EVM_ADDR_SIZE, LLIL_TEMP(1)),
        ),
    )
    il.append(
        il.store(
            EVM_ADDR_SIZE, il.reg(EVM_ADDR_SIZE, RegisterName("sp")),
            il.reg(EVM_ADDR_SIZE, LLIL_TEMP(0)),
        ),
    )

    return []


def log(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def create(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def call(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def callcode(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def return_(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.ret(il.pop(EVM_ADDR_SIZE))


def delegatecall(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def staticcall(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.append(il.unimplemented())


def revert(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.no_ret()


def invalid(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.no_ret()


# TODO: can we do better?
def selfdestruct(il: LowLevelILFunction, addr: int, imm: int) -> ExpressionIndex:
    return il.ret(il.pop(EVM_ADDR_SIZE))
