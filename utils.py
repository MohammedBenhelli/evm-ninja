import string

from binaryninja import log_info

from .constants import LOGGER_SYMBOL


def convert_bytecode(bytecode: bytes) -> bytes:
    bytecode_str = bytecode.decode(errors="ignore")
    if bytecode.startswith(b"0x") and set(bytecode_str[2:]).issubset(string.hexdigits):
        log_info("Converting bytecode from hex string to bytes", LOGGER_SYMBOL)
        return bytes.fromhex(bytecode_str[2:])
    if set(bytecode_str).issubset(string.hexdigits):
        log_info("Converting bytecode from hex string to bytes", LOGGER_SYMBOL)
        return bytes.fromhex(bytecode_str)
    return bytecode
