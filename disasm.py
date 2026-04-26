# disasm.py
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64


def get_disassembler(architecture):
    """
    Create the correct Capstone disassembler based on PE architecture.
    """
    if architecture == "x86":
        return Cs(CS_ARCH_X86, CS_MODE_32)

    if architecture == "x64":
        return Cs(CS_ARCH_X86, CS_MODE_64)

    raise ValueError(f"Unsupported architecture: {architecture}")


def disassemble_bytes(code_bytes, start_address, architecture, max_instructions=40):
    """
    Disassemble raw bytes into a list of instruction dictionaries.
    """
    md = get_disassembler(architecture)

    instructions = []

    for index, insn in enumerate(md.disasm(code_bytes, start_address)):
        instructions.append({
            "address": insn.address,
            "mnemonic": insn.mnemonic.lower(),
            "op_str": insn.op_str.lower(),
            "bytes": insn.bytes.hex()
        })

        if index + 1 >= max_instructions:
            break

    return instructions