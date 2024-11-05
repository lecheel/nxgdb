import argparse
from keystone import *
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from rich import print

def reverse_byte_order(hex_string):
    """Reverse the byte order of a hex string."""
    return ''.join(hex_string[i:i+2] for i in range(0, len(hex_string), 2)[::-1])

def disassemble_bytes(reversed_bytes, offset):
    """Disassemble reversed bytes and return formatted instructions."""
    instructions = []
    for instruction in md.disasm(reversed_bytes, offset):
        instructions.append(f"04000000 {instruction.address:04x} {reversed_bytes.hex()}     [green]{instruction.mnemonic} {instruction.op_str}[/green]")
    return instructions

def process_file(input_file, show_asm):
    """Process the input file and print results."""
    try:
        with open(input_file, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[red]Error:[/red] The file {input_file} was not found.")
        return

    for line in lines:
        line = line.split()
        if len(line) > 1:
            offset = int(line[0], 16)
            hex_string = line[1]
            reversed_bytes_str = reverse_byte_order(hex_string)
            reversed_bytes = bytes.fromhex(reversed_bytes_str)

            if show_asm:
                instructions = disassemble_bytes(reversed_bytes, offset)
                for inst in instructions:
                    print(inst)
            else:
                print(f"04000000 {line[0]} {reversed_bytes_str}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file", type=str, help="The input file to be processed")
    parser.add_argument("--asm", action='store_true', help="Optional show asm")
    args = parser.parse_args()

    ks = keystone.Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    process_file(args.input_file, args.asm)
