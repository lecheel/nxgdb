# from rich import print
# from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
from keystone import *
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
import sys
import os
import argparse

C_green = "\033[32m"
C_red = "\033[31m"
C_cyan = "\033[36m"
C_reset = "\033[0m"
C_yellow = "\033[33m"                

# code powered by the laichi 2024
# https://github.com/Atmosphere-NX/Atmosphere/blob/master/docs/features/cheats.md#code-type-0x8-begin-keypress-conditional-block
# thanks the decoder logic from breeze project and atmosphere project
# Define the keypad mask values
keypad_values = {
    0x0000001: 'A',
    0x0000002: 'B',
    0x0000004: 'X',
    0x0000008: 'Y',
    0x0000010: 'Left Stick Pressed',
    0x0000020: 'Right Stick Pressed',
    0x0000040: 'L',
    0x0000080: 'R',
    0x0000100: 'ZL',
    0x0000200: 'ZR',
    0x0000400: 'Plus',
    0x0000800: 'Minus',
    0x0001000: 'Left',
    0x0002000: 'Up',
    0x0004000: 'Right',
    0x0008000: 'Down',
    0x0010000: 'Left Stick Left',
    0x0020000: 'Left Stick Up',
    0x0040000: 'Left Stick Right',
    0x0080000: 'Left Stick Down',
    0x0100000: 'Right Stick Left',
    0x0200000: 'Right Stick Up',
    0x0400000: 'Right Stick Right',
    0x0800000: 'Right Stick Down',
    0x1000000: 'SL',
    0x2000000: 'SR',
}


def opcode_asm(opcode,addr):
    asm_code = []
# Create a disassembler object for ARM64
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    opcode_hex = int(opcode, 16)
    # in little endian
    opcode = opcode_hex.to_bytes(4, byteorder='little').hex()
    # print(f"Opcode: {opcode} {type(opcode)} {opcode_hex}")
    code = bytes.fromhex(opcode)
    for insn in md.disasm(code, addr):  # 0x1000 is the starting address
        # print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
        asm_code.append(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
    return asm_code

def hex_0TMR00AA(hex_string):
    # Split the hex string into three 32-bit parts
    first_dword, second_dword, third_dword = hex_string.split()
    
    dasm=opcode_asm(third_dword,int(second_dword, 16))
    if len(dasm) == 0:
        dasm=['invalid opcode']
    # Convert to integers
    first_dword = int(first_dword, 16)
    second_dword = int(second_dword, 16)
    third_dword = int(third_dword, 16)
    
    # Extract components from first_dword
    bit_width = (first_dword >> 24) & 0xF
    mem_type = (first_dword >> 20) & 0xF
    offset_register = (first_dword >> 16) & 0xF
    rel_address = ((first_dword & 0xFF) << 32) | second_dword
    
    # Extract value from third_dword
    value = third_dword
    
    # Define memory types
    mem_type_str = ["Main", "Heap", "Alias"]
    
    # Format the opcode components
    if bit_width == 8:
        opcode_str = f"{C_Green}[{mem_type_str[mem_type]}+R{offset_register}+0x{rel_address:010X}{C_reset}]=0x{value:016X}"
    elif bit_width == 4:
        opcode_str = f"[{mem_type_str[mem_type]}+R{offset_register}+0x{rel_address:010X}]=0x{value:08X}"
    elif bit_width == 2:
        opcode_str = f"[{mem_type_str[mem_type]}+R{offset_register}+0x{rel_address:010X}]=0x{value:04X}"
    elif bit_width == 1:
        opcode_str = f"[{mem_type_str[mem_type]}+R{offset_register}+0x{rel_address:010X}]=0x{value:02X}"
    else:
        raise ValueError("Invalid bit width")
 
    return opcode_str, dasm

def hex_1TMC00AA(first_dword, second_dword, third_dword):
    if verbose:
        print("""
BeginConditionalBlock 1TMC00AA AAAAAAAA YYYYYYYY 
T: Width of memory write (1, 2, 4, or 8 bytes)      1, 8
M: Memory region to write to 0 = Main NSO, 1 = Heap, 2 = Alias
C: Condition to use                                 1, 6
A: Immediate offset to use from memory region base  0, 15
A: Immediate offset to use from memory region base  0, 15
""")
    bit_width = (first_dword >> 24) & 0xF
    mem_type = (first_dword >> 20) & 0xF
    cond_type = (first_dword >> 16) & 0xF
    rel_address = ((first_dword & 0xFF) << 32) | second_dword
    value = third_dword

    mem_type_str = {0: "Main", 1: "Heap", 2: "Alias"}
    cond_type_str = {0: "condition0"}  # Add more conditions as needed

    formatted_str = f"If [{mem_type_str.get(mem_type, 'Unknown')}+0x{rel_address:010X}] {cond_type_str.get(cond_type, 'Unknown')}0x{value:08X}"

    return formatted_str

def hex_2X000000(hex_value):
    # Convert hex value to integer
    int_value = int(hex_value, 16)
    end_type = (int_value >> 20) & 0xF
    
    # Determine the type of end block
    if end_type == 0:
        return "End"
    elif end_type == 1:
        return "Else"
    else:
        return "Unknown"

def hex_5TMRI0AA(hex_string):
    if verbose:
        print(""" 
LoadRegisterMemory 5TMRI0AA AAAAAAAA                0, 15
T: Width of memory load (1, 2, 4, or 8 bytes)       1, 8
M: Memory region to load from 0 = Main NSO, 1 = Heap, 2 = Alias(not supported by atm)
R: Register to load                                 0, 15
I: Load from register                               0, 1
A: Immediate offset to use from memory region base, 0, 15
A: Immediate offset to use from memory region base, 0, 15
    """)
    # Split the hex string into two 32-bit parts
    first_dword, second_dword = hex_string.split()
    
    # Convert to integers
    first_dword = int(first_dword, 16)
    second_dword = int(second_dword, 16)
    
    # Extract the components from first_dword
    bit_width = (first_dword >> 24) & 0xF
    mem_type = (first_dword >> 20) & 0xF
    reg_index = (first_dword >> 16) & 0xF
    load_from_reg = (first_dword >> 12) & 0xF
    rel_address = ((first_dword & 0xFF) << 32) | second_dword
    
    # Format the opcode components
    if load_from_reg == 1:
        opcode_str = f"R{reg_index}=[R{reg_index}+0x{rel_address:010X}] W={bit_width}"
    elif load_from_reg == 2:
        mem_type_str = ["Main", "Heap", "Alias"][mem_type]
        opcode_str = f"R{reg_index}=[{mem_type_str}+R{reg_index}+0x{rel_address:010X}] W={bit_width}"
    else:
        mem_type_str = ["Main", "Heap", "Alias"][mem_type]
        opcode_str = f"R{reg_index}=[{mem_type_str}+0x{rel_address:010X}] W={bit_width}"
    
    return opcode_str

def hex_6T0RIor0(hex_string):
    if verbose:
        print("""
StoreStaticToAddress 6T0RIor0 VVVVVVVV VVVVVVVV
T: Width of memory write (1, 2, 4, or 8 bytes) 
R: Register used as base memory address     0, 15
I: Increment register flag                  0, 1
o: Offset register enable flag              0, 1
r: Register used as offset when o is 1      0, 15
""")

    # Split the hex string into three 32-bit parts
    first_dword, second_dword, third_dword = hex_string.split()
    # Convert to integers
    first_dword = int(first_dword, 16)
    second_dword = int(second_dword, 16)
    third_dword = int(third_dword, 16)
    # Extract components from first_dword
    bit_width = (first_dword >> 24) & 0xF
    reg_index = (first_dword >> 16) & 0xF
    increment_reg = (first_dword >> 12) & 0xF
    add_offset_reg = (first_dword >> 8) & 0xF
    offset_reg_index = (first_dword >> 4) & 0xF
    # Combine second and third dword to form the full value
    value = ((second_dword << 32) | third_dword)
    # Format the opcode components
    if add_offset_reg:
        opcode_str = f"[R{reg_index}+R{offset_reg_index}]=0x{value:016X} W={bit_width}"
    else:
        opcode_str = f"[R{reg_index}]=0x{value:016X} W={bit_width}"
    if increment_reg:
        opcode_str += f" R{reg_index}+=W"
    return opcode_str



def hex_7T0RC000(hex_string):
    if verbose:
        print("""
PerformArithmeticStatic 7T0RC000 VVVVVVVV          0, 15
T: Width of memory write (1, 2, 4, or 8 bytes)     1, 8 
R: Register to apply arithmetic to                 0, 15
C: Arithmetic operation to apply                   0, 4 
    """)
    # Split the hex string into two 32-bit parts
    first_dword, second_dword = hex_string.split()
    
    # Convert to integers
    first_dword = int(first_dword, 16)
    second_dword = int(second_dword, 16)
    
    # Extract components from first_dword
    bit_width = (first_dword >> 24) & 0xF
    reg_index = (first_dword >> 16) & 0xF
    math_type = (first_dword >> 12) & 0xF
    value = second_dword
    
    # Define arithmetic operation strings
    math_str = ["", "+", "-", "*", "/"]  # Example, modify according to actual operations
    
    # Format the opcode components
    opcode_str = f"R{reg_index}=R{reg_index} {math_str[math_type]}0x{value:08X} W={bit_width}"
    
    return opcode_str
 
def hex_8kkkkkkk(hex_value):
    # Convert hex value to integer
    int_value = int(hex_value, 16)
    
    # Find which keys are pressed based on the mask
    pressed_keys = []
    for mask, key in keypad_values.items():
        if int_value & mask:
            pressed_keys.append(key)
    
    return pressed_keys

def hex_9TCRSIs0(hex_string):
    math_str = [" ADD ", " SUB ", " MUL ", " DIV ", " MOD ", " AND ", " OR ", " XOR ", " SHL ", " SHR "]
    # Convert hex strings to integers
    first_dword, second_dword = hex_string.split()
    
    # Convert to integers
    first_dword = int(first_dword, 16)
    second_dword = int(second_dword, 16)

    # Extract bits based on the opcode structure
    bit_width = (first_dword >> 24) & 0xF
    math_type = (first_dword >> 20) & 0xF
    dst_reg_index = (first_dword >> 16) & 0xF
    src_reg_1_index = (first_dword >> 12) & 0xF
    has_immediate = ((first_dword >> 8) & 0xF) != 0

    if has_immediate:
        value = second_dword  # Immediate value is in the second dword
        if bit_width == 8:
            formatted_value = f"0x{value:016X}"
        elif bit_width == 4:
            formatted_value = f"0x{value:08X}"
        elif bit_width == 2:
            formatted_value = f"0x{value:04X}"
        elif bit_width == 1:
            formatted_value = f"0x{value:02X}"
        opcode_str = f"R{dst_reg_index}=R{src_reg_1_index}{math_str[math_type]}{formatted_value} W={bit_width}"
    else:
        src_reg_2_index = (first_dword >> 4) & 0xF
        if math_type in range(7) or math_type == 8:
            opcode_str = f"R{dst_reg_index}=R{src_reg_1_index}{math_str[math_type]}R{src_reg_2_index} W={bit_width}"
        elif math_type == 7:
            opcode_str = f"R{dst_reg_index}=!R{src_reg_1_index} W={bit_width}"
        elif math_type == 9:
            opcode_str = f"R{dst_reg_index}=R{src_reg_1_index} W={bit_width}"

    return opcode_str

def decode_cheatcode(cheatcode):
    supported_cheatcodes = ['0', '2', '5', '6', '7', '8','9',chr(0x5B)]
    parts = cheatcode.split()
    if parts[0][:1] not in supported_cheatcodes:
        print(f"---> {C_red}Unsupported cheatcode{C_reset}: {parts[0]}")
        return
    if parts[0][:1] == chr(0x5B):
        # concat the list 
        msg = ' '.join(parts)
        # replace [ and ] to -< >- 
        # msg = msg.replace('[', '{').replace(']', '}')
        print(f"{C_yellow}{msg}{C_reset}")
    if parts[0].startswith('0'):
        decoded,dasm = hex_0TMR00AA(cheatcode)
        # print(f"Decoded 0TMR00AA -> {C_green}{cheatcode}{C_reset}")
        print(f"{C_green}{decoded}{C_reset} -> {C_cyan}{dasm[0]}{C_reset}")

    if parts[0].startswith('2'):
        decoded = hex_2X000000(cheatcode)
        print(f"Decoded 2X00000 -> {C_green}{cheatcode}{C_reset}")
        print(decoded)

    if parts[0].startswith('5'):
        decoded = hex_5TMRI0AA(cheatcode)
        print(f"Decoded 5TMRI0AA AAAAAAAA -> {C_green}{cheatcode}{C_reset}")
        print(decoded)

    if parts[0].startswith('6'):
        decoded = hex_6T0RIor0(cheatcode)
        print(f"Decoded 6T0RIor0 VVVVVVVV VVVVVVVV -> {C_green}{cheatcode}{C_reset}")
        print(decoded)
        
    if parts[0].startswith('7'):
        decoded = hex_7T0RC000(cheatcode)
        print(f"Decoded 7T0RC000 VVVVVVVV -> {C_green}{cheatcode}{C_reset}")
        print(decoded)

    if parts[0].startswith('8'):
        decoded = hex_8kkkkkkk(cheatcode)
        print(f"Decoded 8kkkkkkk -> {C_green}{cheatcode}{C_reset}")
        print(decoded)

    if parts[0].startswith('9'):
        print("[red] *** not tested *** [/red]")
        decoded = hex_9TCRSIs0(cheatcode)
        print(f"Decoded 9TCRSIs0 VVVVVVVV (VVVVVVVV) -> {C_green}{cheatcode}{C_reset}")
        print(decoded)

verbose = False  # Set to True to enable verbose output

"""
cheatcode = ["580f0000 02cc5fe0",
             "780f0000 00005d90",
             "640f0000 00000000 00015b38",
             "04000000 010B9684 11001508",
             ]  # Hexadecimal instruction

ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
for instruction in cheatcode:
    decode_cheatcode(instruction)
    print("")

"""

ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
if len(sys.argv) > 1:
    cheatcode = sys.argv[1]
    try:
        with open(cheatcode, 'r') as f:
            cheatcode = f.read()
    except:
        print(f"Failed to open {cheatcode}")
        exit(1)
    for it in cheatcode.splitlines():
        if len(it) == 0: continue
        decode_cheatcode(it)
