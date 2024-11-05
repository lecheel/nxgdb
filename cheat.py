import gdb
import re
# from rich import print
from keystone import *
import os
import sys
from colors import colors
from typing import (Any, ByteString, Callable, Dict, Generator, Iterable,
                    Iterator, List, NoReturn, Optional, Sequence, Set, Tuple, Type, TypeVar,
                    Union, cast)
previous_registers = {}
blist = []
cpsr = []

enable_cheats = []
last_xreg = []
last_wreg = []

ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

class Instruction:
    def __init__(self, mnemonic, operands):
        self.mnemonic = mnemonic
        self.operands = operands

class Base:
    def is_branch_taken(self, insn):
        # Base implementation (if any)
        return False, "Base method called"

class Derived(Base):
    """Derived class that overrides the base method."""
    
    def is_branch_taken(self, insn: Instruction) -> Tuple[bool, str]:
        # Define flags from CPSR
        flags_table = {
            31: "Negative (N)",
            30: "Zero (Z)",
            29: "Carry (C)",
            28: "Overflow (V)",
            7:  "Interrupt (I)",
            9:  "Endian (E)",
            6:  "Fast (F)",
            5:  "T32 (T)",
            4:  "M[4]",
        }

        # Get the value of the CPSR register
        cpsr_value = int(gdb.execute("p/x $cpsr", to_string=True).split()[2], 16)
        print(f"CPSR Value: {cpsr_value:#010x}")  # Print CPSR in hex format

        # Check flags based on CPSR value
        for flag, name in flags_table.items():
            if (cpsr_value & (1 << flag)) != 0:
                print(f"{name} flag is set")
            else:
                print(f"{name} flag is not set")

        # Extract mnemonic and operands from the instruction
        mnemo, operands = insn.mnemonic, insn.operands
        taken, reason = False, ""

        if mnemo in {"cbnz", "cbz", "tbnz", "tbz"}:
            reg = f"${operands[0]}"
            op = gef.arch.register(reg)
            print(f"Value in {reg}: {op}")  # Print register value

            if mnemo == "cbnz":
                taken = op != 0
                reason = f"{reg}!=0" if taken else f"{reg}==0"
            
            elif mnemo == "cbz":
                taken = op == 0
                reason = f"{reg}==0" if taken else f"{reg}!=0"

            elif mnemo in {"tbnz", "tbz"}:
                i = int(operands[1].strip().lstrip("#"))

                if mnemo == "tbnz":
                    taken = (op & (1 << i)) != 0
                    reason = f"{reg}&1<<{i}!=0" if taken else f"{reg}&1<<{i}==0"
                
                elif mnemo == "tbz":
                    taken = (op & (1 << i)) == 0
                    reason = f"{reg}&1<<{i}==0" if taken else f"{reg}&1<<{i}!=0"

        return taken, reason

def bid():
    val = "00 00 00 47 4E 55 00"
    val=val.replace(" ","")
    bytes_list = [val[i:i+2] for i in range(0, len(val), 2)]
    # Add '0x' prefix and join with ', '
    ro_start = gdb.parse_and_eval('$rodata_end')-0x1000
    ro_end = gdb.parse_and_eval('$rodata_end')
    data_str = ", ".join(f"0x{byte}" for byte in bytes_list)

    try:
        addr=gdb.execute(f'find /b {ro_start}, {ro_end}, {data_str}', to_string=True)
        if addr[:-1] == 'Pattern not found.':
            print("Error: Pattern not found.")
            return
        data=int(addr.split('\n')[0],16)+7
        i = gdb.inferiors()[0]
        m = i.read_memory(data, 8)
        hex_string = m.tobytes().hex()

        gdb.execute(f'set $bid="{hex_string}"')
        print(f"  set $bid = '{hex_string}' addr: 0x{data:x}")
    except gdb.GdbError as e:
        print(f"An error occurred: {e}")

def main():
    gdb.execute(f'shell clear')
    try:
        msg=gdb.execute('monitor get info', to_string=True)
    except gdb.error as e:
        print(f"yuzu Emulator is not running.")
        return
    print(f"-- {colors['green']} setup main from XXXX.nss {colors['normal']} ----------")
    match = re.search(r'0x([0-9a-f]+)\s+-\s+0x([0-9a-f]+)\s+.*\.nss', msg)
        
    if match:
        start_address = f"0x{match.group(1)}"
        end_address = f"0x{match.group(2)}"
        gdb.execute(f'set $main={start_address}')
        gdb.execute(f'set $main_start={start_address}')
        gdb.execute(f'set $main_end={end_address}')
        print(f"  set {colors['green']}$main = {start_address}{colors['normal']} and is ready 󱨎 yuzu")
    else:
        print(f"{colors['red']}.nss not found using default 0x80004000{colors['normal']}")
        gdb.execute(f'set $main={0x80004000}')
        gdb.execute(f'set $main_start={0x80004000}')

    pattern = r'Heap:\s*0x([0-9a-f]+)\s*-\s*0x([0-9a-f]+)'
    match = re.search(pattern, msg, re.IGNORECASE | re.DOTALL)
    if match:
        heap_start = f"0x{match.group(1)}"
        heap_end = f"0x{match.group(2)}"
        gdb.execute(f'set $heap_start={heap_start}')
        gdb.execute(f'set $heap_end={heap_end}')
        print(f"  set $heap_start = {heap_start} and $heap_end = {heap_end}")

    match = re.search(r'Program Id:\s*0x([0-9a-f]+)', msg)
    if match:
        program_id = f"{match.group(1)}"
        gdb.execute(f'set $cheat_id = 0x{program_id}')
        print(f"  set $cheat_id = 0x{program_id}")

    memory_mapping=gdb.execute(f'monitor get mappings', to_string=True)
    pattern = re.compile(r'(\S+)\s*-\s*(\S+)\s+r--\s+Code\b')

    # Find all matches
    matches = pattern.findall(memory_mapping)

    # remove ./tmp/*.txt 
    file = glob.glob('./tmp/*.txt')
    for f in file:
        os.remove(f)

    # Check if there are at least two matches
    if len(matches) >= 2:
        # Extract the second 'r-- Code' region
        second_r_code = matches[1]
        start_address, end_address = second_r_code
        print(f"󰪩 .rodata 'r-- Code' {start_address} to {end_address}.")
        gdb.execute(f'set $rodata_start = {start_address}')
        gdb.execute(f'set $rodata_end = {end_address}')
        print(f"  set $rodata_start = {start_address} and $rodata_end = {end_address}")
    bid()
    print(f"󰘳  {colors['green']}ops -- {colors['cyan']}si(stepin) / ni(nexti) / u(disassemble) / v(mem) / bpl(breakpoint list) / p(rint) c(ontinue) / q(uit){colors['normal']}") 
    

def go_break_here(addr):
    cmd = f"b *0x{addr:x}"
    info = gdb.execute(cmd, to_string=True)
    match = re.search(r"Breakpoint (\d+)", info)
    if match:
        break_num = match.group(1)
        print(f"Breakpoint number: {break_num}")
        gdb.execute(f"cont")
        gdb.execute(f"delete {break_num}")
    else:
        print("No breakpoint found.")

def go_break_X(addr):
    # print(f"addr: {addr} {type(addr)}")
    addrV = int(addr, 16)
    main_eval = gdb.parse_and_eval('$main')
    base = int(main_eval)
    cmd = f"b *0x{base+addrV:x}"
    info = gdb.execute(cmd, to_string=True)
    match = re.search(r"Breakpoint (\d+)", info)
    if match:
        break_num = match.group(1)
        print(f"Breakpoint number: {break_num}")
        gdb.execute(f"cont")
        gdb.execute(f"delete {break_num}")
    else:
        print("No breakpoint found.")

def gn_break(input):
    input = str(input)
    # check input is hex or number lt 20  
    ret=0
    addr = gdb.parse_and_eval('$pc')
    real_addr = 0
    try:
        if int(input) < 20:
            ret=int(input)
        else:
            ret=int(input)
    except ValueError:
        return 
    if ret < 20:
        addr_str = hex(addr+ret*4)
        real_addr = int(addr_str, 16)
    else:
        # check input hex is part of address last 3 bytes
        xxx=f"{ret:x}"
        # missing boundary last $pc 3 bytes, if last 3 bytes gt NNN then addr=0x1NNN else addr=0xNNN
        # TODO
        if len(xxx) == 3:
            addr_hex = int(addr)
            real_addr = (addr_hex & 0xfffffffffffff000) + ret
        else:
            print("not support")
    # print(f"{real_addr:x}")
    cmd=f"break *0x{real_addr:x}"

    info = gdb.execute(cmd, to_string=True)
    match = re.search(r"Breakpoint (\d+)", info)
    if match:
        break_num = match.group(1)
        print(f"Breakpoint number: {break_num}")
        gdb.execute(f"cont")
        gdb.execute(f"delete {break_num}")
    else:
        print("No breakpoint found.")
    asm_nexti()


def bmark(msg):
    if len(msg)>0:
        msg1 = msg.split(" ")
        main_eval = gdb.parse_and_eval('$main')
        main = int(main_eval)
        info = f"b *0x{main+int(msg1[0],16):x}"
        infos = f"b *0x{main+int(msg1[0],16):x}    <- {msg}"
        blist.append(infos)
        gdb.execute(info)

        # add to remark dict
        remark[int(msg1[0],16)+main] = msg

    else:
        for idx, it in enumerate(blist):
            print(f"{idx}: {it}")

def asm_arm64(assembly):
    # Assemble the assembly instruction
    try:
        encoding, count = ks.asm(assembly)
    except:
        print('ERROR: ' + assembly)
        return
    hex_output = ' '.join(f'{byte:02X}' for byte in encoding)
    # convert to reversed hex 
    cheat_hex = ''.join(f'{byte:02X}' for byte in encoding[::-1])
    # pygments.highlight(hex_output, pygments.lexers.InstructionLexer(), pygments.formatters.TerminalFormatter())
    main_eval = gdb.parse_and_eval('$main_start')
    main = int(main_eval)
    pcaddr_eval = gdb.parse_and_eval('$pc')
    pcaddr = int(pcaddr_eval)
    print(f"---> using current $pc addr=0x{pcaddr:x} -> 0x{(pcaddr-main):x}")
    print(f"{assembly:<16} --> opcode: {hex_output}  --> cheat format : {cheat_hex}")
    cmd = "set {unsigned int} 0x%x = 0x%s" % (pcaddr, cheat_hex)
    # print(cmd)
    save_pc()
    # 󰕍
    remark[pcaddr] = '󰕍'
    gdb.execute(cmd)
    gdb.execute("x/i $pc")

def undo():
    addr = gdb.parse_and_eval('$pc')
    bid = gdb.parse_and_eval('$bid')
    cheatstr= bid.strip('"')
    i = gdb.inferiors()[0]
    m = i.read_memory(addr, 4)
    hex_string = m.tobytes().hex()
    if hex_string == "1f2003d5":
        if os.path.exists(f"./tmp/{cheatstr.upper()}/{addr}.txt"):
            with open(f"./tmp/{addr}.txt", "r") as f:
                old_hex_string = f.read()
                patched_hex = ''.join(old_hex_string[i:i+2] for i in range(0, len(old_hex_string), 2)[::-1])
                cmd = "set {unsigned int} $pc = 0x"+patched_hex
                gdb.execute(cmd)
            os.remove(f"./tmp/{addr}.txt")

def nop():
    addr = gdb.parse_and_eval('$pc')
    i = gdb.inferiors()[0]
    m = i.read_memory(addr, 4)
    hex_string = m.tobytes().hex()
    if hex_string != "1f2003d5":
        if not os.path.exists(f"./tmp/{addr}.txt"):
            with open(f"./tmp/{addr}.txt", "w") as f:
                f.write(hex_string)
        gdb.execute("set {unsigned int} $pc = 0xd503201f")
    else:
        if os.path.exists(f"./tmp/{addr}.txt"):
            print("undo nop")
            with open(f"./tmp/{addr}.txt", "r") as f:
                old_hex_string = f.read()
                patched_hex = ''.join(old_hex_string[i:i+2] for i in range(0, len(old_hex_string), 2)[::-1])
                cmd = "set {unsigned int} $pc = 0x"+patched_hex
                gdb.execute(cmd)
            os.remove(f"./tmp/{addr}.txt")




def get_registers():
    """Return the current state of all registers."""
    return {r.split()[0]: gdb.execute(f"info reg {r.split()[0]}", to_string=True).split()[-1] 
            for r in gdb.execute("info reg", to_string=True).splitlines()[1:] if r.split()[0]}

def print_registers(reg, hexval, val):
    # if reg not pc or sp 
    if reg not in ['pc', 'sp']:
        print(f"{reg}: 0x{hexval} = {val} vs {previous_registers[reg]}")

def get_reg():
    regs = gdb.execute("info all", to_string=True).splitlines()[1:]
    info=[]
    for it in regs:
        # save all x and w prefix registers
        if it.startswith('x') or it.startswith('w'):
            info.append(it)
    print(info)

def track_registers():
    """Track and print changes in registers."""
    global previous_registers
    current_registers = get_registers()

    if previous_registers:
        changed = {r: current_registers[r] for r in current_registers if previous_registers.get(r) != current_registers[r]}
        if changed:
            for reg, value in changed.items():
                # Determine if value is in hexadecimal or decimal
                if value.startswith('0x'):
                    hex_value = value[2:]  # Remove '0x' prefix
                else:
                    hex_value = value
                
                # Convert hex to decimal and handle conversion errors
                try:
                    # Check if value is numeric; if not, skip conversion
                    if hex_value.isdigit() or (hex_value[0] == '-' and hex_value[1:].isdigit()):
                        decimal_value = int(hex_value, 10)  # Convert decimal string directly
                        hex_value = f"{decimal_value:x}"  # Convert back to hex for formatting
                    else:
                        decimal_value = 0  # Default for non-numeric values
                        hex_value = '0'

                    print_registers(reg, hex_value, decimal_value)

                except ValueError:
                    print(f"Error converting {value} to decimal")

    previous_registers = current_registers

def parse_cpsr(cpsr_value):
    """
    Parses the CPSR value and returns the state of relevant flags.
    """
    if not isinstance(cpsr_value, int):
        raise TypeError("cpsr_value must be an integer")
    
    # CPSR is a 32-bit integer; extract flags based on position
    N = (cpsr_value & 0x80000000) >> 31  # Negative Flag
    Z = (cpsr_value & 0x40000000) >> 30  # Zero Flag
    C = (cpsr_value & 0x20000000) >> 29  # Carry Flag
    V = (cpsr_value & 0x10000000) >> 28  # Overflow Flag

    return {
        'N': N,
        'Z': Z,
        'C': C,
        'V': V
    }

def check_branch_condition(flags, condition):
    """
    Checks if the given branch condition is met based on CPSR flags.
    """
    conditions = {
        'lt': lambda flags: flags['N'] != flags['Z'],  # Less than (N != Z)
        'gt': lambda flags: flags['Z'] == 0 and flags['N'] == flags['V'],  # Greater than (Z == 0 and N == V)
        'ge': lambda flags: flags['N'] == flags['V'],  # Greater than or equal to (N == V)
        'cs': lambda flags: flags['C'] == 1,  # Carry Set (C == 1)
        'cbnz': lambda flags: flags['Z'] == 0,  # Compare Branch Not Zero (Z == 0)
        'cbz': lambda flags: flags['Z'] == 1,  # Compare Branch Zero (Z == 1)
        'tbz': lambda flags: flags['Z'] == 0,  # Test and Branch Zero (Z == 0)
    }
    
    if condition not in conditions:
        raise ValueError(f"Unknown condition '{condition}'")
    
    return conditions[condition](flags)

def binfo():

    def extract_registers(instruction):
        """Extract W and X registers from the given assembly instruction."""
        matches = re.findall(r'(\bw\d+\b|\bx\d+\b)', instruction)
        return [m for m in matches if m.startswith('w')], [m for m in matches if m.startswith('x')]

    def print_current_register_values(registers):
        """Print the current values of specified registers in 'xN = value' format."""
        for reg in registers:
            hex_value = gdb.execute(f"p/x ${reg}", to_string=True).strip()
            index = hex_value.find('=')
            hex_value = hex_value[index+2:]
            
            # Transforming the output format directly
            transformed_line = f"{reg} = {hex_value}"
            print(transformed_line)            

    def print_last_accessed_registers(last_x, last_w):
        """Print the values of the last accessed X and W registers."""
        for reg in last_x + last_w:
            value = gdb.execute(f"p/x ${reg}", to_string=True).strip()
            index = value.find('=')
            value = value[index+2:]
            print(f"Last Register {reg} = {value}")

    global last_xreg, last_wreg

    try:
        # Retrieve CPSR value and current instruction
        cpsr_value = int(gdb.execute("p/x $cpsr", to_string=True).split()[2], 16)
        current_instruction = gdb.execute("x/i $pc", to_string=True).strip()
        
        print(f"CPSR: {cpsr_value:08x}, Instruction: {current_instruction}")

        # Extract registers from the instruction
        w_registers, x_registers = extract_registers(current_instruction)

        # Print last accessed registers
        print_last_accessed_registers(last_xreg, last_wreg)

        # Print current register values in the desired format
        print_current_register_values(x_registers)

        # Update last accessed registers
        last_wreg, last_xreg = w_registers, x_registers


    except Exception as e:
        print(f"Error occurred: {e}")

def replace_variable_names(text, new_name):
    pattern = r'\$(\d+) ='
    return re.sub(pattern, f'{new_name} =', text)

def go_overBL():
    addr = gdb.parse_and_eval('$pc')
    addr_str = "0x"+hex(addr+4)[2:].zfill(16)
    # print(addr_str)

    cmd = f"b *{addr_str}"
    info = gdb.execute(cmd, to_string=True)
    match = re.search(r"Breakpoint (\d+)", info)
    if match:
        break_num = match.group(1)
        print(f"Breakpoint number: {break_num}")
        gdb.execute(f"cont")
        gdb.execute(f"delete {break_num}")
    else:
        print("No breakpoint found.")


def dispreg():
    addr=gdb.parse_and_eval("$pc")
    cmd = f"disassemble {addr-0x10},{addr+0x20}"
    asm = gdb.execute(cmd, to_string=True)
    pattern = r'\b(w\d+|s\d+|x\d+)\b'

    matches = re.findall(pattern, asm)
    sorted_matches = sorted(set(matches))

    # print reg like x0=nnnnn x2=nnnnnnn ... 4 in line
    for match in sorted_matches:
        value = gdb.parse_and_eval(f"${match}")
        try:
            int_value = int(value)
            print(f"{colors['cyan']}{match}{colors['normal']}=0x{int_value:08x} ", end=" ")
        except gdb.error:
            pass

    print()
    for i in range(0,10):
        try:
            xxx = gdb.parse_and_eval(f"$r{i}")
            if int(xxx) == 0:
                continue
            print(f"{colors['yellow']}$r{i}{colors['normal']}=0x{int(xxx):0x}",end=" ")
        except gdb.error:
            pass
    print()

def nexti_with_track():
    gdb.execute("x/i $pc")
    gdb.execute("nexti")
    dispreg()

    # binfo()
    # track_registers()

    """
    asm=gdb.execute("x/i $pc", to_string=True)
    print(asm)
    mnemo, operands = parse_instruction(asm)
    # how insn from mnemo and operands

    insn = Instruction(mnemo, operands)
    derived_instance = Derived()
    taken, reason = derived_instance.is_branch_taken(insn)
    print(f"Taken: {taken}, Reason: {reason}")
    """
    # gdb.execute("x/i $pc")
    asm_nexti()

def parse_instruction(asm: str) -> Tuple[str, list]:
    """Parse the assembly instruction string to extract mnemonic and operands."""
    match = re.match(r'^\s*([a-zA-Z]+)\s+(.*)', asm)
    if match:
        mnemo = match.group(1)
        operands = match.group(2).split(',') if match.group(2) else []
        return mnemo, [op.strip() for op in operands]
    return "", []

def u32_search(val):
    try:
        hex_val = f'0x{int(val):08x}'
        # Ensure the range is within the heap region
        cmd = f'find {heap_start}, {heap_end}, {hex_val}'
        print(cmd)
        gdb.execute(f'find {heap_start}, {heap_end}, {hex_val}')
    except ValueError as e:
        print(f"Invalid value: {val}. Please provide a valid integer value.")
        print(f"Error: {e}")

def aob(val):
    # val="f6 0303 2a f3 03 02 2a"
    # remove spaces 
    val=val.replace(" ","")
    bytes_list = [val[i:i+2] for i in range(0, len(val), 2)]
    # Add '0x' prefix and join with ', '
    main_start = gdb.parse_and_eval('$main_start')
    main_end = gdb.parse_and_eval('$main_end')
    data_str = ", ".join(f"0x{byte}" for byte in bytes_list)
    gdb.execute(f'set pagination off') # set pagination off
    try:
        gdb.execute(f'find /b {main_start}, {main_end}, {data_str}')
    except gdb.GdbError as e:
        print(f"An error occurred: {e}")

def cheat_from_file(patch_id=None):
    cheats = []
    cheat_id=str(gdb.parse_and_eval('$bid'))
    main_addr=gdb.parse_and_eval('$main')
    cheatstr=cheat_id
    # remove the quote
    cheatstr= cheatstr.strip('"')
    # cheatstr = hex(cheat_id)[2:].zfill(16)
    file =f"./gdb/{cheatstr.upper()}.txt"
    try:
        with open(file, "r") as f:
            lines = f.readlines()
            current_cheat_name = None
            current_values = []

            for line in lines:
                line = line.strip()
                
                if not line:
                    continue  # Skip empty lines

                # Check if the line starts with a cheat name
                cheat_name_match = re.search(r'\[(.*?)\]', line)
                if cheat_name_match:
                    # Save the previous cheat's data before starting a new one
                    if current_cheat_name:
                        cheats.append((current_cheat_name, current_values))
                    
                    # Start a new cheat entry
                    current_cheat_name = cheat_name_match.group(1).strip()
                    current_values = []
                    continue
                
                # Check if the line starts with '040' for values
                if line.startswith('040'):
                    parts = line.split()
                    if len(parts) >= 2:
                        values = parts[1:]  # Values after the prefix
                        current_values.append(values)

            # Append the last cheat entry after finishing the loop
            if current_cheat_name and current_values:
                cheats.append((current_cheat_name, current_values))

    except FileNotFoundError:
        print(f"File {file} not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
    
    if patch_id is None:
        for idx, it in enumerate(cheats):
            # print max length of list 40 chars
            if len(it[1])>2:
                # less then 20 chars fill with spaces
                print(f"{colors['green']}{idx}{colors['normal']}: {it[0][:30].ljust(30, ' ')} --> {it[1][:2]} {colors['yellow']}...{colors['normal']}")
            else:
                print(f"{colors['green']}{idx}{colors['normal']}: {it[0][:30].ljust(30, ' ')} --> {it[1]}")
        print(f"  {colors['blue']}{enable_cheats}{colors['normal']}")
    else:
        patch_id = int(patch_id)
        print(f"\nPatching code: {cheats[patch_id]}")
        enable_cheats.append(cheats[patch_id][0])
        # check how many values
        for it in cheats[patch_id][1]:
            cheat_code_str = f"0x{it[1]}"
            cheat_addr_str = f"0x{it[0]}"
            cheat_addr = int(cheat_addr_str, 16)+main_addr
            cmd="set {unsigned int} 0x%x = %s" % (cheat_addr, cheat_code_str)
            # print(cmd)
            gdb.execute(cmd)
 
def __nx_prompt__(current_prompt: Callable[[Callable], str]) -> str:
    cpsr = gdb.execute("p $cpsr", to_string=True).strip().splitlines()
    cpsr_prompt = [s.split('=', 1)[-1].strip() for s in cpsr if '=' in s]
    prompt = f"({colors['yellow']}nx{colors['normal']}) {cpsr_prompt[0]} "
    return prompt


gdb.prompt_hook = __nx_prompt__
main()
