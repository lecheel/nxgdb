import glob
import os
import struct
import gdb
from colors import colors
import re 
import struct
import json
import zmq
import paho.mqtt.client as mqtt

remark={}
r_register = []
global filtered_addresses


class GeneralBreakpoint(gdb.Breakpoint):
    """General breakpoint class to monitor specified register values."""
    
    def __init__(self, addr, registers):
        # Convert the integer address to a string in hexadecimal format
        super(GeneralBreakpoint, self).__init__(f"*{hex(addr)}")
        self.silent = True  # Suppress default breakpoint message
        # self.registers = [reg.strip() for reg in registers.split(",")]
        register_str = str(registers)  # Ensure registers is a string
        self.registers = [reg.strip() for reg in register_str.split(",")]
        self.addr = addr

    def stop(self):
        try:
            for reg in self.registers:
                reg = reg.replace('"', '')
                cmd = f"p ${reg}"
                info = gdb.execute(cmd, to_string=True)
                index = info.find('=')
                value = info[index + 2:] if index != -1 else "N/A"
                addr_val = int(self.addr)
                print(f"{addr_val:x} {reg} = {value[:-1]}")
        except gdb.error as e:
            print(f"Error while accessing registers: {e}")    
        return False

def wbp_wrapper():
    addr = gdb.parse_and_eval('$addr')
    addr_str = hex(addr)[2:].zfill(8)
    regs = gdb.parse_and_eval('$regs')
    register_str = str(regs)
    GeneralBreakpoint(addr, register_str)

def extract_reg(instruction):
    """Extract W, X, and D registers from the given assembly instruction."""
    matches = re.findall(r'\b(w\d+|x\d+|d\d+)\b', instruction)
    reg_w = [m for m in matches if m.startswith('w')]
    reg_x = [m for m in matches if m.startswith('x')]
    reg_d = [m for m in matches if m.startswith('d')]

    # areg_x = [f"x{int(m[1:]):02}" for m in reg_x]
    # areg_w = [f"w{int(m[1:]):02}" for m in reg_w]
    # areg_d = [f"d{int(m[1:]):02}" for m in reg_d]


    unique_regs = set(reg_w + reg_x + reg_d)
    # sort the registers
    unique_regs = sorted(unique_regs)
    return list(unique_regs)

def update_regs(xxx):
    global filtered_addresses
    filtered_addresses = []
    for addr in r_register:
        addr = addr.strip()  # Strip leading/trailing whitespace
        if addr:  # Ensure it's not empty
            parts = addr.split()
            if len(parts) > 1:
                # Get the second part and remove the trailing colon
                address = parts[1].rstrip(':')
            else:
                # Handle cases where there's only one part
                address = parts[0].rstrip(':') if parts[0] else ''

            if address:  # Only append if the address is not empty
                filtered_addresses.append(address)
 
    # only 10 registers can be set at a time
    filtered_addresses = filtered_addresses[:10]
    for idx,it in enumerate(filtered_addresses):
        gdb.execute(f"set $r{idx}={it}")
 
def print_gdbwin(info):
    all_regs = set()
    for line in info:
        all_regs.update(extract_reg(line))
    regs = sorted(all_regs)
    # Prepare the contents for registers in 3 columns
    reg_lines = []

    for i in range(0, len(regs), 3):  # Process registers in groups of 3
        try:
            # Evaluate register values and format them
            data = [f"{regs[j]} = {gdb.parse_and_eval('$' + regs[j])}" 
                    for j in range(i, min(i + 3, len(regs)))]
            reg_lines.append(' '.join(data))
        except Exception as e:
            print(f"Error evaluating registers: {e}")

    reg_values = '\n'.join(reg_lines)  # Join lines with newline
    with open("./tmp/regs.txt", "w") as f:
        f.write(reg_values)


def check_db(xxx):
    # Trim the input string based on its prefix
    if xxx.startswith("=>"):
        xxx = xxx[3:-1]
    else:
        xxx = xxx[:-1]

    # Convert the hexadecimal string to an integer
    dat = int(xxx, 16)

    # Return the corresponding remark if exists, else return an empty string
    return remark.get(dat, "")

def asm_print_db(xxx, opcode):
    parts = xxx.split('\t')
    conv_part = ""

    # Check if there are enough parts and if the third part contains a number
    if len(parts) > 2:
        number_part = parts[2].split("#")
        if len(number_part) > 1 and 'x' not in number_part[1]:
            conv_part = "//" + convert_scientific_to_float(number_part[1])

    # Apply color to the parts
    rem = ""
    for i in range(len(parts)):

        if i == 0:
            r_register.append(parts[i])
            rem=check_db(parts[i])
        elif i == 1:
            parts[i] = f"{opcode}   {colors['green']}{parts[i]}{colors['normal']}" 
        elif i == 2:
            parts[i] = f"{colors['cyan']}{parts[i]}{colors['normal']}\t{conv_part}"
        elif i == 3:
            parts[i] = f"{colors['yellow']}{parts[i]}{colors['normal']}"
        else:
            parts[i] = f"{colors['normal']}{parts[i]}{colors['normal']}" 

    rem = rem or ""
    print('\t'.join(parts) + "\t "+colors['yellow'] + rem+colors['normal'])

def update_gdbwin():
    # publisher with topic asm/pc 
    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    client.connect("localhost", 1883, 60)
    act_pc = gdb.parse_and_eval('$pc')
    basemain = gdb.parse_and_eval('$main')
    print(f"{act_pc} {act_pc-basemain}")
    client.publish("asm/pc", str(act_pc))
    client.disconnect()

    
    # touch /tmp/pc.txt
    # with open("/tmp/pc.txt", "w") as f:
        # f.write(str(gdb.parse_and_eval('$pc')))

def format_bytes(it):
    # Execute the GDB command to read 4 bytes at the address 'it'
    opcode = gdb.execute(f"x/4b {it}", to_string=True)
    
    # Extract the relevant lines from the output
    lines = opcode.splitlines()
    
    # Initialize a list to hold the formatted byte values
    formatted_bytes = []
    
    for line in lines:
        # Split each line and extract the byte values
        parts = line.split(':')
        if len(parts) > 1:
            # Get the byte values and remove '0x' prefix
            bytes_part = parts[1].strip().split()
            formatted_bytes.extend(byte[2:] for byte in bytes_part)  # Remove '0x'
    
    # Join the formatted bytes into a single string
    result = ' '.join(formatted_bytes)
    
    return result

def asm_next():
    addr = gdb.parse_and_eval('$pc')
    with open("./tmp/frame.txt", "w+") as f:
        for it in range(addr-0x10, addr+0x60, 4):
            try:
                asm = gdb.execute(f"x/i {it}", to_string=True)
                opcode = format_bytes(it)
                asm_print_db(asm[:-1], opcode)
                # save asm[:-1] to file frame
                f.write(asm[:-1] + "\n")
            except gdb.error:
                pass
    naddr = addr+0x100
    gdb.execute(f"set $npc={naddr}")
    update_gdbwin()

 
def asm_nexti():
    addr = gdb.parse_and_eval('$pc')
    asms = []
    with open("./tmp/frame.txt", "w+") as f:
        for it in range(addr-0x40, addr+0x40, 4):
            try:
                asm = gdb.execute(f"x/i {it}", to_string=True)
                asms.append(asm[:-1])
                f.write(asm[:-1] + "\n")
            except gdb.error:
                pass
    print_gdbwin(asms)
    update_gdbwin()

def asm_prev():
    addr = gdb.parse_and_eval('$pc')
    for it in range(addr-0x60, addr+0x10, 4):
        asm = gdb.execute(f"x/i {it}", to_string=True)
        opcode = format_bytes(it)
        asm_print_db(asm[:-1],opcode)
 
def rem_asm(msg):
    addr = gdb.parse_and_eval('$pc')
    if addr in remark:
        print(f"--->{remark[addr]}")
    else:
        # add msg to remark dict with addr 
        remark[int(addr)] = msg
    print(remark)

def import_cheat():
    cheats = []
    cheat_id=str(gdb.parse_and_eval('$bid'))
    main_addr=gdb.parse_and_eval('$main')
    cheatstr=cheat_id

    if len(remark) > 0:
        return
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

    for idx,it in enumerate(cheats):
        if idx>0:
            if (len(it[1])>0):
                for addr in it[1]:
                    new_addr=int(addr[0],16)+main_addr
                    remark[int(new_addr)] = it[0]

def save_pc():

    addr = gdb.parse_and_eval('$pc')
    pc = gdb.parse_and_eval('$pc')
    bid = gdb.parse_and_eval('$bid')
    cheat_str = str(bid).strip('"')
    pc_str = "0x"+hex(pc)[2:].zfill(16)
    pcname = f"./tmp/{cheat_str.upper()}/{pc_str}.txt"
    if not os.path.exists(f"./tmp/{cheat_str.upper()}"):
        os.makedirs(f"./tmp/{cheat_str.upper()}")
    if not os.path.exists(pcname):
        with open(pcname, "w") as f:
            i = gdb.inferiors()[0]
            m = i.read_memory(addr, 4)
            hex_string = m.tobytes().hex()
            f.write(hex_string)

def undo_pc():

    addr = gdb.parse_and_eval('$pc')
    pc = gdb.parse_and_eval('$pc')
    bid = gdb.parse_and_eval('$bid')
    cheat_str = str(bid).strip('"')
    pc_str = "0x"+hex(pc)[2:].zfill(16)
    pcname = f"./tmp/{cheat_str.upper()}/{pc_str}.txt"
    if os.path.exists(pcname):
        with open(pcname, "r") as f:
            old_hex_string = f.read()
            patched_hex = ''.join(old_hex_string[i:i+2] for i in range(0, len(old_hex_string), 2)[::-1])
            cmd = "set {unsigned int} $pc = 0x"+patched_hex
            gdb.execute(cmd)
        # os.remove(pcname)
        print(f"{colors['red']}undo{colors['reset']} $pc")



def asm_print(xxx):
    parts = xxx.split('\t')
    conv_part = ""

    # Check if there are enough parts and if the third part contains a number
    if len(parts) > 2:
        number_part = parts[2].split("#")
        if len(number_part) > 1 and 'x' not in number_part[1]:
            conv_part = "//" + convert_scientific_to_float(number_part[1])

    # Apply color to the parts
    for i in range(len(parts)):

        if i == 0:
            r_register.append(parts[i])
        elif i == 1:
            parts[i] = f"{colors['green']}{parts[i]}{colors['normal']}" 
        elif i == 2:
            parts[i] = f"{colors['cyan']}{parts[i]}{colors['normal']}\t{conv_part}"
        elif i == 3:
            parts[i] = f"{colors['yellow']}{parts[i]}{colors['normal']}"
        else:
            parts[i] = f"{colors['normal']}{parts[i]}{colors['normal']}" 

    print('\t'.join(parts))

def convert_scientific_to_float(line):
    # Regular expression to find floating-point numbers in scientific notation
    # pattern = r'([-+]?\d*\.?\d+([eE][-+]?\d+)?)'
    pattern = r'([-+]?\d*\.\d+([eE][-+]?\d+)?)|([-+]?\d+([eE][-+]?\d+)?)'
 
    def replace(match):
        num_str = match.group(0)
        float_num = float(num_str)
        return f"{float_num}" 

    # Replace all occurrences in the line
    new_line = re.sub(pattern, replace, line)
    return new_line

def asm_ops(xxx):
    addr = gdb.parse_and_eval('$pc')
    for it in range(addr, addr+0x2000, 4):
        asm = gdb.execute(f"x/i {it}", to_string=True)
        opcode = format_bytes(it)
        if xxx in asm:
            asm_print_db(asm[:-1],opcode)
        if "ret" in asm:
            break

  
def remarks():
    # beautify remarks
    # print(remark)
    if len(remark) == 0:
        load_db()
    for idx,it in enumerate(remark):
        print(f"{idx}: 0x{int(it):x} {remark[it]}")

def save_db():
    cheat_id=str(gdb.parse_and_eval('$bid'))[1:-1].upper()
    savename = f"./gdb/{cheat_id}.json"
    # save remark in json 
    if len(remark) > 0:
        with open(savename, "w") as f:
            json.dump(remark, f)

def load_db():
    cheat_id=str(gdb.parse_and_eval('$bid'))[1:-1].upper()
    savename = f"./gdb/{cheat_id}.json"
    if os.path.exists(savename):
        with open(savename, "r") as f:
            global remark
            remark = json.load(f)

def ops(cmd):
    try:
        for it in range(0,10):
            gdb.execute(f"set $r{it}=0")
    except gdb.error:
        pass
    # print(colors['yellow']+cmd+colors['normal'])
    asm_ops(cmd)
    update_regs(r_register)
    r_register.clear()
    # print(filtered_addresses)

def opcode(addr, opcode_hex):
    addr_str = hex(addr)[2:].zfill(8)
    cmd = f"set *(unsigned int*)0x{addr_str} = {opcode_hex}"
    print(cmd)
    gdb.execute(cmd)

def reverse_hex(hex_value):
    # Remove '0x' prefix if present
    hex_str = hex_value[2:] if hex_value.startswith('0x') else hex_value
    
    # Ensure the hex string has an even length
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str

    # Split the hex string into bytes and reverse the order
    reversed_bytes = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)][::-1]
    
    # Join the reversed bytes and prepend '0x'
    reversed_hex = '0x' + ''.join(reversed_bytes)
    
    return reversed_hex

def opcode_wrapper():
    # check $opcode and $addr is set
    if not gdb.parse_and_eval('$opcode') or not gdb.parse_and_eval('$addr'):
        return
    addr = gdb.parse_and_eval('$addr')
    opcode_value = str(hex(gdb.parse_and_eval('$opcode')))
    opcode_hex = reverse_hex(opcode_value)
    opcode(addr, opcode_hex)
 
def search_codecave_addr():
    # Execute the command to get memory mappings
    info = gdb.execute("monitor get mappings", to_string=True)
    
    # Split the mappings into lines
    lines = info.strip().split('\n')

    # Initialize variable to store the last 'r-x Code' mapping
    last_r_x_code = None

    # Iterate over each line to find 'r-x Code'
    for line in lines:
        if 'r-x Code' in line:
            last_r_x_code = line.strip()

    # Output the last 'r-x Code' mapping found
    if last_r_x_code:
        print("Last 'r-x Code' mapping:", last_r_x_code)
        
        # Extract the start and end addresses from the last r-x Code mapping
        parts = last_r_x_code.split()
        start_addr_str = parts[0]  # Start address as string
        end_addr_str = parts[2]     # End address as string (the third part)
        founded = []

        # Check if start and end addresses are valid hex strings
        if start_addr_str.startswith('0x') and end_addr_str.startswith('0x'):
            # start_addr = int(start_addr_str, 16)  # Convert start address from hex to int
            end_addr = int(end_addr_str, 16)      # Convert end address from hex to int
            start_addr = end_addr - 0x4e88800
            # Print the start and end addresses
            print(f"Start address:{start_addr:x} - End address:{end_addr:x}")
            # print(f"End address:{end_addr:x}")

            segment_size = 0x2000  # Size of each segment to check (4096 bytes)
            pattern_length = 0x200     # Number of zero bytes to find (32 bytes)

            current_addr = start_addr
            founded = []
            while current_addr < end_addr:
                # Search for 32 consecutive zero bytes in the current segment
                info = gdb.execute(f'find /b {current_addr}, +{segment_size},{", ".join(["0x00"] * pattern_length)}', to_string=True)

                if info.strip() != 'Pattern not found.':
                    info=info.replace("\n"," ")
                    founded.append(info)
                    # print(f"{current_addr:x}")
                    break
                current_addr += segment_size  # Move to the next segment
            addr1=int(founded[0].split(' ')[0],16)
            addr2 = int(addr1-gdb.parse_and_eval('$main'))
            print(f"0x{addr1:x} <--> {colors['green']}codecave addr = 0x{addr2:x}{colors['normal']}") 
            gdb.execute(f"x/64b {addr1}")
                    


