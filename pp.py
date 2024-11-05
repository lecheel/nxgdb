import gdb

def print_arm64_registers():
    # Define column width
    label_width = 5  # Width of the register label
    value_width = 12  # Width of the register value in hex (including 0x)

    # Print 32-bit registers (w1 to w22)
    print("w Registers:")
    for i in range(0, 23):
        reg_w = f"w{i}"
        try:
            value_w = gdb.parse_and_eval(f"${reg_w}")
            int_value_w = int(value_w)
            # Format each line with fixed-width labels and values
            print(f"{reg_w:<{label_width}}: {int_value_w:0{value_width}x}", end="  ")
            if i % 6 == 5:
                print()  # Print a new line every 6 registers for better readability
        except gdb.error:
            print(f"{reg_w:<{label_width}}: {'N/A':{value_width}}", end="  ")
            if i % 6 == 5:
                print()

    print("\nx Registers:")
    for i in range(0, 23):
        reg_x = f"x{i}"
        try:
            value_x = gdb.parse_and_eval(f"${reg_x}")
            int_value_x = int(value_x)
            # Format each line with fixed-width labels and values
            print(f"{reg_x:<{label_width}}: {int_value_x:0{value_width}x}", end="  ")
            if i % 6 == 5:
                print()  # Print a new line every 6 registers for better readability
        except gdb.error:
            print(f"{reg_x:<{label_width}}: {'N/A':{value_width}}", end="  ")
            if i % 6 == 5:
                print()
    
    print()  # Final new line for clean output

def grab_reg(reg):
    value = gdb.parse_and_eval(f"${reg}")
    int_value = int(value)
    print(f"{colors['cyan']}{reg}{colors['normal']}=0x{int_value:08x} ", end=" ")

def print_asm_reg():
    addr=gdb.parse_and_eval("$pc")
    cmd = f"disassemble {addr-0x10},{addr+0x20}"
    asm = gdb.execute(cmd, to_string=True)
    pattern = r'\b(w\d+|x\d+)\b'

    matches = re.findall(pattern, asm)
    sorted_matches = sorted(set(matches))

    # print reg like x0=nnnnn x2=nnnnnnn ... 4 in line
    for match in sorted_matches:
        grab_reg(match)
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

# Call the function to print the registers
# print_arm64_registers()
print_asm_reg()

