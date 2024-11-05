import gdb
import re
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

def cheat_from_file():
    cheats = []
    cheat_id=gdb.parse_and_eval('$cheat_id')
    # int to hex 
    cheatstr = hex(cheat_id)[2:]
    # fill 0 for 16 digits
    while len(cheatstr) < 16:
        cheatstr = '0' + cheatstr
    file =f"./gdb/{cheatstr}.txt"
    print(file)
    with open(file, "r") as f:
        lines = f.readlines()
        previous_line = None
        for line in lines:
            line = line.strip()
            # Print each line for debugging
            # print(f"Read line: {line}")
            if line.startswith('04000000'):
                if previous_line:
                    # Extract cheat name from the previous line
                    cheat_name_match = re.search(r'\[(.*?)\]', previous_line)
                    if cheat_name_match:
                        cheat_name = cheat_name_match.group(1).strip()
                        parts = line.split()
                        if len(parts) >= 2:  # Adjust this if necessary
                            values = parts[1:]  # Values after the prefix
                            cheats.append((cheat_name, values))
                # Set current line as the previous line for the next iteration
                previous_line = line
            else:
                # Update previous_line if it's not the targeted line
                previous_line = line
    for cheat in cheats:
        print(f"{cheat}, b *$main+0x{cheat[1][0]}")


