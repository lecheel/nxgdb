import re

def master_code():
    master_codes = ['Restore Code', 'Master Code']
    gdb.execute("set pagination off")
    cheats = []
    
    cheat_id = str(gdb.parse_and_eval('$bid')).strip('"')
    main_addr = gdb.parse_and_eval('$main')
    tid = hex(gdb.parse_and_eval('$cheat_id'))[2:].upper()
    
    print(f"[TID:{tid} BID:{cheat_id[1:-1].upper()}]")
    
    file_path = f"./gdb/{cheat_id.upper()}.txt"
    
    # Read the cheat codes from the file
    cheats = read_cheats_from_file(file_path)
    
    # Process and print the cheats
    for idx, (cheat_name, values) in enumerate(cheats):
        if cheat_name in master_codes:
            print("[Master Code]")
        else:
            get_opcode(idx, values, main_addr)

def read_cheats_from_file(file_path):
    cheats = []
    
    try:
        with open(file_path, "r") as f:
            current_cheat_name = None
            current_values = []

            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Check for cheat name
                cheat_name_match = re.search(r'\[(.*?)\]', line)
                if cheat_name_match:
                    if current_cheat_name:
                        cheats.append((current_cheat_name, current_values))
                    
                    current_cheat_name = cheat_name_match.group(1).strip()
                    current_values = []
                    continue
                
                # Check for values starting with '040'
                if line.startswith('040'):
                    parts = line.split()
                    if len(parts) >= 2:
                        values = parts[1:]  # Values after the prefix
                        current_values.append(values)

            # Append last entry if exists
            if current_cheat_name and current_values:
                cheats.append((current_cheat_name, current_values))
                
    except FileNotFoundError:
        print(f"File {file_path} not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

    return cheats

def get_opcode(idx, values, main_addr):
    for v in values:
        cheat_addr = int(v[0], 16)
        addr = main_addr + cheat_addr
        
        # Prepare address strings
        cheat_addr_str = hex(cheat_addr)[2:].zfill(8)
        addr_str = hex(addr)[2:].zfill(16)

        # Read memory and process the opcode
        m = gdb.inferiors()[0].read_memory(addr, 4)
        hex_string = m.tobytes().hex()
        
        patched_hex = ''.join(hex_string[i:i+2] for i in range(0, len(hex_string), 2)[::-1])

        if patched_hex != "00000000":
            print(f"040A0000 {cheat_addr_str} {patched_hex}")

# Execute the master code function
master_code()
