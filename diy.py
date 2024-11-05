import glob
import os
import struct
import gdb
from colors import colors
import json
# remark using dict 
class GdbCheatEngine(object):
    def __init__(self, inferior, ram_addr, ram_size):
        self.inferior = inferior
        self.ram_addr = ram_addr
        self.ram_size = ram_size
        self.last_results = set()

    def __search_ram_iter(self, pattern):
        """Yields all the RAM addresses where the pattern is found."""
        end_address = self.ram_addr + self.ram_size - len(pattern)
        result_addr = self.ram_addr

        while True:
            # Calculate remaining length
            if result_addr >= end_address:
                return  # Exit if we've reached the end

            remaining_length = end_address - result_addr
            
            # Check if there is enough memory left to search
            if remaining_length < len(pattern):
                return  # Exit if there's not enough memory left to search

            result_addr = self.inferior.search_memory(result_addr + len(pattern), remaining_length, pattern)

            if result_addr is None:
                return  # Exit if the search fails
            else:
                yield result_addr

    def __search_ram(self, pattern):
        """Returns a set with all of the RAM addresses that contain the pattern"""
        return set([addr for addr in self.__search_ram_iter(pattern)])


    def search_ram(self, pattern):
        """
        Returns a set with all of the RAM addresses that contain the pattern (stateful).
        It is possible to further filter the matches with consecutive calls to search_ram_again.
        """
        self.last_results = self.__search_ram(pattern)
        return self.last_results


    def search_ram_again(self, pattern):
        """
        Returns all the RAM addresses that match the new pattern and old ones (stateful filter).
        It is possible to further filter the matches with consecutive calls to this method.
        """
        new_results = self.__search_ram(pattern)
        # self.last_results = self.last_results.intersection(new_results)
        self.last_results.intersection_update(new_results)
        return self.last_results

    def write_memory(self, address, buff):
        return self.inferior.write_memory(address, buff)

    def read_memory(self, address, length):
        return self.inferior.read_memory(address, length)



# print ("diy script v0.0 by laichi")
# home directory
def dir_diy():
    home = os.path.expanduser("~")
    files = glob.glob(home + "/gdb/*.py")
    for file in files:
        # only the filename without the path
        filename = os.path.basename(file)
        print ("  "+filename)

def patch(base, addr_str, opcode_str):
    addr = int(addr_str, 16)+base
    opcode_bytes = bytes.fromhex(opcode_str)
    formatted_opcode_str = ''.join(opcode_str[i:i+2] for i in range(0, len(opcode_str), 2))
    # Reverse the byte order
    cmd=("set *(unsigned int*)0x%x = 0x%s" % (addr, formatted_opcode_str))
    print(cmd)
    gdb.execute(cmd)

def bp_bookmark():
    bplist = gdb.execute('info breakpoints', to_string=True)
    print(bplist)

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


def search_byte(val):
    founded = []
    filtered_addresses = []
    data = gdb.execute("monitor get mappings", to_string=True)
    data = data.split('\n')
    for idx,it in enumerate(data):
        if "rw- Normal" in it:
            it = it.split(" ")
            start,end = (it[2],it[4])
            filtered_addresses.append((start, end))

    hex_val = f"{val:02x}"  # Adjust length as needed (e.g., 2 for single byte)
    byte_val = bytes.fromhex(hex_val)
    print(byte_val.hex())

    total = len(filtered_addresses)
    for idx,(main_start, main_end) in enumerate(filtered_addresses):
        inferior = gdb.inferiors()[0]
        ram_addr, ram_size = (int(main_start,16), int(main_end,16) - int(main_start,16))
        ce = GdbCheatEngine(inferior, ram_addr, ram_size)
        print(f"({idx+1}/{total}) Searching in range {main_start} - {main_end} size = {int(((int(main_end,16)-int(main_start,16))/1024)/1024)} MB")

        # val to byte string
        hex_value = hex(val)[2:]
        xxx=ce.search_ram(hex_value)
        if len(xxx) > 0:
            print(f"{colors['red']}{xxx}{colors['normal']}")


# Function to calculate size of memory ranges
def calculate_memory_sizes(ranges):
    sizes = []
    
    for range_str in ranges:
        # Ignore lines that don't contain address information
        if not range_str or "Mappings:" in range_str:
            continue
        
        # Split the string to extract start and end addresses
        parts = range_str.split(" ")
        
        # Filter out empty strings and keep only relevant parts
        addresses = [part for part in parts if part]
        
        if len(addresses) < 3:  # Ensure we have at least start and end addresses
            continue
        
        try:
            start_address = int(addresses[0], 16)  # Convert start address from hex to int
            end_address = int(addresses[2], 16)    # Convert end address from hex to int
            
            # Calculate size
            size = end_address - start_address + 1
            sizes.append((hex(start_address), hex(end_address), size))
        except ValueError:
            continue  # Skip lines that can't be parsed
    
    return sizes


def get_rw_normal_mappings():
    # Execute the GDB command to get memory mappings
    mappings = gdb.execute("monitor get mappings", to_string=True).split('\n')
    
    # Filter for rw- Normal entries
    rw_normal_mappings = []
    for line in mappings:
        if 'rw-' in line and 'Normal' in line:
            rw_normal_mappings.append(line.strip())
    
    return rw_normal_mappings


def main0():
    # Get the filtered mappings
    rw_mappings = get_rw_normal_mappings()
    memory_sizes = calculate_memory_sizes(rw_mappings)

    # Print results
    print("Memory Range Start       End         Size (bytes)")
    idx = 0
    act_idx = 0
    for start, end, size in memory_sizes:
        idx += 1
        sizeinMB = int(size/1024/1024)
        if sizeinMB > 1:
            act_idx += 1
            print(f"{idx} {start} - {end} : {sizeinMB} MB")

    print(act_idx)

def gdbprint(cmd):
    info=gdb.execute(cmd, to_string=True)
    # $4155 = {f = 0, u = 0, s = 0}
    # replace $NNNN with cmd $s0
    modified_info = re.sub(r'\$(\d+)', cmd, info)
    print(modified_info[2:-1])

class MyBreakpoint(gdb.Breakpoint):
    """Custom breakpoint class to monitor register values."""
    
    def __init__(self, addr):
        # Convert the integer address to a string in hexadecimal format
        super(MyBreakpoint, self).__init__(f"*{hex(addr)}")
        self.silent = True  # Suppress default breakpoint message

    def stop(self):
        try:
            # Print the values of s3, s0, and s1 registers when the breakpoint is hit
            cmd ="p $s0"
            info=gdb.execute(cmd, to_string=True)
            index = info.find('=')
            value = info[index+2:]
            print(f"{cmd[2:]} = {value[:-1]}")
        except gdb.error as e:
            print(f"Error while accessing registers: {e}")    
        return False

# Set the address for the breakpoint
# addr = 0x8153bb64
# MyBreakpoint(addr)


# undo_pc()
# save_pc()

"""
last_ce = None
search_byte(92400)
# print(last_ce.last_results)
# print all last_results address value
inferior = gdb.inferiors()[0]
for addr in last_ce.last_results:
    addr_str = hex(addr)[2:].zfill(8)
    m = inferior.read_memory(addr, 4)
    hex_string = m.tobytes().hex()
    # big endian
    patched_hex = ''.join(hex_string[i:i+2] for i in range(0, len(hex_string), 2)[::-1])
    if patched_hex != "00000000":
        print(f"0x{addr_str} {patched_hex} //{int(patched_hex,16)}")
"""


# go_overBL()    
# bp_bookmark()
# recovery_from_cheat() 


