from keystone import *
import argparse
import re
# from rich import print

# Initialize Keystone for ARM64 architecture
ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
C_green = "\033[32m"
C_cyan = "\033[36m"
C_reset = "\033[0m"
C_yellow = "\033[33m"                

def load_assembly_instructions(filename):
    assembly_instructions = []
    current_comment = None
    
    try:
        with open(filename, 'r') as file:
            for line in file:
                # Check for standalone comments
                if '//' in line:
                    standalone_comment = line.split('//', 1)[1].strip()
                    if standalone_comment:
                        current_comment = f"{C_green}[{standalone_comment}]{C_reset}"

                # Remove comments from the line for processing
                line_parts = line.split('//', 1)
                instruction = line_parts[0].strip()
                
                if not instruction:  # Skip empty lines
                    continue
                
                # Match the address and instruction using regex
                match = re.match(r'(\S+):\s*(.*)', instruction)
                if match:
                    address = match.group(1)
                    asm_instruction = match.group(2)
                    assembly_instructions.append((address, asm_instruction, current_comment))
                    current_comment = None  # Reset comment after using it
    except IOError as e:
        print(f"Error reading file {filename}: {e}")
        exit(1)

    return assembly_instructions


def patch_branch_instruction(b_instruction, address, target_address):
    # Calculate relative offset
    current_address = address
    instruction_size = 4  # ARM64 instructions are usually 4 bytes
    offset = target_address - (current_address + instruction_size)

    # Ensure the offset is within a valid range for branch instructions
    if offset < -0x80000000 or offset > 0x7FFFFFFF:
        raise ValueError("Offset out of range for branch instruction.")

    # Extract the branch instruction without the comment
    b_ins = b_instruction.split('#')[0].strip()
    
    # Assemble new instruction with the calculated offset
    assembly = f'{b_ins} #{offset + 4}'
    encoding, _ = ks.asm(assembly)

    # Return the encoding for further use
    return encoding

def assemble_and_print(instructions, cheat=False):
    last_comment = None
    
    for address, instruction, comment in instructions:
        # Print the last comment before printing the next instruction set
        if comment and last_comment != comment:
            print(f"\n{comment}")
            last_comment = comment
 
        formatted_address = f"{int(address, 16):08x}"                    
        try:
            # Check for branch instructions (including conditional branches)
            if re.match(r'b\.?(eq|gt|lt|nz)? ', instruction.lower()):  
                target_address_match = re.search(r'#(0x[0-9a-fA-F]+)', instruction)
                if target_address_match:
                    target_address = int(target_address_match.group(1), 16)
                    encoding = patch_branch_instruction(instruction, int(address, 16), target_address)

                    # Use the encoding returned from patch_branch_instruction
                    hex_output = ''.join(f'{byte:02x}' for byte in reversed(encoding))
                    # print(f"{formatted_address}: {hex_output}")
            else:
                encoding, count = ks.asm(instruction)
                hex_output = ''.join(f'{byte:02x}' for byte in reversed(encoding))

            cheat_output = ''.join(f'{byte:02x}' for byte in encoding)
            
            if not cheat:
                print(f"04000000 {C_yellow}{formatted_address} {C_cyan}{hex_output} {C_green}// {cheat_output} {instruction}{C_reset}")
            else:
                 print(f"04000000 {C_yellow}{formatted_address} {C_cyan}{hex_output} {C_reset}")
        except KsError as e:
            print(f"Assembly failed for instruction '{instruction}': {e}")

# Main function to parse arguments and execute the program
def main():
    parser = argparse.ArgumentParser(description="Assemble ARM64 instructions from a file.")
    parser.add_argument('filename', type=str, help='The filename containing assembly instructions.')
    parser.add_argument('--cheat', action='store_true', help='Enable cheat mode.')
    args = parser.parse_args()

    # Load assembly instructions from the specified file
    assembly_instructions = load_assembly_instructions(args.filename)

    # Assemble the provided assembly instructions
    assemble_and_print(assembly_instructions, args.cheat)

if __name__ == "__main__":
    main()
