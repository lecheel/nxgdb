import gdb    
from colors import colors
import struct
def aob_heap():
    valid_idx = []
    founded = []
    filtered_addresses = []
    data = gdb.execute("monitor get mappings", to_string=True)
    data = data.split('\n')
    for idx,it in enumerate(data):
        if "rw- Normal" in it:
            it = it.split(" ")
            start,end = (it[2],it[4])
            filtered_addresses.append((start, end))


    val = gdb.parse_and_eval('$opfind')
    val_str = str(val)
    val_str=val_str.replace('"',"").replace(" ","")
    val = val_str

    total = len(filtered_addresses)
    for idx,it in enumerate(filtered_addresses):

        main_start = it[0]
        main_end = it[1]

        # val0=2675
        # val1=00
        # hex_bytes_val0 = struct.pack('<I', val0).hex()
        # hex_bytes_val1 = struct.pack('<I', val1).hex()
        # val = hex_bytes_val0+hex_bytes_val1
        # val="fb 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00"
        # remove spaces 
        # val=val.replace(" ","")
        bytes_list = [val[i:i+2] for i in range(0, len(val), 2)]
        # Add '0x' prefix and join with ', '
        data_str = ", ".join(f"0x{byte}" for byte in bytes_list)
        # print(f"find /b {main_start}, {main_end}, {data_str}")
        # if no valid_idx search all else search only valid_idx
        if (idx in valid_idx or len(valid_idx)==0):
            print(f"({idx+1}/{total}) Searching in range {main_start} - {main_end} size = {int(((int(main_end,16)-int(main_start,16))/1024)/1024)} MB", end='\r')
            info = gdb.execute(f'find /b {main_start}, {main_end}, {data_str}', to_string=True)
            if info.strip() != 'Pattern not found.':
                info=info.replace("\n"," ")
                print(f"\n{colors['green']}{info}{colors['normal']}")
                founded.append(info)
            else:
                print("")


    # print(f"[green]{founded}[/green]")

aob_heap()
