import gdb
import re
# from rich import print

def register_stop_handler():
    gdb.events.stop.connect(stop_handler)
    #unregister
    #gdb.events.stop.disconnect(stop_handler)
    print('\nDone setting stop-handler\n')

def stop_handler(event):
    print("hook for bp")
    gdb.execute("c")

# gdb.execute(f'shell clear')
msg=gdb.execute('monitor get info', to_string=True)
print("-- [red] setup main from SwitchPlayer.nss [/red] ----------")
match = re.search(r'0x([0-9a-f]+)\s+-\s+0x([0-9a-f]+)\s+SwitchPlayer\.nss', msg)
    
if match:
    start_address = f"0x{match.group(1)}"
    end_address = f"0x{match.group(2)}"
    gdb.execute(f'set $main={start_address}')
    gdb.execute(f'set $main_start={start_address}')
    gdb.execute(f'set $main_end={end_address}')
    print(f"  set $main = {start_address} is ready 󱨎 yuzu from (wylde flowers)")

# msg=gdb.execute('monitor get info', to_string=True)
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

print(f"󰘳  ops -- si(stepin) / nexti / u(disassemble) / v(mem) / bpl(breakpoint list) / p(rint) c(ontinue) / q(uit)") 
# register_stop_handler()
