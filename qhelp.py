from colors import colors
def qhelp():
    offset=f"{colors['yellow']}0x<offset>{colors['normal']}"
    addr=f"{colors['yellow']}0x<addr>{colors['normal']}"
    pc=f"{colors['yellow']}$pc{colors['normal']}"
    ret=f"{colors['yellow']}ret{colors['normal']}"
    regs=f"{colors['yellow']}'s0,w1'{colors['normal']}"
    opcode=f"{colors['yellow']}set {{unsigned int}} $pc=0xd503201f{colors['normal']}  nop->{colors['green']}1f2003d5{colors['normal']}"
    nop=f"{colors['yellow']}0x1f2003d5{colors['normal']}"
    help = f"""
        {colors['green']}u/U    {colors['normal']}  disassembly
        {colors['green']}ll/lL  {colors['normal']}  lestyle disassembly with remark from cheat code or remark 
        {colors['green']}rem    {colors['normal']}  disassembly with remark for {pc}
        {colors['green']}kk     {colors['normal']}  init nso game info like $main $bid
        {colors['green']}bb     {colors['normal']}  breakpoint with {offset} will add +$main
        {colors['green']}bmark  {colors['normal']}  breakpoint with remark '{offset} this is breakpoint with remark'
        {colors['green']}blist  {colors['normal']}  breakpoint list with remark vs {colors['green']}bp{colors['normal']}
        {colors['green']}pp     {colors['normal']}  smart point registers base on currect {pc} .. {pc}+0x40
        {colors['green']}mbp    {colors['normal']}  memory breakpoint vs awatch *(int*)0xNNNNN
        {colors['green']}wbp    {colors['normal']}  watch memory {addr} {regs}
        {colors['green']}ops    {colors['normal']}  search opcode from current {pc}+0x1000 or until '{ret}'
        {colors['green']}asm    {colors['normal']}  change current {pc} code with asm 'fmov s0, #1.0'
        {colors['green']}nop    {colors['normal']}  change current {pc} code with nop
        {colors['green']}set    {colors['normal']}  {opcode}
        {colors['green']}opcode {colors['normal']}  opcode {addr} {nop}
        {colors['green']}code   {colors['normal']}  looking for codecave {addr}
        {colors['green']}gn     {colors['normal']}  go breakpoint to here <N>x4|<hex> last 3 hex
        {colors['green']}cheat  {colors['normal']}  list cheat code also active the cheat code with cheat N or ls
        {colors['green']}cheat N{colors['normal']}  active the cheat code with N
        {colors['green']}map    {colors['normal']}  search aob_heap()
        {colors['green']}master {colors['normal']}  mastercode for cheatcode via bid.txt
        {colors['green']}q      {colors['normal']}  quit
    """
    print(help)

qhelp()
