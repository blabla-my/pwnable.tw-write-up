set $fini_arr=0x4b40f0
set $ropstack=$fini_arr+0x10
set $binsh_addr=$fini_arr - 0x10
memory watch  $fini_arr 16 qword
x/s $binsh_addr
b *0x44a309